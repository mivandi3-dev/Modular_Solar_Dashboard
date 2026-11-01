//! Mrežni ulaz: jedan TCP port (zadano 8700, iz postavki poslužitelja). TLS (rustls, TLS 1.2/1.3) za sve; obični
//! HTTP samo s loopbacka (cloudflared na istom računalu) – isto ponašanje kao 3.x/4.0.0, pa postojeća konfiguracija
//! tunela radi bez izmjene. Ograničenja: veze po IP-u, ukupne veze (odvojeno mreža / loopback), nove veze u sekundi po
//! IP-u, rok prvog bajta 3 s, rok TLS rukovanja 5 s, rok zaglavlja 10 s, rok veze 15 s, ≤ 8 KB zaglavlja,
//! ≤ 100 zaglavlja, ≤ 16 KB tijela (http.rs), jedna veza = jedan zahtjev.

use crate::backend::{Backend, ListenConfig};
use crate::http::{self, Upstream};
use crate::log;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub per_ip: usize,
    /// loopback (127.0.0.0/8, ::1) – cloudflared dovodi sve korisnike tunela s iste adrese (ADR-001 §4)
    pub loopback_per_ip: usize,
    /// 5.0.2 (audit G-04): ukupno veza iz mreže i ukupno s loopbacka odvojeno – mreža ne može zatvoriti tunel
    pub global: usize,
    pub global_loopback: usize,
    /// nove veze po IP-u: trenutni nalet i obnova u sekundi (mreža / loopback)
    pub burst: f64,
    pub per_sec: f64,
    pub loopback_burst: f64,
    pub loopback_per_sec: f64,
    pub first_byte_timeout: Duration,
    pub tls_timeout: Duration,
    pub header_timeout: Duration,
    pub connection_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            per_ip: 4,
            loopback_per_ip: 48,
            global: 192,
            global_loopback: 64,
            burst: 8.0,
            per_sec: 2.0,
            loopback_burst: 64.0,
            loopback_per_sec: 30.0,
            first_byte_timeout: Duration::from_secs(3),
            tls_timeout: Duration::from_secs(5),
            header_timeout: Duration::from_secs(10),
            connection_deadline: Duration::from_secs(15),
        }
    }
}

/// Loopback (cijeli 127.0.0.0/8, ::1 i IPv4-mapirani loopback) broji se kao jedna adresa (audit G-12).
pub fn limit_key(ip: IpAddr) -> IpAddr {
    let lo = match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
    };
    if lo {
        return IpAddr::V4(Ipv4Addr::LOCALHOST);
    }
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn is_loopback_key(ip: IpAddr) -> bool {
    ip == IpAddr::V4(Ipv4Addr::LOCALHOST)
}

// ------------------------------------------------------------------ brojači odbijanja (audit G-10)
pub const STAT_NAMES: [&str; 7] = ["previše veza s adrese", "ukupna granica", "prebrze nove veze", "neuspjelo TLS rukovanje",
    "obični HTTP iz mreže", "isteklo vrijeme", "zahtjev iz preglednika"];
pub static STATS: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];
pub const STAT_PER_IP: usize = 0;
pub const STAT_GLOBAL: usize = 1;
pub const STAT_RATE: usize = 2;
pub const STAT_TLS: usize = 3;
pub const STAT_PLAIN_LAN: usize = 4;
pub const STAT_DEADLINE: usize = 5;
pub const STAT_BROWSER: usize = 6;

pub fn count(stat: usize) {
    STATS[stat].fetch_add(1, Ordering::Relaxed);
}

/// Jedan sažeti redak u zapisniku svake minute, samo kad je nešto odbijeno (nikad redak po događaju – zapisnik bi
/// sam postao put za DoS).
pub async fn stats_task() {
    let mut last = [0u64; 7];
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let parts: Vec<String> = (0..STATS.len())
            .filter_map(|i| {
                let now = STATS[i].load(Ordering::Relaxed);
                let delta = now - last[i];
                last[i] = now;
                (delta > 0).then(|| format!("{}: {delta}", STAT_NAMES[i]))
            })
            .collect();
        if !parts.is_empty() {
            log::warn(&format!("Odbijeno u zadnjoj minuti – {}", parts.join(", ")));
        }
    }
}

// ------------------------------------------------------------------ aktivne veze
/// Brojač aktivnih veza (po IP-u, ukupno iz mreže, ukupno s loopbacka).
#[derive(Default)]
pub struct Tracker {
    inner: Mutex<(HashMap<IpAddr, usize>, usize, usize)>,
}

pub struct Slot {
    tracker: Arc<Tracker>,
    ip: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut g = self.tracker.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = g.0.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                g.0.remove(&self.ip);
            }
        }
        if is_loopback_key(self.ip) {
            g.2 -= 1;
        } else {
            g.1 -= 1;
        }
    }
}

impl Tracker {
    pub fn acquire(self: &Arc<Self>, peer: IpAddr, limits: &Limits) -> Option<Slot> {
        let ip = limit_key(peer);
        let lo = is_loopback_key(ip);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (cap, total, global) = if lo { (limits.loopback_per_ip, g.2, limits.global_loopback) } else { (limits.per_ip, g.1, limits.global) };
        if total >= global {
            count(STAT_GLOBAL);
            return None;
        }
        if g.0.get(&ip).copied().unwrap_or(0) >= cap {
            count(STAT_PER_IP);
            return None;
        }
        *g.0.entry(ip).or_insert(0) += 1;
        if lo {
            g.2 += 1;
        } else {
            g.1 += 1;
        }
        Some(Slot { tracker: self.clone(), ip })
    }

    pub fn active(&self) -> usize {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.1 + g.2
    }
}

// ------------------------------------------------------------------ nove veze u sekundi (audit G-04)
/// Kanta žetona po IP-u: nalet `burst`, obnova `per_sec`. Tablica je ograničena (stari zapisi se brišu).
#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

const RATE_TABLE_MAX: usize = 4096;

impl RateLimiter {
    pub fn allow(&self, peer: IpAddr, limits: &Limits, now: Instant) -> bool {
        let ip = limit_key(peer);
        let (burst, rate) = if is_loopback_key(ip) { (limits.loopback_burst, limits.loopback_per_sec) } else { (limits.burst, limits.per_sec) };
        let mut m = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= RATE_TABLE_MAX && !m.contains_key(&ip) {
            m.retain(|_, (tokens, at)| now.duration_since(*at) < Duration::from_secs(60) && *tokens < burst);
            if m.len() >= RATE_TABLE_MAX {
                count(STAT_RATE);
                return false; // tablica puna novih adresa – nova adresa čeka
            }
        }
        let entry = m.entry(ip).or_insert((burst, now));
        let refill = now.duration_since(entry.1).as_secs_f64() * rate;
        entry.0 = (entry.0 + refill).min(burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            count(STAT_RATE);
            false
        }
    }
}

// ------------------------------------------------------------------ cloudflared (audit G-14 / C-11)
/// CF-Connecting-IP vrijedi samo kad je udaljeni kraj veze proces usluge `cloudflared` – lokalni korisnik inače može
/// lažirati adresu klijenta i zaobići ograničenja prijave. PID usluge pamti se 30 s.
struct CloudflaredPid {
    cached: Mutex<Option<(Option<u32>, Instant)>>,
}

static CLOUDFLARED: CloudflaredPid = CloudflaredPid { cached: Mutex::new(None) };

fn cloudflared_pid() -> Option<u32> {
    let mut g = CLOUDFLARED.cached.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((pid, at)) = *g {
        if at.elapsed() < Duration::from_secs(30) {
            return pid;
        }
    }
    let pid = crate::win::service_pid("cloudflared");
    *g = Some((pid, Instant::now()));
    pid
}

async fn is_cloudflared(server: SocketAddr, peer: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || match cloudflared_pid() {
        Some(pid) => crate::win::tcp_peer_pid(server, peer) == Some(pid),
        None => false,
    })
    .await
    .unwrap_or(false)
}

// ------------------------------------------------------------------ veze
pub fn tls_acceptor(id: &crate::tlscert::Identity) -> std::io::Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .and_then(|b| b.with_no_client_auth().with_single_cert(vec![id.cert.clone()], id.key.clone_key()))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// `trusted_proxy`: obični HTTP od procesa cloudflared – samo tada se prosljeđuje CF-Connecting-IP.
async fn serve_http<I, U>(io: I, peer: SocketAddr, trusted_proxy: bool, upstream: Arc<U>, limits: Limits)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: Upstream,
{
    let svc = service_fn(move |req: Request<Incoming>| {
        let up = upstream.clone();
        async move { Ok::<_, Infallible>(http::handle_transport(req, peer, trusted_proxy, &*up).await) }
    });
    let mut b = http1::Builder::new();
    b.timer(TokioTimer::new()).header_read_timeout(limits.header_timeout).keep_alive(false).max_buf_size(8 * 1024).max_headers(100);
    let _ = b.serve_connection(TokioIo::new(io), svc).await;
}

async fn serve_connection<U: Upstream>(stream: TcpStream, peer: SocketAddr, tls: TlsAcceptor, upstream: Arc<U>, limits: Limits) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    match tokio::time::timeout(limits.first_byte_timeout, stream.peek(&mut first)).await {
        Ok(Ok(1)) => {}
        Err(_) => {
            count(STAT_DEADLINE);
            return;
        }
        _ => return,
    }
    if first[0] == 0x16 {
        match tokio::time::timeout(limits.tls_timeout, tls.accept(stream)).await {
            Ok(Ok(tls_stream)) => serve_http(tls_stream, peer, false, upstream, limits).await,
            _ => count(STAT_TLS),
        }
    } else if is_loopback_key(limit_key(peer.ip())) {
        let server = stream.local_addr().ok();
        let trusted = match server {
            Some(server) => is_cloudflared(server, peer).await,
            None => false,
        };
        serve_http(stream, peer, trusted, upstream, limits).await; // cloudflared → http://127.0.0.1:port
    } else {
        count(STAT_PLAIN_LAN); // obični HTTP iz mreže: veza se zatvara bez odgovora (u mreži samo HTTPS)
    }
}

/// Prihvaćanje veza na već otvorenom portu (testovi ga zovu izravno).
pub async fn accept_loop<U: Upstream>(listener: TcpListener, tls: TlsAcceptor, upstream: Arc<U>, limits: Limits, tracker: Arc<Tracker>) {
    accept_loop_rate(listener, tls, upstream, limits, tracker, Arc::new(RateLimiter::default())).await
}

pub async fn accept_loop_rate<U: Upstream>(
    listener: TcpListener,
    tls: TlsAcceptor,
    upstream: Arc<U>,
    limits: Limits,
    tracker: Arc<Tracker>,
    rate: Arc<RateLimiter>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !rate.allow(peer.ip(), &limits, Instant::now()) {
            drop(stream); // prebrze nove veze s te adrese – odmah zatvoreno, bez TLS-a
            continue;
        }
        let Some(slot) = tracker.acquire(peer.ip(), &limits) else {
            drop(stream); // previše veza s te adrese ili ukupno – odmah zatvoreno
            continue;
        };
        let (tls, upstream) = (tls.clone(), upstream.clone());
        tokio::spawn(async move {
            let _slot = slot;
            if tokio::time::timeout(limits.connection_deadline, serve_connection(stream, peer, tls, upstream, limits)).await.is_err() {
                count(STAT_DEADLINE);
            }
        });
    }
}

/// Port s isključivim pravom (SO_EXCLUSIVEADDRUSE) – drugi proces ga ne može preuzeti dok gateway radi.
/// 5.0.2 (audit G-11): veže se i IPv6 ([::1], a u mreži [::]) – inače bi lokalni proces mogao zauzeti [::1]:port, a
/// cloudflared za „localhost” prvo pokušava IPv6. Ako IPv6 na računalu ne postoji, radi samo IPv4.
pub fn bind(cfg: ListenConfig) -> std::io::Result<Vec<TcpListener>> {
    let v4 = SocketAddr::new(if cfg.lan { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::LOCALHOST) }, cfg.port);
    let socket = tokio::net::TcpSocket::new_v4()?;
    crate::win::exclusive_address(&socket)?;
    socket.bind(v4)?;
    let mut out = vec![socket.listen(1024)?];
    let v6 = SocketAddr::new(if cfg.lan { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::LOCALHOST) }, cfg.port);
    match tokio::net::TcpSocket::new_v6() {
        Ok(s6) => {
            crate::win::exclusive_address(&s6)?;
            crate::win::v6_only(&s6)?;
            match s6.bind(v6) {
                Ok(()) => out.push(s6.listen(1024)?),
                // zauzeto: netko drugi drži [::1]:port – ne radi se dalje (promet tunela mogao bi otići njemu)
                Err(e) if matches!(e.kind(), std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied) => return Err(e),
                Err(e) => log::warn(&format!("IPv6 adresa {v6} nije dostupna ({e}) – samo IPv4")),
            }
        }
        Err(e) => log::warn(&format!("IPv6 nije dostupan ({e}) – samo IPv4")),
    }
    Ok(out)
}

fn load_listen(state: Option<&Path>) -> ListenConfig {
    let default = ListenConfig { port: 8700, lan: false };
    let Some(path) = state else { return default };
    let Ok(text) = std::fs::read_to_string(path) else { return default };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    match (v["port"].as_u64().and_then(|p| u16::try_from(p).ok()), v["lan"].as_bool()) {
        (Some(port), Some(lan)) if port > 0 => ListenConfig { port, lan },
        _ => default,
    }
}

fn save_listen(state: Option<&Path>, cfg: ListenConfig) {
    if let Some(path) = state {
        let _ = std::fs::write(path, serde_json::json!({"port": cfg.port, "lan": cfg.lan}).to_string());
    }
}

struct Listening {
    cfg: ListenConfig,
    loops: Vec<JoinHandle<()>>,
}

impl Listening {
    fn stop(self) {
        for h in self.loops {
            h.abort();
        }
    }
}

fn spawn_loops(listeners: Vec<TcpListener>, tls: &TlsAcceptor, backend: &Arc<Backend>, limits: Limits, tracker: &Arc<Tracker>,
               rate: &Arc<RateLimiter>) -> Vec<JoinHandle<()>> {
    listeners
        .into_iter()
        .map(|l| tokio::spawn(accept_loop_rate(l, tls.clone(), backend.clone(), limits, tracker.clone(), rate.clone())))
        .collect()
}

/// Upravljanje portom prema postavkama poslužitelja (provjera svakih 5 s preko kanala).
/// 5.0.1 (audit G-01): port se veže ODMAH pri pokretanju (zadnja poznata konfiguracija iz `state`, inače 127.0.0.1:8700) i
/// drži se i kad servis ne odgovara – lokalni proces ga ne može preuzeti i primati promet tunela; novi port se veže prije
/// zatvaranja starog (kad se port ne mijenja, samo kratka zamjena istog porta).
pub async fn run(backend: Arc<Backend>, tls: TlsAcceptor, limits: Limits, state: Option<PathBuf>) {
    let tracker = Arc::new(Tracker::default());
    let rate = Arc::new(RateLimiter::default());
    tokio::spawn(stats_task());
    let mut current: Option<Listening> = None;
    let mut last_error = String::new();
    let initial = load_listen(state.as_deref());
    match bind(initial) {
        Ok(listeners) => {
            log::info(&format!("Port {} zauzet odmah pri pokretanju (zadnja poznata postavka)", initial.port));
            current = Some(Listening { cfg: initial, loops: spawn_loops(listeners, &tls, &backend, limits, &tracker, &rate) });
        }
        Err(e) => log::error(&format!("Port {} se ne može otvoriti pri pokretanju (zauzeo ga je drugi proces?): {e}", initial.port)),
    }
    loop {
        match backend.config().await {
            Ok(cfg) if current.as_ref().map(|c| c.cfg) != Some(cfg) => {
                // drugi port: prvo novi, pa zatvori stari; isti port (promjena LAN-a): zatvori pa odmah veži
                let same_port = current.as_ref().is_some_and(|c| c.cfg.port == cfg.port);
                if same_port {
                    if let Some(c) = current.take() {
                        c.stop();
                        tokio::task::yield_now().await;
                    }
                }
                match bind(cfg) {
                    Ok(listeners) => {
                        if let Some(c) = current.take() {
                            c.stop();
                        }
                        save_listen(state.as_deref(), cfg);
                        log::info(&format!(
                            "Slušam na {}:{} ({})",
                            if cfg.lan { "0.0.0.0 / [::]" } else { "127.0.0.1 / [::1]" },
                            cfg.port,
                            if cfg.lan { "HTTPS u mreži, HTTP samo s loopbacka" } else { "samo loopback" }
                        ));
                        current = Some(Listening { cfg, loops: spawn_loops(listeners, &tls, &backend, limits, &tracker, &rate) });
                        last_error.clear();
                    }
                    Err(e) => {
                        let msg = format!("Port {} se ne može otvoriti: {e}", cfg.port);
                        if msg != last_error {
                            log::error(&msg);
                            last_error = msg;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(e) => {
                let msg = format!("Servis poslužitelja nije dostupan: {e}");
                if msg != last_error {
                    log::warn(&msg);
                    last_error = msg;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_limits_per_ip_and_global() {
        let t = Arc::new(Tracker::default());
        let limits = Limits { per_ip: 4, loopback_per_ip: 6, global: 5, global_loopback: 6, ..Limits::default() };
        let ip: IpAddr = "192.168.1.9".parse().unwrap();
        let held: Vec<_> = (0..4).map(|_| t.acquire(ip, &limits).unwrap()).collect();
        assert!(t.acquire(ip, &limits).is_none(), "5. veza s istog IP-a se odbija");
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let lo_held: Vec<_> = (0..6).map(|_| t.acquire(lo, &limits).unwrap()).collect();
        // 127.0.0.2 i ::1 broje se kao isti loopback (G-12)
        assert!(t.acquire("127.0.0.2".parse().unwrap(), &limits).is_none());
        assert!(t.acquire("::1".parse().unwrap(), &limits).is_none());
        // mreža ima vlastitu ukupnu granicu – loopback je ne troši (G-04)
        let other = t.acquire("10.0.0.1".parse().unwrap(), &limits);
        assert!(other.is_some(), "5. veza iz mreže još stane");
        assert!(t.acquire("10.0.0.2".parse().unwrap(), &limits).is_none(), "ukupna granica mreže");
        drop(held);
        drop(other);
        assert_eq!(t.active(), 6);
        assert!(t.acquire(ip, &limits).is_some());
        drop(lo_held);
    }

    #[test]
    fn rate_limiter_burst_and_refill() {
        let r = RateLimiter::default();
        let limits = Limits { burst: 3.0, per_sec: 1.0, ..Limits::default() };
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let t0 = Instant::now();
        assert!((0..3).all(|_| r.allow(ip, &limits, t0)));
        assert!(!r.allow(ip, &limits, t0), "nalet potrošen");
        assert!(r.allow(ip, &limits, t0 + Duration::from_millis(1100)), "nakon sekunde jedan žeton");
        assert!(r.allow("192.168.1.21".parse().unwrap(), &limits, t0), "druga adresa ima svoju kantu");
    }

    #[test]
    fn loopback_key_normalisation() {
        assert_eq!(limit_key("127.5.6.7".parse().unwrap()), limit_key("::1".parse().unwrap()));
        assert_eq!(limit_key("::ffff:127.0.0.1".parse().unwrap()), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(limit_key("::ffff:192.168.1.7".parse().unwrap()), "192.168.1.7".parse::<IpAddr>().unwrap());
    }
}

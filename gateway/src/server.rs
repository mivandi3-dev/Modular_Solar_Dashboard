//! Mrežni ulaz: jedan TCP port (zadano 8700, iz postavki poslužitelja). TLS (rustls, TLS 1.2/1.3) za sve; obični
//! HTTP samo s loopbacka (cloudflared na istom računalu) – isto ponašanje kao 3.x/4.0.0, pa postojeća konfiguracija
//! tunela radi bez izmjene. Ograničenja: veze po IP-u, ukupne veze, rok zaglavlja 10 s, rok veze 15 s,
//! ≤ 8 KB zaglavlja, ≤ 100 zaglavlja, ≤ 16 KB tijela (http.rs), jedna veza = jedan zahtjev.

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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub per_ip: usize,
    /// 127.0.0.1 i ::1 – cloudflared dovodi sve korisnike tunela s iste adrese (ADR-001 §4)
    pub loopback_per_ip: usize,
    pub global: usize,
    pub header_timeout: Duration,
    pub connection_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            per_ip: 4,
            loopback_per_ip: 32,
            global: 256,
            header_timeout: Duration::from_secs(10),
            connection_deadline: Duration::from_secs(15),
        }
    }
}

/// Brojač aktivnih veza (po IP-u i ukupno).
#[derive(Default)]
pub struct Tracker {
    inner: Mutex<(HashMap<IpAddr, usize>, usize)>,
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
        g.1 -= 1;
    }
}

impl Tracker {
    pub fn acquire(self: &Arc<Self>, ip: IpAddr, limits: &Limits) -> Option<Slot> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cap = if ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST) {
            limits.loopback_per_ip
        } else {
            limits.per_ip
        };
        if g.1 >= limits.global || g.0.get(&ip).copied().unwrap_or(0) >= cap {
            return None;
        }
        *g.0.entry(ip).or_insert(0) += 1;
        g.1 += 1;
        Some(Slot { tracker: self.clone(), ip })
    }

    pub fn active(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1
    }
}

pub fn tls_acceptor(id: &crate::tlscert::Identity) -> std::io::Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .and_then(|b| b.with_no_client_auth().with_single_cert(vec![id.cert.clone()], id.key.clone_key()))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

async fn serve_http<I, U>(io: I, peer: SocketAddr, upstream: Arc<U>, limits: Limits)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: Upstream,
{
    let svc = service_fn(move |req: Request<Incoming>| {
        let up = upstream.clone();
        async move { Ok::<_, Infallible>(http::handle(req, peer, &*up).await) }
    });
    let mut b = http1::Builder::new();
    b.timer(TokioTimer::new()).header_read_timeout(limits.header_timeout).keep_alive(false).max_buf_size(8 * 1024).max_headers(100);
    let _ = b.serve_connection(TokioIo::new(io), svc).await;
}

async fn serve_connection<U: Upstream>(stream: TcpStream, peer: SocketAddr, tls: TlsAcceptor, upstream: Arc<U>, limits: Limits) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    match tokio::time::timeout(limits.header_timeout, stream.peek(&mut first)).await {
        Ok(Ok(1)) => {}
        _ => return,
    }
    if first[0] == 0x16 {
        if let Ok(tls_stream) = tls.accept(stream).await {
            serve_http(tls_stream, peer, upstream, limits).await;
        }
    } else if peer.ip().is_loopback() || matches!(peer.ip(), IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())) {
        serve_http(stream, peer, upstream, limits).await; // cloudflared → http://127.0.0.1:port
    }
    // obični HTTP iz mreže: veza se zatvara bez odgovora (u mreži samo HTTPS)
}

/// Prihvaćanje veza na već otvorenom portu (testovi ga zovu izravno).
pub async fn accept_loop<U: Upstream>(listener: TcpListener, tls: TlsAcceptor, upstream: Arc<U>, limits: Limits, tracker: Arc<Tracker>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(slot) = tracker.acquire(peer.ip(), &limits) else {
            drop(stream); // previše veza s te adrese ili ukupno – odmah zatvoreno
            continue;
        };
        let (tls, upstream) = (tls.clone(), upstream.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tokio::time::timeout(limits.connection_deadline, serve_connection(stream, peer, tls, upstream, limits)).await;
        });
    }
}

/// Port s isključivim pravom (SO_EXCLUSIVEADDRUSE) – drugi proces ga ne može preuzeti dok gateway radi.
pub fn bind(cfg: ListenConfig) -> std::io::Result<TcpListener> {
    let addr = SocketAddr::new(if cfg.lan { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::LOCALHOST) }, cfg.port);
    let socket = tokio::net::TcpSocket::new_v4()?;
    crate::win::exclusive_address(&socket)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// Upravljanje portom prema postavkama poslužitelja (provjera svakih 5 s preko kanala).
pub async fn run(backend: Arc<Backend>, tls: TlsAcceptor, limits: Limits) {
    let tracker = Arc::new(Tracker::default());
    let mut current: Option<(ListenConfig, JoinHandle<()>)> = None;
    let mut last_error = String::new();
    loop {
        match backend.config().await {
            Ok(cfg) if current.as_ref().map(|c| c.0) != Some(cfg) => {
                if let Some((_, h)) = current.take() {
                    h.abort();
                }
                match bind(cfg) {
                    Ok(listener) => {
                        log::info(&format!(
                            "Slušam na {}:{} ({})",
                            if cfg.lan { "0.0.0.0" } else { "127.0.0.1" },
                            cfg.port,
                            if cfg.lan { "HTTPS u mreži, HTTP samo s loopbacka" } else { "samo loopback" }
                        ));
                        let h = tokio::spawn(accept_loop(listener, tls.clone(), backend.clone(), limits, tracker.clone()));
                        current = Some((cfg, h));
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
        let limits = Limits { per_ip: 4, loopback_per_ip: 6, global: 10, ..Limits::default() };
        let ip: IpAddr = "192.168.1.9".parse().unwrap();
        let held: Vec<_> = (0..4).map(|_| t.acquire(ip, &limits).unwrap()).collect();
        assert!(t.acquire(ip, &limits).is_none(), "5. veza s istog IP-a se odbija");
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let lo_held: Vec<_> = (0..6).map(|_| t.acquire(lo, &limits).unwrap()).collect();
        assert!(t.acquire("10.0.0.1".parse().unwrap(), &limits).is_none(), "ukupna granica");
        drop(held);
        assert_eq!(t.active(), 6);
        assert!(t.acquire(ip, &limits).is_some());
        drop(lo_held);
    }
}

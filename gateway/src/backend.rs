//! Veza prema C++ servisu poslužitelja (SolarniServer.exe --service, SYSTEM) preko imenovanog kanala.
//! Do 8 istodobnih veza (servis ima 8 instanci kanala); svaka veza ima svoj izazov (nonce) iz poruke hello.

use crate::frame::{read_frame, write_frame, MAX_REQUEST, MAX_RESPONSE};
use crate::win;
use serde_json::{json, Value};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

pub const MAX_CONNECTIONS: usize = 8;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenConfig {
    pub port: u16,
    pub lan: bool,
}

struct Conn {
    pipe: NamedPipeClient,
    nonce: String,
}

pub struct Backend {
    pipe_name: String,
    owner_sid: String,
    hello: Value,
    pool: Mutex<Vec<Conn>>,
    slots: Semaphore,
    next_id: AtomicU64,
}

impl Backend {
    pub fn new(pipe_name: String, owner_sid: String, fingerprint: &str, not_after: &str) -> Arc<Self> {
        Arc::new(Backend {
            pipe_name,
            owner_sid,
            hello: json!({"type": "hello", "fingerprint": fingerprint, "not_after": not_after,
                          "version": env!("CARGO_PKG_VERSION")}),
            pool: Mutex::new(Vec::new()),
            slots: Semaphore::new(MAX_CONNECTIONS),
            next_id: AtomicU64::new(1),
        })
    }

    async fn connect(&self) -> io::Result<Conn> {
        let mut pipe = win::connect_pipe(&self.pipe_name, &self.owner_sid)?;
        let hello = timeout(HELLO_TIMEOUT, read_frame(&mut pipe, 4096))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "servis nije poslao hello"))??;
        let nonce = match (hello["type"].as_str(), hello["nonce"].as_str()) {
            (Some("hello"), Some(n)) if n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()) => n.to_string(),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "neispravan hello servisa")),
        };
        let mut conn = Conn { pipe, nonce };
        // svaka nova veza javlja otisak certifikata (servis ga zapisuje samo kad se promijeni)
        self.exchange(&mut conn, self.hello.clone()).await?;
        Ok(conn)
    }

    async fn exchange(&self, conn: &mut Conn, mut msg: Value) -> io::Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        msg["v"] = json!(1);
        msg["nonce"] = json!(conn.nonce);
        msg["id"] = json!(id);
        let frame_len = serde_json::to_vec(&msg).map(|v| v.len()).unwrap_or(usize::MAX);
        if frame_len > MAX_REQUEST {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zahtjev je prevelik"));
        }
        let pipe = &mut conn.pipe;
        timeout(CALL_TIMEOUT, async {
            write_frame(pipe, &msg).await?;
            let resp = read_frame(pipe, MAX_RESPONSE).await?;
            if resp["id"].as_u64() != Some(id) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "odgovor ne pripada zahtjevu"));
            }
            Ok(resp)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "servis nije odgovorio na vrijeme"))?
    }

    /// Jedan zahtjev; ako postojeća veza više ne vrijedi (servis ponovno pokrenut), jedan pokušaj s novom vezom.
    pub async fn call(&self, msg: Value) -> io::Result<Value> {
        let _slot = self.slots.acquire().await.map_err(|_| io::Error::other("zatvoreno"))?;
        let pooled = self.pool.lock().await.pop();
        let (mut conn, fresh) = match pooled {
            Some(c) => (c, false),
            None => (self.connect().await?, true),
        };
        let result = match self.exchange(&mut conn, msg.clone()).await {
            Err(e) if !fresh && matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof) => {
                conn = self.connect().await?;
                self.exchange(&mut conn, msg).await
            }
            other => other,
        };
        if result.is_ok() {
            let mut pool = self.pool.lock().await;
            if pool.len() < MAX_CONNECTIONS {
                pool.push(conn);
            }
        }
        result
    }

    /// Port i način rada (LAN) iz postavki poslužitelja.
    pub async fn config(&self) -> io::Result<ListenConfig> {
        let r = self.call(json!({"type": "config"})).await?;
        let port = r["config"]["port"].as_u64().filter(|p| (1..=65535).contains(p));
        match (r["ok"].as_bool(), port, r["config"]["lan"].as_bool()) {
            (Some(true), Some(port), Some(lan)) => Ok(ListenConfig { port: port as u16, lan }),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "neispravne postavke servisa")),
        }
    }
}

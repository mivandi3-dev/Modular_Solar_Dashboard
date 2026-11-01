//! Jednostavan zapisnik: datoteka gateway.log u mapi gatewaya (rotacija na 2 MB, 3 stare) i stderr u načinu konzole.
//! Ne zapisuju se zahtjevi, oznake ni lozinke – samo pokretanje, portovi i greške.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 2_000_000;

struct Sink {
    path: Option<PathBuf>,
    file: Option<File>,
    console: bool,
}

static SINK: Mutex<Sink> = Mutex::new(Sink { path: None, file: None, console: true });

pub fn init(path: Option<PathBuf>, console: bool) {
    let mut s = SINK.lock().unwrap_or_else(|e| e.into_inner());
    s.file = path.as_ref().and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
    s.path = path;
    s.console = console;
}

fn rotate(s: &mut Sink) {
    let Some(path) = s.path.clone() else { return };
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) < MAX_BYTES {
        return;
    }
    s.file = None;
    for i in (1..3).rev() {
        let _ = std::fs::rename(path.with_extension(format!("log.{i}")), path.with_extension(format!("log.{}", i + 1)));
    }
    let _ = std::fs::rename(&path, path.with_extension("log.1"));
    s.file = OpenOptions::new().create(true).append(true).open(&path).ok();
}

fn write(level: &str, msg: &str) {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let t = time::OffsetDateTime::from_unix_timestamp(secs as i64).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let line = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC {level} {msg}\n",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    let mut s = SINK.lock().unwrap_or_else(|e| e.into_inner());
    rotate(&mut s);
    if let Some(f) = s.file.as_mut() {
        let _ = f.write_all(line.as_bytes());
    }
    if s.console {
        eprint!("{line}");
    }
}

pub fn info(msg: &str) {
    write("INFO   ", msg);
}

pub fn warn(msg: &str) {
    write("WARNING", msg);
}

pub fn error(msg: &str) {
    write("ERROR  ", msg);
}

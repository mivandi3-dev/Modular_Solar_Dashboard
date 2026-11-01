//! Solarni monitor 4.0 – mrežni ulaz Solarnog poslužitelja (arhitektura B1, ADR-001).
//!
//! ```text
//! klijent ──TLS──► solari-gateway.exe (NT SERVICE\SolariGateway, bez administratorskih prava)
//!                     │ rustls + hyper, rokovi, veličine, veze po IP-u, samo rute API-ja
//!                     ▼ okvir (4 B duljina + JSON), izazov po vezi
//!          \\.\pipe\SolarniServer.Api.v1 (vlasnik SYSTEM; DACL: SYSTEM + SID usluge gatewaya)
//!                     ▼
//!          SolarniServer.exe --service (C++, SYSTEM): prijava, korisnici, baza, uređaji
//! ```
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod backend;
pub mod frame;
pub mod http;
pub mod log;
pub mod server;
pub mod tlscert;
pub mod win;

pub const SERVICE_NAME: &str = "SolariGateway";
pub const PIPE_NAME: &str = r"\\.\pipe\SolarniServer.Api.v1";
pub const SYSTEM_SID: &str = "S-1-5-18";

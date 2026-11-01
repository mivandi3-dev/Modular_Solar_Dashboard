//! solari-gateway.exe
//!   --service            Windows usluga SolariGateway (instalacija: sc create … obj= "NT SERVICE\SolariGateway")
//!   --console            isto, u konzoli (razvoj, dijagnostika)
//!   --data-dir <mapa>    certifikat i zapisnik (zadano %ProgramData%\SolarniServer\gateway)
//!   --pipe, --pipe-owner samo uz značajku `dev` (testovi bez administratora)

use solari_gateway::{backend::Backend, log, server, tlscert, PIPE_NAME, SERVICE_NAME, SYSTEM_SID};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

struct Options {
    data_dir: PathBuf,
    pipe: String,
    pipe_owner: String,
}

fn parse_options() -> Result<(Options, bool), String> {
    let mut args = std::env::args().skip(1);
    let program_data = std::env::var_os("PROGRAMDATA").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let mut o =
        Options { data_dir: program_data.join("SolarniServer").join("gateway"), pipe: PIPE_NAME.into(), pipe_owner: SYSTEM_SID.into() };
    let mut service = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--service" => service = Some(true),
            "--console" => service = Some(false),
            "--data-dir" => o.data_dir = args.next().map(PathBuf::from).ok_or("--data-dir bez mape")?,
            #[cfg(feature = "dev")]
            "--pipe" => o.pipe = args.next().ok_or("--pipe bez imena")?,
            #[cfg(feature = "dev")]
            "--pipe-owner" => o.pipe_owner = args.next().ok_or("--pipe-owner bez SID-a")?,
            other => return Err(format!("nepoznat argument: {other}")),
        }
    }
    let service = service.ok_or("upotreba: solari-gateway.exe --service | --console [--data-dir <mapa>]")?;
    Ok((o, service))
}

async fn run(o: Options) -> std::io::Result<()> {
    std::fs::create_dir_all(&o.data_dir)?;
    let (id, created) = tlscert::load_or_create(&o.data_dir)?;
    log::info(&format!(
        "Solarni gateway {} pokrenut kao {}; certifikat {} (do {}), kod za uparivanje {}",
        env!("CARGO_PKG_VERSION"),
        solari_gateway::win::current_user_sid().unwrap_or_default(),
        if created { "izrađen" } else { "učitan" },
        id.not_after,
        tlscert::pairing_code(&id.fingerprint).unwrap_or_default()
    ));
    if o.pipe_owner != SYSTEM_SID {
        log::warn(&format!("RAZVOJ: očekivani vlasnik kanala {} (nije SYSTEM)", o.pipe_owner));
    }
    let tls = server::tls_acceptor(&id)?;
    let backend = Backend::new(o.pipe, o.pipe_owner, &id.fingerprint, &id.not_after);
    server::run(backend, tls, server::Limits::default(), Some(o.data_dir.join("listen.json"))).await;
    Ok(())
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build()
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let options = match parse_options() {
        Ok((o, _)) => o,
        Err(e) => {
            log::error(&e);
            return;
        }
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = std::sync::Mutex::new(Some(stop_tx));
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else {
        log::error("Registracija usluge nije uspjela");
        return;
    };
    let set = |state, accept, exit_code| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        });
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, ServiceExitCode::Win32(0));
    log::init(Some(options.data_dir.join("gateway.log")), false);
    // greška (npr. port zauzet) → izlazni kod različit od 0, da upravitelj usluga primijeni akcije ponovnog pokretanja
    // (sc failure … + failureflag 1); uredno zaustavljanje (Stop/Shutdown) → 0
    let failed = match runtime() {
        Ok(rt) => rt.block_on(async {
            tokio::select! {
                r = run(options) => match r {
                    Err(e) => { log::error(&format!("Gateway: {e}")); true }
                    Ok(()) => { log::error("Gateway je završio bez zahtjeva za zaustavljanje"); true }
                },
                _ = stop_rx => { log::info("Usluga zaustavljena"); false }
            }
        }),
        Err(e) => {
            log::error(&format!("Tokio: {e}"));
            true
        }
    };
    let exit_code = if failed { ServiceExitCode::ServiceSpecific(1) } else { ServiceExitCode::Win32(0) };
    set(ServiceState::Stopped, ServiceControlAccept::empty(), exit_code);
}

fn main() {
    let (options, service) = match parse_options() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if service {
        log::init(Some(options.data_dir.join("gateway.log")), false);
        if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            log::error(&format!("Pokretanje usluge nije uspjelo (pokreće ga upravitelj usluga): {e}"));
            std::process::exit(1);
        }
        return;
    }
    let _ = std::fs::create_dir_all(&options.data_dir);
    log::init(Some(options.data_dir.join("gateway.log")), true);
    match runtime() {
        Ok(rt) => {
            if let Err(e) = rt.block_on(run(options)) {
                log::error(&format!("Gateway: {e}"));
                std::process::exit(1);
            }
        }
        Err(e) => {
            log::error(&format!("Tokio: {e}"));
            std::process::exit(1);
        }
    }
}

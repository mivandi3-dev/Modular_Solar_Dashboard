// Solarni poslužitelj bez prozora (SolarniServer.exe --service, zadatak sustava iz instalacije):
// bilježi logger u bazu (poller), šalje obavijesti i poslužuje API za klijente (src/api.cpp).
// 4.0 (B1): API prima Rust gateway (solari-gateway.exe) i prosljeđuje ga kanalom (src/api_ipc.cpp);
// uz "server_gateway": false radi rezervni put A (C++ HTTPS listener).
// Promjene postavki (port, pristup iz mreže, logger, slike) preuzima sam, bez ponovnog pokretanja.
#include <windows.h>

#include <memory>
#include <mutex>
#include <regex>

#include "api.hpp"
#include "api_ipc.hpp"
#include "i18n.hpp"
#include "poller.hpp"
#include "system.hpp"
#include "tls.hpp"

namespace sm {

namespace {
constexpr DWORD kCheckMs = 2000;

std::time_t config_stamp() {
    std::error_code ec;
    const auto t = fs::last_write_time(config_file(), ec);
    return ec ? 0 : static_cast<std::time_t>(t.time_since_epoch().count() / 10'000'000);
}
}  // namespace

int run_server_service() {
    log_open(service_logs_dir() / L"server.log");  // 4.0: zapisi procesa SYSTEM odvojeno
    install_crash_logging("Solarni poslužitelj");
    NamedMutex mutex(kServerServiceMutex);
    if (!mutex.owned()) {
        log_info("Solarni poslužitelj već radi – ova instanca se zatvara");
        return 0;
    }
    log_info(std::string("Solarni poslužitelj ") + SOLARI_VERSION + " pokrenut (" + narrow(home_dir().wstring()) + ")");
    std::unique_ptr<UserStore> users;
    for (;;) {  // bez ključa korisnika API ne smije raditi (nitko se ne bi mogao prijaviti, a ne smije pustiti sve)
        try {
            users = std::make_unique<UserStore>(users_db_file(), load_or_create_user_keys(users_key_file()));
            break;
        } catch (const std::exception& e) {
            log_error(std::string("Korisnici: ") + e.what() + " – novi pokušaj za minutu");
            Sleep(60'000);
        }
    }
    if (!users->has_admin()) log_warn("Nema administratora – otvorite Solarni poslužitelj i izradite ga (do tada nitko se ne može prijaviti)");
    const Catalog catalog = load_catalog(exe_dir() / L"web" / L"catalog.json");
    DataService data(db_file());
    WeatherService weather;
    std::mutex settings_mutex;
    Settings settings = load_settings();
    set_language(settings.language);
    std::time_t stamp = config_stamp();

    Poller poller;
    poller.start();
    migrate_ui_files();  // slike poslužitelja iz data\ u ui\ (mapa poslužitelja je samo za administratore)
    const auto api = api_handler({&data, &weather, &catalog, users.get(), [&] {
        std::lock_guard lock(settings_mutex);
        return settings;
    }});

    // ------------------------------------------------ B1: Rust gateway + kanal (ADR-001)
    std::unique_ptr<ipc::PipeServer> pipe;
    std::wstring gateway_sid = ipc::service_sid(kGatewayService);
    bool owner_system = true;
#ifdef SOLARI_DEV_BUILD
    // samo razvojna gradnja (testovi bez administratora): SID gatewaya i ime kanala iz okoline
    if (const wchar_t* sid = _wgetenv(L"SOLARI_DEV_GATEWAY_SID"); sid && *sid) {
        gateway_sid = sid;
        owner_system = false;
    }
    const wchar_t* dev_pipe = _wgetenv(L"SOLARI_DEV_API_PIPE");
    const std::wstring pipe_name = dev_pipe && *dev_pipe ? dev_pipe : kApiPipe;
#else
    const std::wstring pipe_name = kApiPipe;
#endif
    const auto start_pipe = [&] {
        ipc::PipeServerConfig cfg;
        cfg.name = pipe_name;
        cfg.sddl = api_pipe_sddl(gateway_sid, owner_system);
        cfg.instances = 8;
        cfg.io_timeout_ms = 15'000;
        cfg.idle_timeout_ms = 0;            // gateway drži veze otvorenima
        cfg.requests_per_connection = 0;
        cfg.max_request_bytes = ipc::kMaxRequestBytes;
        cfg.authorize = [gateway_sid](const ipc::Caller& c) { return c.sid == gateway_sid; };  // samo usluga gatewaya
        auto server = std::make_unique<ipc::PipeServer>(
            cfg, api_ipc_handler(api,
                                 [&] {
                                     std::lock_guard lock(settings_mutex);
                                     return GatewayConfig{settings.server_port, settings.server_lan};
                                 },
                                 [](const json& hello) {
                                     static const std::regex fp(R"(^([0-9A-F]{2}:){31}[0-9A-F]{2}$)");
                                     const std::string f = hello.value("fingerprint", std::string());
                                     if (!std::regex_match(f, fp)) return;
                                     json info = {{"fingerprint", f}, {"not_after", hello.value("not_after", std::string())},
                                                  {"version", hello.value("version", std::string())}, {"updated", utc_text(now())}};
                                     if (const auto old = gateway_info(); old && (*old)["fingerprint"] == f) return;
                                     if (no_reparse_points(service_dir())) {
                                         write_file_atomic(gateway_info_file(), info.dump(2));
                                         log_info("Gateway: otisak certifikata " + f);
                                     }
                                 }));
        server->start();
        log_info("API: kanal za gateway " + narrow(pipe_name) + " (C++ nema TCP port za API)");
        return server;
    };

    // ------------------------------------------------ A (rezerva): C++ HTTPS listener
    // HTTPS u lokalnoj mreži; bez certifikata API sluša samo na 127.0.0.1 (nikad nešifrirano u mreži)
    std::shared_ptr<TlsCredentials> tls;
    std::unique_ptr<HttpServer> http;
    const auto lan = [&](bool want) { return want && tls != nullptr; };
    const auto start_http = [&] {
        if (!tls) {
            try {
                tls = std::make_shared<TlsCredentials>();
                log_info("HTTPS: otisak certifikata " + tls->cert().fingerprint);
            } catch (const std::exception& e) {
                log_error(std::string("HTTPS: ") + e.what() + " – API samo na 127.0.0.1");
            }
        }
        auto server = std::make_unique<HttpServer>(api);
        if (tls) server->set_tls(tls);
        server->start(settings.server_port, lan(settings.server_lan));
        log_warn("API: rezervni put A – C++ HTTP poslužitelj na portu " + std::to_string(settings.server_port));
        return server;
    };

    bool gateway_mode = settings.server_gateway;
    const auto switch_mode = [&] {
        try {
            if (gateway_mode) {
                http.reset();
                if (!pipe) pipe = start_pipe();
            } else {
                pipe.reset();
                if (!http) http = start_http();
            }
        } catch (const std::exception& e) {
            log_error(std::string("API: ") + e.what());
        }
    };
    switch_mode();
    for (;;) {  // poslužitelj ne smije sam izaći – greška se zapiše i nastavlja se
        Sleep(kCheckMs);
        try {
            if (config_stamp() == stamp) {
                if (gateway_mode && !pipe) switch_mode();  // npr. ime kanala je bilo zauzeto
                if (!gateway_mode && http && !http->port()) http->start(settings.server_port, lan(settings.server_lan));
                continue;
            }
            stamp = config_stamp();
            const Settings next = load_settings();
            bool restart = false;
            {
                std::lock_guard lock(settings_mutex);
                restart = next.server_port != settings.server_port || next.server_lan != settings.server_lan;
                settings = next;
            }
            set_language(next.language);
            log_info("Postavke poslužitelja promijenjene");
            if (next.server_gateway != gateway_mode) {
                gateway_mode = next.server_gateway;
                switch_mode();
            } else if (restart && http) {
                http->start(next.server_port, lan(next.server_lan));
            }
            // u načinu gatewaya port i sučelje preuzima gateway porukom "config"
        } catch (const std::exception& e) {
            log_error(std::string("Poslužitelj: ") + e.what());
        }
    }
}

}  // namespace sm

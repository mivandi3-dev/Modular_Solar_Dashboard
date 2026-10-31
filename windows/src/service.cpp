// Solarni poslužitelj bez prozora (SolarniServer.exe --service, zadatak sustava iz instalacije):
// bilježi logger u bazu (poller), šalje obavijesti i poslužuje API za klijente (src/api.cpp).
// Promjene postavki (port, pristup iz mreže, logger, slike) preuzima sam, bez ponovnog pokretanja.
#include <windows.h>

#include <mutex>

#include "api.hpp"
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
    // HTTPS u lokalnoj mreži; bez certifikata API sluša samo na 127.0.0.1 (nikad nešifrirano u mreži)
    std::shared_ptr<TlsCredentials> tls;
    try {
        tls = std::make_shared<TlsCredentials>();
        log_info("HTTPS: otisak certifikata " + tls->cert().fingerprint);
    } catch (const std::exception& e) {
        log_error(std::string("HTTPS: ") + e.what() + " – API samo na 127.0.0.1");
    }
    const auto lan = [&](bool want) { return want && tls != nullptr; };
    HttpServer api(api_handler({&data, &weather, &catalog, users.get(), [&] {
        std::lock_guard lock(settings_mutex);
        return settings;
    }}));
    if (tls) api.set_tls(tls);
    api.start(settings.server_port, lan(settings.server_lan));
    for (;;) {  // poslužitelj ne smije sam izaći – greška se zapiše i nastavlja se
        Sleep(kCheckMs);
        try {
            if (config_stamp() == stamp) {
                if (!api.port()) api.start(settings.server_port, lan(settings.server_lan));  // npr. port je bio zauzet
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
            if (restart) api.start(next.server_port, lan(next.server_lan));
        } catch (const std::exception& e) {
            log_error(std::string("Poslužitelj: ") + e.what());
        }
    }
}

}  // namespace sm

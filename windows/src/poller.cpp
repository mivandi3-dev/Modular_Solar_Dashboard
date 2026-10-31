#include "poller.hpp"

#include "offgrid.hpp"

#include <windows.h>

#include <chrono>
#include <memory>

#include "alerts.hpp"
#include "fronius.hpp"
#include "modbus.hpp"
#include "sunspec.hpp"
#include "vendors.hpp"
#include "net.hpp"
#include "system.hpp"
#include "i18n.hpp"
#include "util.hpp"
#include "weather.hpp"

namespace sm {

namespace {
constexpr int kMinIntervalS = 5;
constexpr int kRecheckMutexS = 300;  // koliko često provjeriti je li stao poller zadatka sustava
constexpr int kWaitForConfigS = 10;
constexpr int kForecastTtlS = 3600;
const wchar_t* g_poller_mutex = kPollerMutex;  // prognoza za provjeru niske proizvodnje

// Obavijesti e-poštom nakon svakog očitanja (src/alerts.cpp); šalju se u zasebnoj niti.
class Notifier {
public:
    explicit Notifier(Db* db) : state_(load_alert_state()) {
        if (db) if (const auto last = db->latest()) last_ok_ = last->ts;
    }

    void process(const Settings& s, const PlantReading* p, const std::string& error) {
        if (s.smtp_host.empty() || trim(s.alert_emails).empty()) return;
        const std::time_t t = now();
        if (p) last_ok_ = t;
        Observation obs{t, p != nullptr, last_ok_};
        if (p) {
            obs.status = p->reading.status;
            obs.day_kwh = p->reading.e_daily_kwh;
            obs.expected_kwh = expected(s, t);
        }
        obs.error = error;
        auto [state, messages] = evaluate_alerts(s, state_, obs);
        if (!(state == state_)) {
            state_ = state;
            try {
                save_alert_state(state_);
            } catch (const std::exception& e) {
                log_error(std::string("Stanje obavijesti nije spremljeno: ") + e.what());
            }
        }
        for (auto& m : messages) {
            std::thread([s, m] {
                NetInit net;
                try {
                    send_mail(s, m.subject, m.body);
                } catch (const std::exception& e) {
                    log_warn("Obavijest „" + m.subject + "“ nije poslana: " + e.what());
                }
            }).detach();
        }
    }

private:
    std::optional<double> expected(const Settings& s, std::time_t t) {
        if (!wants_forecast(s, state_, t)) return std::nullopt;
        if (t - forecast_at_ > kForecastTtlS) {
            forecast_at_ = t;
            try {
                const auto ip = source_ip(s.internet_interface);
                hourly_ = WeatherService::fetch(s.weather_lat, s.weather_lon, ip.value_or("")).value("hourly", json::array());
            } catch (const std::exception& e) {
                log_warn(std::string("Prognoza za obavijesti nije dostupna: ") + e.what());
                hourly_ = json::array();
            }
        }
        if (hourly_.empty()) return std::nullopt;
        return expected_until(hourly_, t, s.peak_power_kwp);
    }

    AlertState state_;
    std::optional<std::time_t> last_ok_;
    std::time_t forecast_at_ = 0;
    json hourly_ = json::array();
};

std::time_t config_mtime() {
    std::error_code ec;
    const auto t = fs::last_write_time(config_file(), ec);
    return ec ? 0 : static_cast<std::time_t>(t.time_since_epoch().count() / 10'000'000);
}

std::string describe(const Settings& s) {
    std::string via = s.logger_interface.empty() ? "" : " preko kartice „" + s.logger_interface + "“";
    const std::string device = s.device_type == "inverter" ? " inverter " + s.inverter_units
                                                           : " logger unit " + std::to_string(s.modbus_unit_id);
    return s.modbus_host + ":" + std::to_string(s.modbus_port) + device + via +
           ", svakih " + std::to_string(std::max(kMinIntervalS, s.poll_interval_s)) + " s";
}

// Spavanje do sljedećeg višekratnika intervala (ravnomjerna očitanja), prekidivo.
void sleep_aligned(int interval_s, const std::atomic<bool>& stop) {
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
    long long wait = interval_s * 1000LL - now_ms % (interval_s * 1000LL);
    while (wait > 0 && !stop) {
        const long long step = std::min<long long>(wait, 200);
        Sleep(static_cast<DWORD>(step));
        wait -= step;
    }
}

// Petlja pollera (zajednička za nit i --poller način).
void loop(const std::atomic<bool>& stop) {
    while (!is_configured() && !stop) {
        log_info("Poller čeka postavke (prvo pokretanje aplikacije)");
        for (int i = 0; i < kWaitForConfigS * 5 && !stop; ++i) Sleep(200);
    }
    Settings s = load_settings();
    set_language(s.language);  // obavijesti e-poštom na jeziku aplikacije
    std::time_t mtime = config_mtime();
    std::unique_ptr<Db> db;
    try {
        db = std::make_unique<Db>(db_file());
    } catch (const std::exception& e) {
        log_error(std::string("Baza: ") + e.what());
    }
    Notifier notifier(db.get());
    int failures = 0;
    std::optional<Date> backup_day;
    log_info("Poller pokrenut: " + describe(s));
    while (!stop) {
        if (config_mtime() != mtime) {
            s = load_settings();
            set_language(s.language);
            mtime = config_mtime();
            log_info("Postavke promijenjene: " + describe(s));
        }
        try {
            if (!db) db = std::make_unique<Db>(db_file());
        } catch (const std::exception& e) {
            log_error(std::string("Baza: ") + e.what());
        }
        const Date today = local_date(now());
        if (backup_day != today && db) {
            backup_day = today;
            try {
                if (auto created = daily_backup(db_file(), backups_dir(), s.backup_keep_days, today)) {
                    log_info("Sigurnosna kopija baze: " + narrow(created->wstring()));
                }
            } catch (const std::exception& e) {
                log_error(std::string("Sigurnosna kopija baze nije uspjela: ") + e.what());
            }
        }
        if (s.data_source == "cloud") {  // podatke bilježi Solarni poslužitelj – ovdje nema loggera
            sleep_aligned(std::max(kMinIntervalS, s.poll_interval_s), stop);
            continue;
        }
        std::optional<PlantReading> plant;
        std::string error;
        try {
            plant = read_plant(s);
        } catch (const std::exception& e) {
            error = e.what();
            log_warn(error);
        }
        bool ok = false;
        if (plant && db) {
            if (!plant->meter_error.empty()) log_warn("Mjerač (unit " + std::to_string(s.meter_unit_id) + "): " + plant->meter_error);
            try {
                db->insert(now(), plant->reading, plant->load_kw);
                ok = true;
            } catch (const std::exception& e) {
                log_error(std::string("Upis u bazu nije uspio: ") + e.what());
            }
        }
        try {
            notifier.process(s, plant ? &*plant : nullptr, error);
        } catch (const std::exception& e) {  // obavijesti nikad ne smiju zaustaviti bilježenje
            log_error(std::string("Obavijesti: ") + e.what());
        }
        if (ok && failures) log_info("SmartLogger ponovno dostupan nakon " + std::to_string(failures) + " neuspjelih pokušaja");
        failures = ok ? 0 : failures + 1;
        sleep_aligned(std::max(kMinIntervalS, s.poll_interval_s), stop);
    }
    log_info("Poller zaustavljen");
}

}  // namespace

// Huawei SUN2000 (Modbus Interface Definitions): temperatura 32087, napon faze A 32069, frekvencija 32085;
// baterija LUNA2000: SOC 37760, snaga punjenja/pražnjenja 37765 (> 0 punjenje). Što inverter nema, preskače se.
json huawei_inverter_extras(ModbusClient& client, int unit) {
    json x = json::object();
    auto get = [&](const char* key, const Register& reg) {
        try {
            x[key] = client.read_value(reg, unit);
        } catch (const ModbusError&) {
        }
    };
    get("inverter_temp", Register{32087, "I16", 10});
    get("grid_v", Register{32069, "U16", 10});
    get("grid_hz", Register{32085, "U16", 100});
    get("battery_soc", Register{37760, "U16", 10});
    if (x.contains("battery_soc")) {
        get("battery_kw", Register{37765, "I32", 1000});
        x["battery_dir"] = true;
    }
    return x;
}

PlantReading read_plant(const Settings& s) {
    if (s.device_type == "sunspec") return read_sunspec(s);
    if (s.device_type == "fronius") return read_fronius(s);
    if (s.device_type == "vendor") return read_vendor(s);
    if (s.device_type == "voltronic") return read_voltronic(s);
    if (s.device_type == "vedirect") return read_vedirect(s);
    constexpr int kInverterTimeoutMs = 10'000;  // SDongle i WLAN invertera odgovaraju sporije
    constexpr DWORD kInverterConnectDelayMs = 1000;  // inverter odbija zahtjeve odmah nakon spajanja
    const bool inverter = s.device_type == "inverter";
    const auto src = source_ip(s.logger_interface);
    ModbusClient client(s.modbus_host, s.modbus_port, s.modbus_unit_id, src.value_or(""), inverter ? kInverterTimeoutMs : 5000,
                        inverter ? "Inverter" : "SmartLogger");
    client.connect();
    PlantReading out;
    if (inverter) {
        const auto units = parse_units(s.inverter_units);
        if (!units) throw std::runtime_error(tr("Upišite adrese invertera odvojene zarezom, npr. 1 ili 1,2,3 (0–247, najviše 10)."));
        Sleep(kInverterConnectDelayMs);
        for (size_t i = 0; i < units->size(); ++i) {
            const Reading r = client.read_inverter((*units)[i]);
            if (i == 0) out.extra = huawei_inverter_extras(client, (*units)[i]);
            out.reading.power_kw += r.power_kw;
            out.reading.e_daily_kwh += r.e_daily_kwh;
            out.reading.e_total_kwh += r.e_total_kwh;
            if (i == 0) { out.reading.pf = r.pf; out.reading.status = r.status; }
        }
    } else {
        out.reading = client.read();
    }
    if (s.meter_unit_id) {
        try {  // greška mjerača ne poništava očitanje elektrane
            out.load_kw = inverter ? -client.read_value(kInvMeterPowerKw, s.meter_unit_id) : client.read_meter_kw(s.meter_unit_id);
        } catch (const ModbusError& e) {
            out.meter_error = e.what();
        }
    }
    return out;
}

std::vector<std::string> device_capabilities(const Settings& s) {
    std::vector<std::string> caps;
    auto add = [&](const char* c) { if (std::find(caps.begin(), caps.end(), c) == caps.end()) caps.emplace_back(c); };
    if (s.device_type == "inverter") { add("battery"); add("temperature"); add("grid"); }
    if (s.device_type == "sunspec") { add("temperature"); add("grid"); }
    if (s.device_type == "fronius") add("battery");
    if (s.device_type == "voltronic") { add("battery"); add("temperature"); add("grid"); add("offgrid"); }
    if (s.device_type == "vedirect") { add("battery"); add("offgrid"); }
    if (s.device_type == "vendor") {
        if (const VendorProfile* p = find_vendor(s.device_profile)) {
            for (const auto& [key, point] : p->extras) {
                const std::string k = key;
                if (k == "battery_soc") add("battery");
                if (k == "inverter_temp") add("temperature");
                if (k == "grid_v" || k == "grid_hz") add("grid");
                if (k == "battery_v" || k == "ac_load_w" || k == "ac_out_v") add("offgrid");
            }
        }
    }
    return caps;
}

double integrate_total(Db& db, std::time_t t, double power_kw) {
    constexpr std::time_t kMaxGapS = 15 * 60;  // dulji prekid: ne nagađa se što je bilo između
    const auto last = db.latest();
    if (!last) return 0;
    const std::time_t dt = t - last->ts;
    if (dt <= 0 || dt > kMaxGapS) return last->e_total_kwh;
    return last->e_total_kwh + (last->power_kw + power_kw) / 2.0 * static_cast<double>(dt) / 3600.0;
}

double daily_from_total(Db& db, std::time_t t, double e_total_kwh) {
    const auto base = db.day_start_total(local_midnight(local_date(t)));
    return base ? std::max(0.0, e_total_kwh - *base) : 0.0;
}

bool poll_once(const Settings& s, Db& db) {
    try {
        PlantReading p = read_plant(s);
        if (!p.meter_error.empty()) log_warn("Mjerač (unit " + std::to_string(s.meter_unit_id) + "): " + p.meter_error);
        const std::time_t t = now();
        if (p.reading.e_total_kwh < 0) p.reading.e_total_kwh = integrate_total(db, t, p.reading.power_kw);
        if (p.reading.e_daily_kwh < 0) p.reading.e_daily_kwh = daily_from_total(db, t, p.reading.e_total_kwh);
        db.insert(t, p.reading, p.load_kw, p.extra);
        return true;
    } catch (const std::exception& e) {
        log_warn(e.what());
        return false;
    }
}

void Poller::start() {
    stop_ = false;
    thread_ = std::thread([this] { run(); });
}

void Poller::stop() {
    stop_ = true;
    if (thread_.joinable()) thread_.join();
}

void Poller::run() {
    NetInit net;
    while (!stop_) {
        NamedMutex mutex(g_poller_mutex);
        if (mutex.owned()) {
            active_ = true;
            loop(stop_);
            active_ = false;
            return;
        }
        // Bilježi zadatak sustava – provjeri povremeno radi li još.
        for (int i = 0; i < kRecheckMutexS * 5 && !stop_; ++i) Sleep(200);
    }
}

void set_poller_mutex(const wchar_t* name) { g_poller_mutex = name; }

int run_poller_mode() {
    log_open(logs_dir() / L"poller.log");
    install_crash_logging("Poller");
    NetInit net;
    NamedMutex mutex(g_poller_mutex);
    if (!mutex.owned()) {
        log_info("Poller već radi – ova instanca se zatvara");
        return 0;
    }
    const std::atomic<bool> never{false};
    loop(never);
    return 0;
}

}  // namespace sm

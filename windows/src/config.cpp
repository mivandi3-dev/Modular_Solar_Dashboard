#include "config.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cmath>
#include <regex>
#include <sstream>

#include "i18n.hpp"
#include "secret.hpp"
#include "serial.hpp"
#include "util.hpp"
#include "vendors.hpp"

namespace sm {

namespace {

constexpr ULONGLONG kPinIterations = 200'000;  // isto kao Python verzija (desktop/forms.py)

const char* const kScales[] = {"auto", "fhd", "2k", "4k"};
const char* const kThemes[] = {"dark", "light"};
const char* const kNightModes[] = {"off", "dim", "screen_off"};
const char* const kSmtpSecurity[] = {"starttls", "ssl", "none"};

template <size_t N>
bool one_of(const std::string& v, const char* const (&list)[N]) {
    for (const char* x : list) if (v == x) return true;
    return false;
}

template <typename T>
void read(const json& j, const char* key, T& out) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return;
    try {
        out = it->get<T>();
    } catch (const json::exception&) {
        // neispravan tip – ostaje zadana vrijednost
    }
}

std::string hex(const std::vector<uint8_t>& bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (uint8_t b : bytes) { out += kDigits[b >> 4]; out += kDigits[b & 15]; }
    return out;
}

std::optional<std::vector<uint8_t>> unhex(const std::string& s) {
    if (s.size() % 2) return std::nullopt;
    std::vector<uint8_t> out;
    for (size_t i = 0; i < s.size(); i += 2) {
        try {
            out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return out;
}

std::vector<uint8_t> pbkdf2(const std::string& pin, const std::vector<uint8_t>& salt) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    std::vector<uint8_t> out(32);
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        throw std::runtime_error("BCrypt SHA-256 nije dostupan");
    }
    const NTSTATUS st = BCryptDeriveKeyPBKDF2(alg, reinterpret_cast<PUCHAR>(const_cast<char*>(pin.data())),
                                              static_cast<ULONG>(pin.size()), const_cast<PUCHAR>(salt.data()),
                                              static_cast<ULONG>(salt.size()), kPinIterations, out.data(),
                                              static_cast<ULONG>(out.size()), 0);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) throw std::runtime_error("PBKDF2 nije uspio");
    return out;
}

// Vrijednost iz obrasca (tekst ili broj; prihvaća i decimalni zarez).
std::optional<double> number(const json& v) {
    if (v.is_number()) return v.get<double>();
    if (!v.is_string()) return std::nullopt;
    std::string s;
    for (char c : v.get<std::string>()) {
        if (c == ' ') continue;
        s += c == ',' ? '.' : c;
    }
    if (s.empty()) return std::nullopt;
    char* end = nullptr;
    const double d = std::strtod(s.c_str(), &end);
    if (*end != '\0' || !std::isfinite(d)) return std::nullopt;
    return d;
}

std::string fmt_bound(double v) {
    std::ostringstream ss;
    ss << v;
    std::string s = ss.str();
    for (auto& c : s) if (c == '.') c = ',';
    return s;
}

}  // namespace

// ---------------------------------------------------------------- JSON
json to_json(const Settings& s, bool include_pin_hash) {
    json j = {
        {"modbus_host", s.modbus_host}, {"modbus_port", s.modbus_port}, {"modbus_unit_id", s.modbus_unit_id},
        {"serial_port", s.serial_port}, {"serial_baud", s.serial_baud},
        {"poll_interval_s", s.poll_interval_s}, {"meter_unit_id", s.meter_unit_id},
        {"logger_interface", s.logger_interface}, {"internet_interface", s.internet_interface},
        {"plant_name", s.plant_name}, {"location", s.location}, {"peak_power_kwp", s.peak_power_kwp},
        {"co2_factor", s.co2_factor}, {"commissioned", s.commissioned}, {"headline", s.headline},
        {"headline_running", s.headline_running}, {"headline_idle", s.headline_idle}, {"speedo_max_kw", s.speedo_max_kw},
        {"theme", s.theme}, {"language", s.language}, {"device_type", s.device_type},
        {"inverter_units", s.inverter_units}, {"meter_export_positive", s.meter_export_positive},
        {"device_profile", s.device_profile}, {"logger_serial", s.logger_serial}, {"meter_invert", s.meter_invert},
        {"palette", s.palette}, {"icon_theme", s.icon_theme},
        {"weather_lat", s.weather_lat}, {"weather_lon", s.weather_lon}, {"weather_city", s.weather_city}, {"forecast_days", s.forecast_days},
        {"display_scale", s.display_scale}, {"monitor", s.monitor}, {"start_fullscreen", s.start_fullscreen},
        {"hide_idle_cursor", s.hide_idle_cursor}, {"keep_awake", s.keep_awake}, {"backup_keep_days", s.backup_keep_days},
        {"price_kwh", s.price_kwh}, {"feedin_price_kwh", s.feedin_price_kwh}, {"currency", s.currency},
        {"night_mode", s.night_mode}, {"night_from", s.night_from}, {"night_to", s.night_to},
        {"remote_view", s.remote_view}, {"remote_port", s.remote_port}, {"remote_view_key_enc", s.remote_view_key_enc}, {"alert_emails", s.alert_emails},
        {"smtp_host", s.smtp_host}, {"smtp_port", s.smtp_port}, {"smtp_security", s.smtp_security},
        {"smtp_user", s.smtp_user}, {"smtp_password_enc", s.smtp_password_enc}, {"smtp_from", s.smtp_from},
        {"alert_offline_min", s.alert_offline_min}, {"alert_low_production", s.alert_low_production},
        {"alert_fault", s.alert_fault}, {"data_source", s.data_source}, {"cloud_url", s.cloud_url},
        {"cloud_token_enc", s.cloud_token_enc}, {"cloud_account_enc", s.cloud_account_enc}, {"cloud_cert_pin", s.cloud_cert_pin},
        {"server_port", s.server_port}, {"server_lan", s.server_lan}, {"server_gateway", s.server_gateway},
    };
    if (include_pin_hash) j["settings_pin_hash"] = s.settings_pin_hash;
    return j;
}

Settings settings_from_json(const json& j) {
    Settings s;
    if (!j.is_object()) return s;
    read(j, "modbus_host", s.modbus_host);
    read(j, "serial_port", s.serial_port);
    read(j, "serial_baud", s.serial_baud);
    read(j, "modbus_port", s.modbus_port);
    read(j, "modbus_unit_id", s.modbus_unit_id);
    read(j, "poll_interval_s", s.poll_interval_s);
    read(j, "meter_unit_id", s.meter_unit_id);
    read(j, "logger_interface", s.logger_interface);
    read(j, "internet_interface", s.internet_interface);
    read(j, "plant_name", s.plant_name);
    read(j, "location", s.location);
    read(j, "peak_power_kwp", s.peak_power_kwp);
    read(j, "co2_factor", s.co2_factor);
    read(j, "commissioned", s.commissioned);
    read(j, "headline", s.headline);
    read(j, "headline_running", s.headline_running);
    read(j, "headline_idle", s.headline_idle);
    read(j, "speedo_max_kw", s.speedo_max_kw);
    read(j, "theme", s.theme);
    read(j, "palette", s.palette);
    if (!is_palette(s.palette)) s.palette.clear();
    read(j, "icon_theme", s.icon_theme);
    if (!is_icon_theme(s.icon_theme)) s.icon_theme = "classic";
    read(j, "language", s.language);
    read(j, "device_type", s.device_type);
    read(j, "inverter_units", s.inverter_units);
    read(j, "meter_export_positive", s.meter_export_positive);
    read(j, "device_profile", s.device_profile);
    read(j, "logger_serial", s.logger_serial);
    read(j, "meter_invert", s.meter_invert);
    read(j, "weather_lat", s.weather_lat);
    read(j, "weather_lon", s.weather_lon);
    read(j, "weather_city", s.weather_city);
    read(j, "forecast_days", s.forecast_days);
    if (s.forecast_days != 2 && s.forecast_days != 3 && s.forecast_days != 5) s.forecast_days = 5;
    read(j, "display_scale", s.display_scale);
    read(j, "monitor", s.monitor);
    read(j, "start_fullscreen", s.start_fullscreen);
    read(j, "hide_idle_cursor", s.hide_idle_cursor);
    read(j, "keep_awake", s.keep_awake);
    read(j, "settings_pin_hash", s.settings_pin_hash);
    read(j, "backup_keep_days", s.backup_keep_days);
    read(j, "price_kwh", s.price_kwh);
    read(j, "feedin_price_kwh", s.feedin_price_kwh);
    read(j, "currency", s.currency);
    read(j, "night_mode", s.night_mode);
    read(j, "night_from", s.night_from);
    read(j, "night_to", s.night_to);
    read(j, "remote_view", s.remote_view);
    read(j, "remote_port", s.remote_port);
    read(j, "remote_view_key_enc", s.remote_view_key_enc);
    read(j, "alert_emails", s.alert_emails);
    read(j, "smtp_host", s.smtp_host);
    read(j, "smtp_port", s.smtp_port);
    read(j, "smtp_security", s.smtp_security);
    read(j, "smtp_user", s.smtp_user);
    read(j, "smtp_password_enc", s.smtp_password_enc);
    read(j, "smtp_from", s.smtp_from);
    read(j, "alert_offline_min", s.alert_offline_min);
    read(j, "alert_low_production", s.alert_low_production);
    read(j, "alert_fault", s.alert_fault);
    read(j, "data_source", s.data_source);
    read(j, "cloud_url", s.cloud_url);
    read(j, "cloud_token_enc", s.cloud_token_enc);
    read(j, "cloud_account_enc", s.cloud_account_enc);
    read(j, "cloud_cert_pin", s.cloud_cert_pin);
    if (const auto u = normalize_server_url(s.cloud_url)) s.cloud_url = *u;  // stari http://IP:8700 → https
    read(j, "server_port", s.server_port);
    read(j, "server_lan", s.server_lan);
    read(j, "server_gateway", s.server_gateway);
    if (s.data_source != "local" && s.data_source != "cloud") s.data_source = "local";
    if (!one_of(s.night_mode, kNightModes)) s.night_mode = "off";
    if (!one_of(s.smtp_security, kSmtpSecurity)) s.smtp_security = "starttls";
    if (!one_of(s.theme, kThemes)) s.theme = "dark";
    if (!one_of(s.display_scale, kScales)) s.display_scale = "auto";
    if (!is_language(s.language)) s.language = "hr";
    if (!is_device_type(s.device_type)) s.device_type = "logger";
    return s;
}

bool valid_host_name(const std::string& host) {
    static const std::regex kIp(R"(^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$)");
    static const std::regex kHost(R"(^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9][A-Za-z0-9-]{0,62})*$)");
    static const std::regex kDigitsDots(R"(^[\d.]+$)");
    if (host.empty() || host.size() > 253) return false;
    return std::regex_match(host, kIp) || (std::regex_match(host, kHost) && !std::regex_match(host, kDigitsDots));
}

bool is_configured() { return fs::exists(config_file()); }

const std::vector<std::string>& secret_keys() {
    static const std::vector<std::string> keys = {"smtp_password_enc", "cloud_token_enc", "cloud_account_enc", "remote_view_key_enc",
                                                  "settings_pin_hash"};
    return keys;
}

fs::path secrets_file() { return secrets_dir() / L"secrets.json"; }

json strip_secrets(json j) {
    for (const auto& k : secret_keys()) j.erase(k);
    return j;
}

Settings load_settings() {
    const auto text = read_file(config_file());
    try {
        json j = text ? json::parse(*text) : json::object();  // bez config.json: zadano + tajne (PIN iz instalacije)
        // 4.0: tajne su u secrets\secrets.json (sučelje bez prava je ne može pročitati – dobiva ih od brokera)
        if (const auto secrets = read_file(secrets_file())) {
            const json sj = json::parse(*secrets, nullptr, false);
            if (sj.is_object()) {
                for (const auto& k : secret_keys()) {
                    if (sj.contains(k)) j[k] = sj[k];
                }
            }
        }
        return settings_from_json(j);
    } catch (const json::exception& e) {
        log_error(std::string("config.json nije ispravan: ") + e.what());
        return Settings{};
    }
}

bool config_has_secrets() {
    const auto text = read_file(config_file());
    if (!text) return false;
    const json j = json::parse(*text, nullptr, false);
    if (!j.is_object()) return false;
    for (const auto& k : secret_keys()) {
        if (j.contains(k) && j[k].is_string() && !j[k].get<std::string>().empty()) return true;
    }
    return false;
}

void save_secret_field(const std::string& key, const std::string& value) {
    json secrets = json::object();
    if (const auto text = read_file(secrets_file())) {
        const json sj = json::parse(*text, nullptr, false);
        if (sj.is_object()) secrets = sj;
    }
    secrets[key] = value;
    create_private_dir(secrets_dir());
    if (!no_reparse_points(secrets_dir())) throw std::runtime_error("Mapa tajni je spojnica – tajna nije spremljena");
    write_file_atomic(secrets_file(), secrets.dump(2));
}

void save_settings(const Settings& s) {
    const fs::path path = config_file();
    std::error_code ec;
    // prethodna verzija (bez tajni – i stari config.json iz 3.x/4.0.0 ih je imao)
    if (const auto old = read_file(path)) {
        const json oj = json::parse(*old, nullptr, false);
        if (oj.is_object()) write_file_atomic(fs::path(path) += L".bak", strip_secrets(oj).dump(2));
    }
    json j = to_json(s);
    json secrets = json::object();
    for (const auto& k : secret_keys()) {
        if (j.contains(k)) secrets[k] = j[k];
    }
    create_private_dir(secrets_dir());
    if (!no_reparse_points(secrets_dir())) throw std::runtime_error("Mapa tajni je spojnica – postavke nisu spremljene");
    write_file_atomic(secrets_file(), secrets.dump(2));
    write_file_atomic(path, strip_secrets(std::move(j)).dump(2));
}

std::optional<Settings> legacy_settings() {
    // Jednostavan čitač TOML-a koji piše Python verzija: [sekcija] i ključ = vrijednost.
    // Instalirana Python verzija, a ako je nema – razvojna u C:\solari (ista imena ključeva).
    const wchar_t* pd = _wgetenv(L"PROGRAMDATA");
    std::optional<std::string> text;
    for (const fs::path& file : {fs::path(pd ? pd : L"C:\\ProgramData") / L"SolarniMonitor" / L"config.toml",
                                 fs::path(L"C:\\solari\\.streamlit\\secrets.toml")}) {
        if ((text = read_file(file))) break;
    }
    if (!text) return std::nullopt;
    static const std::map<std::string, std::string> kMap = {
        {"app.plant_name", "plant_name"}, {"app.location", "location"}, {"app.peak_power_kwp", "peak_power_kwp"},
        {"app.co2_factor_kg_per_kwh", "co2_factor"}, {"app.commissioned", "commissioned"}, {"app.headline", "headline"},
        {"app.headline_running", "headline_running"}, {"app.headline_idle", "headline_idle"},
        {"app.speedo_max_kw", "speedo_max_kw"}, {"app.theme", "theme"}, {"app.language", "language"}, {"modbus.device", "device_type"},
        {"modbus.inverter_units", "inverter_units"}, {"modbus.host", "modbus_host"},
        {"modbus.port", "modbus_port"}, {"modbus.unit_id", "modbus_unit_id"}, {"modbus.meter_unit_id", "meter_unit_id"},
        {"modbus.poll_interval_s", "poll_interval_s"}, {"network.logger_interface", "logger_interface"},
        {"network.internet_interface", "internet_interface"}, {"weather.latitude", "weather_lat"},
        {"weather.longitude", "weather_lon"}, {"display.scale", "display_scale"}, {"display.monitor", "monitor"},
        {"display.start_fullscreen", "start_fullscreen"}, {"display.hide_idle_cursor", "hide_idle_cursor"},
        {"display.keep_awake", "keep_awake"}, {"system.backup_keep_days", "backup_keep_days"},
        {"savings.price_kwh", "price_kwh"}, {"savings.feedin_price_kwh", "feedin_price_kwh"}, {"savings.currency", "currency"},
        {"display.night_mode", "night_mode"}, {"display.night_from", "night_from"}, {"display.night_to", "night_to"},
        {"alerts.emails", "alert_emails"}, {"alerts.smtp_host", "smtp_host"}, {"alerts.smtp_port", "smtp_port"},
        {"alerts.smtp_security", "smtp_security"}, {"alerts.smtp_user", "smtp_user"}, {"alerts.smtp_from", "smtp_from"},
        {"alerts.offline_minutes", "alert_offline_min"}, {"alerts.low_production", "alert_low_production"},
        {"alerts.fault", "alert_fault"},
    };
    json j = json::object();
    std::string section, line;
    std::istringstream in(*text);
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.front() == '[') { section = line.substr(1, line.find(']') - 1); continue; }
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto it = kMap.find(section + "." + trim(line.substr(0, eq)));
        if (it == kMap.end()) continue;
        try {
            j[it->second] = json::parse(trim(line.substr(eq + 1)));  // TOML string/broj/bool = JSON
        } catch (const json::exception&) {
        }
    }
    return settings_from_json(j);
}

// ---------------------------------------------------------------- obrazac
json to_form(const Settings& s) {
    json j = to_json(s, false);
    j.erase("smtp_password_enc");
    j.erase("cloud_token_enc");
    j.erase("remote_view_key_enc");
    j.erase("cloud_account_enc");
    const json account = json::parse(unprotect_secret(s.cloud_account_enc), nullptr, false);
    j["cloud_account"] = !s.cloud_token_enc.empty() && account.is_object() ? account : json(nullptr);
    j["pin_set"] = !s.settings_pin_hash.empty();
    j["smtp_password_set"] = !s.smtp_password_enc.empty();
    return j;
}

Validation validate_form(const json& form, const Settings& current, const std::vector<std::string>& interfaces) {
    Validation v;
    Settings s = current;
    auto& errors = v.errors;
    auto text = [&](const char* key) {
        auto it = form.find(key);
        return it != form.end() && it->is_string() ? trim(it->get<std::string>()) : std::string{};
    };
    auto has_iface = [&](const std::string& name) {
        for (const auto& i : interfaces) if (i == name) return true;
        return false;
    };

    // Izvor podataka: logger u lokalnoj mreži ili Solarni poslužitelj (Cloudflare tunel) – tada logger nije potreban.
    s.data_source = form.value("data_source", current.data_source) == "cloud" ? "cloud" : "local";
    const bool cloud = s.data_source == "cloud";
    if (cloud) {
        const auto url = normalize_server_url(text("cloud_url"));
        if (!url) errors["cloud_url"] = tr("Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr");
        else s.cloud_url = *url;
        if (url && *url != current.cloud_url) {  // drugi poslužitelj: stara prijava i otisak ne vrijede
            s.cloud_token_enc.clear();
            s.cloud_account_enc.clear();
            s.cloud_cert_pin.clear();
        }
        if (url && s.cloud_token_enc.empty()) errors["cloud_login"] = tr("Prijavite se na poslužitelj (e-pošta i lozinka).");
    }

    // otočni uređaji na COM/USB: logger i mrežna kartica nisu potrebni, nego port
    const bool serial_dev = !cloud && is_serial_device(form.value("device_type", current.device_type),
                                                        form.value("device_profile", current.device_profile));
    if (serial_dev) {
        std::string port;
        for (char c : form.value("serial_port", current.serial_port)) if (c != ' ') port += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        bool ok = !port.empty();
        size_t start = 0;
        for (size_t i = 0; i <= port.size() && ok; ++i) {
            if (i == port.size() || port[i] == ',') {
                const std::string one = port.substr(start, i - start);
                ok = is_serial_port_name(one) || (one == "USB" && form.value("device_type", current.device_type) == "voltronic");
                start = i + 1;
            }
        }
        if (!ok) errors["serial_port"] = tr("Izaberite serijski port (npr. COM3) ili USB.");
        s.serial_port = port;
        s.serial_baud = current.serial_baud;
        if (form.contains("serial_baud")) {
            const json& b = form["serial_baud"];
            s.serial_baud = b.is_number_integer() ? b.get<int>() : b.is_string() ? std::atoi(b.get<std::string>().c_str()) : 0;
        }
        if (s.serial_baud != 0 && s.serial_baud != 2400 && s.serial_baud != 9600 && s.serial_baud != 19200 && s.serial_baud != 115200) {
            errors["serial_baud"] = tr("Brzina: 2400, 9600, 19200 ili 115200.");
        }
    }
    s.modbus_host = text("modbus_host");
    static const std::regex kIp(R"(^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$)");
    static const std::regex kHost(R"(^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9][A-Za-z0-9-]{0,62})*$)");
    static const std::regex kDigitsDots(R"(^[\d.]+$)");
    if (serial_dev && s.modbus_host.empty()) s.modbus_host = current.modbus_host;
    if (!cloud && !serial_dev && !std::regex_match(s.modbus_host, kIp) &&
        (!std::regex_match(s.modbus_host, kHost) || std::regex_match(s.modbus_host, kDigitsDots))) {
        errors["modbus_host"] = tr("Upišite IP adresu loggera (npr. 192.168.5.199).");
    }
    if (cloud && s.modbus_host.empty()) s.modbus_host = current.modbus_host;

    s.logger_interface = text("logger_interface");
    if (cloud || serial_dev) {
        if (!s.logger_interface.empty() && !has_iface(s.logger_interface)) s.logger_interface.clear();
    } else if (s.logger_interface.empty()) {
        errors["logger_interface"] = tr("Izaberite mrežnu karticu koja vodi do loggera.");
    } else if (!has_iface(s.logger_interface)) {
        errors["logger_interface"] = tr("Ova mrežna kartica više ne postoji.");
    }
    s.internet_interface = text("internet_interface");
    if (!s.internet_interface.empty() && !has_iface(s.internet_interface)) {
        errors["internet_interface"] = tr("Ova mrežna kartica više ne postoji.");
    }

    struct Num { const char* key; bool integer; double lo, hi; };
    static const Num kNumbers[] = {
        {"modbus_port", true, 1, 65535}, {"modbus_unit_id", true, 0, 247}, {"meter_unit_id", true, 0, 247},
        {"poll_interval_s", true, 5, 3600}, {"peak_power_kwp", false, 0.1, 100000}, {"co2_factor", false, 0, 2},
        {"speedo_max_kw", true, 1, 100000}, {"weather_lat", false, -90, 90}, {"weather_lon", false, -180, 180},
        {"monitor", true, 0, 16}, {"backup_keep_days", true, 0, 365},
        {"price_kwh", false, 0, 100}, {"feedin_price_kwh", false, 0, 100}, {"remote_port", true, 1024, 65535},
        {"smtp_port", true, 1, 65535}, {"alert_offline_min", true, 0, 1440}, {"server_port", true, 1024, 65535},
    };
    json cur = to_json(current);
    json values = json::object();
    for (const auto& n : kNumbers) {
        const json raw = form.contains(n.key) ? form[n.key] : cur[n.key];
        const auto d = number(raw);
        if (!d || (n.integer && std::floor(*d) != *d)) {
            errors[n.key] = n.integer ? tr("Upišite cijeli broj.") : tr("Upišite broj.");
        } else if (*d < n.lo || *d > n.hi) {
            errors[n.key] = tr("Dopušteno od {lo} do {hi}.", {{"lo", fmt_bound(n.lo)}, {"hi", fmt_bound(n.hi)}});
        } else if (n.integer) {
            values[n.key] = static_cast<int>(*d);
        } else {
            values[n.key] = *d;
        }
    }

    struct Text { const char* key; size_t lo, hi; std::string* target; };
    const Text kTexts[] = {{"plant_name", 1, 80, &s.plant_name}, {"location", 0, 80, &s.location},
                           {"commissioned", 0, 20, &s.commissioned}, {"headline", 1, 60, &s.headline},
                           {"headline_running", 0, 60, &s.headline_running}, {"headline_idle", 0, 60, &s.headline_idle},
                           {"currency", 1, 5, &s.currency}, {"smtp_host", 0, 253, &s.smtp_host},
                           {"smtp_user", 0, 254, &s.smtp_user}, {"smtp_from", 0, 254, &s.smtp_from}};
    for (const auto& t : kTexts) {
        const std::string value = text(t.key);
        const size_t len = widen(value).size();
        if (len < t.lo || len > t.hi) errors[t.key] = value.empty() ? tr("Obavezno polje.") : tr("Najviše {n} znakova.", {{"n", std::to_string(t.hi)}});
        *t.target = value;
    }

    for (const char* key : {"start_fullscreen", "hide_idle_cursor", "keep_awake", "remote_view", "alert_low_production",
                            "alert_fault", "server_lan", "meter_export_positive", "meter_invert"}) {
        values[key] = form.contains(key) ? form[key].is_boolean() && form[key].get<bool>() : cur[key].get<bool>();
    }
    const std::string theme = form.value("theme", current.theme), scale = form.value("display_scale", current.display_scale);
    if (!one_of(theme, kThemes)) errors["theme"] = tr("Nepoznata tema.");
    if (!one_of(scale, kScales)) errors["display_scale"] = tr("Nepoznata razlučivost.");
    const std::string lang = form.value("language", current.language);
    if (!is_language(lang)) errors["language"] = tr("Nepoznat jezik.");
    const std::string device = form.value("device_type", current.device_type);
    if (!is_device_type(device)) errors["device_type"] = tr("Nepoznat uređaj.");
    std::string units;
    for (char c : form.value("inverter_units", current.inverter_units)) if (c != ' ') units += c;
    int forecast_days = current.forecast_days;
    if (form.contains("forecast_days")) {
        const json& fd = form["forecast_days"];
        forecast_days = fd.is_number_integer() ? fd.get<int>() : fd.is_string() ? std::atoi(fd.get<std::string>().c_str()) : 0;
    }
    if (forecast_days != 2 && forecast_days != 3 && forecast_days != 5) errors["forecast_days"] = tr("Izaberite 2, 3 ili 5 dana.");
    std::string city = trim(form.value("weather_city", current.weather_city));
    if (city.size() > 120) city = city.substr(0, 120);
    std::string palette = form.value("palette", current.palette);
    if (palette == "dark" || palette == "light") palette.clear();  // boje same teme
    if (!is_palette(palette)) errors["palette"] = tr("Nepoznata tema.");
    const std::string icon_theme = form.value("icon_theme", current.icon_theme);
    if (!is_icon_theme(icon_theme)) errors["icon_theme"] = tr("Nepoznata tema ikona.");
    const std::string profile = form.value("device_profile", current.device_profile);
    const std::string serial = trim(form.value("logger_serial", current.logger_serial));
    if (device == "vendor") {
        const VendorProfile* vp = find_vendor(profile);
        if (!vp) errors["device_profile"] = tr("Odaberite proizvođača i model invertera.");
        const int port = values.contains("modbus_port") && values["modbus_port"].is_number() ? values["modbus_port"].get<int>() : current.modbus_port;
        if (vp && vp->link == VendorLink::Solarman && port == 8899 && !parse_logger_serial(serial)) {
            errors["logger_serial"] = tr("Upišite serijski broj Wi-Fi loggera (10 znamenki, s naljepnice na loggeru).");
        }
    }
    if ((device == "inverter" || device == "sunspec" || device == "vendor") && !parse_units(units)) {
        errors["inverter_units"] = tr("Upišite adrese invertera odvojene zarezom, npr. 1 ili 1,2,3 (0–247, najviše 10).");
    }

    // noćni način, obavijesti e-poštom i lozinka SMTP-a (isto kao desktop/forms.py)
    s.night_mode = form.value("night_mode", current.night_mode);
    if (!one_of(s.night_mode, kNightModes)) errors["night_mode"] = tr("Nepoznat noćni način.");
    static const std::regex kTime(R"(^([01]\d|2[0-3]):[0-5]\d$)");
    for (auto [key, target] : {std::pair{"night_from", &s.night_from}, std::pair{"night_to", &s.night_to}}) {
        *target = form.contains(key) ? text(key) : *target;
        if (!std::regex_match(*target, kTime)) errors[key] = tr("Upišite vrijeme kao SS:MM, npr. 22:00.");
    }
    s.smtp_security = form.value("smtp_security", current.smtp_security);
    if (!one_of(s.smtp_security, kSmtpSecurity)) errors["smtp_security"] = tr("Nepoznata zaštita veze.");
    std::string bad;
    const auto emails = parse_recipients(form.contains("alert_emails") ? text("alert_emails") : current.alert_emails, &bad);
    if (!emails) {
        errors["alert_emails"] = bad.empty() ? tr("Najviše {n} adresa.", {{"n", std::to_string(kMaxRecipients)}})
                                             : tr("Neispravna adresa e-pošte: {address}", {{"address", bad}});
    }
    s.alert_emails.clear();
    for (const auto& e : emails.value_or(std::vector<std::string>{})) s.alert_emails += (s.alert_emails.empty() ? "" : ", ") + e;
    if (!s.alert_emails.empty() && s.smtp_host.empty()) {
        errors["smtp_host"] = tr("Obavezno polje.");
    } else if (!s.smtp_host.empty() && !valid_host_name(s.smtp_host)) {
        errors["smtp_host"] = tr("Upišite naziv ili IP adresu poslužitelja e-pošte.");
    }
    if (!s.smtp_from.empty() && !parse_recipients(s.smtp_from)) {
        errors["smtp_from"] = tr("Neispravna adresa e-pošte: {address}", {{"address", s.smtp_from}});
    }
    if (const std::string pwd = form.value("smtp_password", std::string{}); !pwd.empty()) {
        s.smtp_password_enc = protect_secret(pwd);
    } else if (s.smtp_host != current.smtp_host || s.smtp_user != current.smtp_user ||
               (values.contains("smtp_port") && values["smtp_port"] != current.smtp_port)) {  // brojevi se upisuju u s tek na kraju
        // NEW-03: spremljena lozinka ne prelazi na drugi poslužitelj ili račun (inače bi je preusmjereni poslužitelj primio)
        s.smtp_password_enc.clear();
    }
    if (s.smtp_user.empty()) s.smtp_password_enc.clear();  // bez korisničkog imena nema prijave

    const std::string new_pin = text("pin_new");
    if (form.value("pin_clear", false)) {
        s.settings_pin_hash.clear();
    } else if (!new_pin.empty()) {
        if (!std::regex_match(new_pin, std::regex(R"(^\d{4,8}$)"))) errors["pin_new"] = tr("PIN ima 4 do 8 znamenki.");
        else s.settings_pin_hash = hash_pin(new_pin);
    }

    if (!errors.empty()) return v;
    json merged = to_json(s);
    for (auto& [k, val] : values.items()) merged[k] = val;
    merged["theme"] = theme;
    merged["display_scale"] = scale;
    merged["language"] = lang;
    merged["device_type"] = device;
    merged["inverter_units"] = units.empty() ? "1" : units;
    merged["device_profile"] = profile;
    merged["palette"] = palette;
    merged["icon_theme"] = icon_theme;
    merged["forecast_days"] = forecast_days;
    merged["weather_city"] = city;
    merged["logger_serial"] = serial;
    v.settings = settings_from_json(merged);
    return v;
}

bool is_palette(const std::string& key) {
    // isti popis kao PALETTES u web/colors.js (dark i light su boje same teme, spremaju se kao "")
    static const char* kPalettes[] = {"", "ocean", "forest", "sunset", "midnight", "graphite", "contrast", "paper", "sky", "sand"};
    return std::any_of(std::begin(kPalettes), std::end(kPalettes), [&](const char* p) { return key == p; });
}

bool is_icon_theme(const std::string& key) { return key == "classic" || key == "neon" || key == "iconset"; }

bool is_device_type(const std::string& type) {
    return type == "logger" || type == "inverter" || type == "sunspec" || type == "fronius" || type == "vendor" ||
           type == "voltronic" || type == "vedirect";
}

bool is_serial_device(const std::string& type, const std::string& profile) {
    if (type == "voltronic" || type == "vedirect") return true;
    const VendorProfile* p = type == "vendor" ? find_vendor(profile) : nullptr;
    return p && p->link == VendorLink::Serial;
}

std::optional<uint32_t> parse_logger_serial(const std::string& text) {
    if (text.empty() || text.size() > 10 || !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        return std::nullopt;
    }
    const unsigned long long v = std::stoull(text);
    if (v == 0 || v > 0xFFFFFFFFull) return std::nullopt;
    return static_cast<uint32_t>(v);
}

std::optional<std::string> normalize_server_url(const std::string& url) {
    static const std::regex kUrl(R"(^(https?)://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$)");
    std::string u = trim(url);
    while (!u.empty() && u.back() == '/') u.pop_back();
    if (!std::regex_match(u, kUrl)) return std::nullopt;
    if (u.rfind("http://", 0) == 0) {
        const std::string rest = u.substr(7);
        const std::string host = rest.substr(0, rest.find_first_of(":/"));
        if (host != "127.0.0.1" && host != "localhost") u = "https://" + rest;
    }
    return u;
}

std::optional<std::vector<std::string>> parse_recipients(const std::string& text, std::string* bad) {
    static const std::regex kEmail(R"(^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$)");
    static const std::regex kSep(R"([,;\s]+)");
    std::vector<std::string> out;
    for (std::sregex_token_iterator it(text.begin(), text.end(), kSep, -1), end; it != end; ++it) {
        const std::string part = *it;
        if (part.empty()) continue;
        if (!std::regex_match(part, kEmail)) {
            if (bad) *bad = part;
            return std::nullopt;
        }
        auto lower = [](std::string v) { for (auto& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); return v; };
        bool dup = false;
        for (const auto& o : out) dup = dup || lower(o) == lower(part);
        if (!dup) out.push_back(part);
    }
    if (out.size() > kMaxRecipients) {
        if (bad) bad->clear();
        return std::nullopt;
    }
    return out;
}

std::optional<std::vector<int>> parse_units(const std::string& text) {
    static const std::regex kUnits(R"(^\s*\d{1,3}\s*(,\s*\d{1,3}\s*)*$)");
    if (!std::regex_match(text, kUnits)) return std::nullopt;
    std::vector<int> units;
    std::stringstream ss(text);
    for (std::string part; std::getline(ss, part, ',');) {
        const int u = std::stoi(trim(part));
        for (int existing : units) if (existing == u) return std::nullopt;
        if (u > 247) return std::nullopt;
        units.push_back(u);
    }
    if (units.empty() || units.size() > 10) return std::nullopt;
    return units;
}

// ---------------------------------------------------------------- PIN
std::string hash_pin(const std::string& pin, const std::vector<uint8_t>& salt_in) {
    std::vector<uint8_t> salt = salt_in;
    if (salt.empty()) {
        salt.resize(16);
        BCryptGenRandom(nullptr, salt.data(), static_cast<ULONG>(salt.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }
    return "pbkdf2$" + hex(salt) + "$" + hex(pbkdf2(pin, salt));
}

bool check_pin(const std::string& pin, const std::string& stored) {
    const auto first = stored.find('$'), second = stored.find('$', first + 1);
    if (first == std::string::npos || second == std::string::npos) return false;
    const auto salt = unhex(stored.substr(first + 1, second - first - 1));
    if (!salt) return false;
    const std::string expected = hash_pin(pin, *salt).substr(second);
    const std::string actual = stored.substr(second);
    if (expected.size() != actual.size()) return false;
    unsigned diff = 0;  // usporedba bez ranog izlaza
    for (size_t i = 0; i < expected.size(); ++i) diff |= static_cast<unsigned>(expected[i] ^ actual[i]);
    return diff == 0;
}

}  // namespace sm

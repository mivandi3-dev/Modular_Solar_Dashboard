// Postavke aplikacije (config.json) – nazivi polja isti su kao u Python verziji (solar/config.py),
// pa i obrazac postavki (web/settings.js) radi bez izmjena.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "util.hpp"

namespace sm {

using json = nlohmann::json;

struct Settings {
    // SmartLogger Modbus TCP
    // "logger" (Huawei SmartLogger) | "inverter" (Huawei SUN2000 izravno) | "sunspec" (SunSpec Modbus: SMA, Fronius,
    // SolarEdge, Kostal, FIMER…) | "fronius" (Fronius Solar API, HTTP) | "vendor" (tablica proizvođača, vendors.cpp)
    // | "voltronic" (Axpert, MPP Solar, EASUN…; QPIGS) | "vedirect" (Victron MPPT, Phoenix, SmartShunt; offgrid.cpp)
    std::string device_type = "logger";
    std::string device_profile = "sungrow_sg";  // za "vendor": ključ iz vendor_profiles()
    std::string logger_serial;                  // Solarman V5 (Deye/Sunsynk Wi-Fi logger): serijski broj, 10 znamenki
    std::string serial_port;  // otočni uređaji: "COM3", Voltronic i "USB" (HID), VE.Direct i "COM3, COM4"
    int serial_baud = 0;      // 0 = uobičajena brzina uređaja
    std::string inverter_units = "1";    // Modbus adrese invertera (Huawei SUN2000, SunSpec), npr. "1" ili "1,2,3"
    std::string modbus_host = "192.168.5.199";
    int modbus_port = 502;
    int modbus_unit_id = 0;
    int poll_interval_s = 10;
    int meter_unit_id = 1;  // Modbus adresa mjerača na loggeru (Meter 1 na COM1); 0 = bez mjerača; Fronius HTTP: 1 = Smart Meter
    bool meter_export_positive = true;  // SunSpec mjerač: pozitivna snaga = predaja u mrežu (proizvođači se razlikuju)
    bool meter_invert = false;          // "vendor": obrni predznak mjerača iz tablice proizvođača
    // mreža: nazivi kartica kako ih prikazuje Windows; "" = Windows sam bira
    std::string logger_interface;
    std::string internet_interface;
    // elektrana
    std::string plant_name = "Moja tvrtka d.o.o.";
    std::string location = "Zagreb, Hrvatska";
    double peak_power_kwp = 80.0;
    double co2_factor = 0.40;
    std::string commissioned = "11.2023.";
    // naslov u zaglavlju: prvi red i drugi red prema stanju; *tekst* je istaknut bojom
    std::string headline = "Solarna elektrana";
    std::string headline_running = "proizvodi *čistu energiju*";
    std::string headline_idle = "trenutno *miruje*";
    int speedo_max_kw = 80;
    std::string theme = "dark";
    // paleta boja (web/colors.js): "" = boje teme, inače ocean, forest, sunset… (tema je osnova palete)
    std::string palette;
    // tema ikona dashboarda (web/icons.js): "classic" = emoji, "neon" = hi-tech SVG ikone (stil ikone aplikacije),
    // "iconset" = PNG ikone iz kompleta (web/icons/iconset)
    std::string icon_theme = "classic";
    std::string language = "hr";  // hr | en | de | fr | it | tr | zh | ja | ko
    double weather_lat = 45.815;
    double weather_lon = 15.982;
    std::string weather_city = "Zagreb, Hrvatska";  // 3.1: odabran grad (koordinate iz Open-Meteo geokodiranja)
    int forecast_days = 5;                          // 3.1: prognoza u zaglavlju i widgetima: 2, 3 ili 5 dana (svaki ekran svoje)
    // prikaz i sustav
    std::string display_scale = "auto";  // auto | fhd | 2k | 4k
    int monitor = 0;
    bool start_fullscreen = true;
    bool hide_idle_cursor = true;
    bool keep_awake = true;
    std::string settings_pin_hash;
    int backup_keep_days = 14;
    // ušteda: cijena struje iz mreže i otkupna cijena viška predanog u mrežu
    double price_kwh = 0.15;
    double feedin_price_kwh = 0.05;
    std::string currency = "€";
    // noćni način: od-do (preko ponoći) prikaz se zatamni ili se zaslon ugasi
    std::string night_mode = "off";  // off | dim | screen_off
    std::string night_from = "22:00";
    std::string night_to = "06:00";
    // pregled dashboarda iz lokalne mreže (preglednik na drugom računalu ili mobitelu)
    bool remote_view = false;
    int remote_port = 8600;
    std::string remote_view_key_enc;  // 4.0 (SMA-08): pristupni ključ pregleda iz mreže (DPAPI)
    // obavijesti e-poštom (šalje ih poller): adrese odvojene zarezom
    std::string alert_emails;
    std::string smtp_host;
    int smtp_port = 587;
    std::string smtp_security = "starttls";  // starttls | ssl | none
    std::string smtp_user;
    std::string smtp_password_enc;  // DPAPI (src/secret.cpp), nikad u čistom tekstu
    std::string smtp_from;
    int alert_offline_min = 30;  // 0 = bez obavijesti
    bool alert_low_production = true;
    bool alert_fault = true;
    // izvor podataka klijenta: "local" = logger u lokalnoj mreži, "cloud" = Solarni poslužitelj (Cloudflare tunel)
    std::string data_source = "local";
    std::string cloud_url;          // npr. https://solar.tvrtka.hr ili https://192.168.1.20:8700
    std::string cloud_token_enc;    // 3.0: oznaka prijave korisnika (DPAPI) – lozinka se nikad ne sprema
    std::string cloud_account_enc;  // 3.0: {"email","name","role"} prijavljenog korisnika (DPAPI)
    std::string cloud_cert_pin;     // 3.0: otisak certifikata poslužitelja u lokalnoj mreži (zapamćen pri prvoj prijavi)
    // Solarni poslužitelj (SolarniServer.exe): port API-ja; server_lan=false → samo 127.0.0.1 (cloudflared)
    int server_port = 8700;
    bool server_lan = false;
    // 4.0 (B1): API prima Rust gateway (solari-gateway.exe) preko kanala; false = rezervni put A (C++ HTTPS listener)
    bool server_gateway = true;

    bool operator==(const Settings&) const = default;
};

json to_json(const Settings& s, bool include_pin_hash = true);
Settings settings_from_json(const json& j);  // nepoznata/neispravna polja → zadane vrijednosti

bool is_configured();
bool valid_host_name(const std::string& host);  // IPv4 ili naziv (bez razmaka, kontrolnih znakova, ':', '/')
Settings load_settings();  // config.json + secrets\secrets.json (ako je čitljiva)
// atomično; tajne (secret_keys) idu u secrets\secrets.json, config.json i config.json.bak su bez njih
void save_settings(const Settings& s);
const std::vector<std::string>& secret_keys();  // smtp_password_enc, cloud_*_enc, remote_view_key_enc, settings_pin_hash
fs::path secrets_file();
json strip_secrets(json j);
// samo secrets.json (npr. PIN iz instalacije – config.json se ne stvara, pa čarobnjak ostaje)
void save_secret_field(const std::string& key, const std::string& value);
bool config_has_secrets();  // config.json iz 3.x/4.0.0 još sadrži tajne (prijenos u secrets.json)

// Postavke Python verzije (instalirane ili iz C:\solari\.streamlit\secrets.toml) za predispunjavanje čarobnjaka.
std::optional<Settings> legacy_settings();

// ---------------------------------------------------------------- obrazac postavki
json to_form(const Settings& s);  // bez hasha PIN-a, uz "pin_set"
struct Validation {
    std::optional<Settings> settings;
    std::map<std::string, std::string> errors;  // polje → poruka
};
Validation validate_form(const json& form, const Settings& current, const std::vector<std::string>& interfaces);

// "1, 2,3" → {1, 2, 3}; std::nullopt ako zapis nije ispravan (0–247, najviše 10, bez ponavljanja)
std::optional<std::vector<int>> parse_units(const std::string& text);
bool is_device_type(const std::string& type);
bool is_serial_device(const std::string& device_type, const std::string& profile);  // COM/USB umjesto mreže  // logger | inverter | sunspec | fronius | vendor
bool is_palette(const std::string& key);
bool is_icon_theme(const std::string& key);  // classic | neon | iconset  // "" ili paleta iz web/colors.js
std::optional<uint32_t> parse_logger_serial(const std::string& text);  // 1–4294967295, samo znamenke

// Adrese e-pošte odvojene zarezom, točka-zarezom ili novim redom (bez ponavljanja, najviše 20).
// nullopt i `bad` = prva neispravna adresa ("" ako ih je previše).
std::optional<std::vector<std::string>> parse_recipients(const std::string& text, std::string* bad = nullptr);
inline constexpr size_t kMaxRecipients = 20;

// "https://solar.tvrtka.hr/" → "https://solar.tvrtka.hr"; nullopt ako adresa nije http(s) adresa poslužitelja
// https://… ili http://… ; http na adresu koja nije 127.0.0.1/localhost postaje https (3.0: poslužitelj u mreži je samo HTTPS)
std::optional<std::string> normalize_server_url(const std::string& url);

// ---------------------------------------------------------------- PIN
std::string hash_pin(const std::string& pin, const std::vector<uint8_t>& salt = {});
bool check_pin(const std::string& pin, const std::string& stored);

}  // namespace sm

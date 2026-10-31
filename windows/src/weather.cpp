#include "weather.hpp"

#include <cctype>

#include <cstdio>
#include <map>

#include "i18n.hpp"

#include "net.hpp"
#include "system.hpp"
#include "util.hpp"

namespace sm {

namespace {
constexpr int kTtlS = 15 * 60;  // Open-Meteo osvježava trenutne podatke svakih 15 min
constexpr int kRetryS = 60;     // nakon greške ne pokušavaj odmah ponovno
constexpr unsigned kTimeoutMs = 15'000;
}  // namespace

std::string weather_label(int code) {
    static const std::map<int, const char*> kWmo = {
        {0, "Vedro"}, {1, "Pretežno vedro"}, {2, "Djelomično oblačno"}, {3, "Oblačno"}, {45, "Magla"}, {48, "Magla s injem"},
        {51, "Slaba rosulja"}, {53, "Rosulja"}, {55, "Jaka rosulja"}, {56, "Ledena rosulja"}, {57, "Ledena rosulja"},
        {61, "Slaba kiša"}, {63, "Kiša"}, {65, "Jaka kiša"}, {66, "Ledena kiša"}, {67, "Ledena kiša"}, {71, "Slab snijeg"},
        {73, "Snijeg"}, {75, "Jak snijeg"}, {77, "Zrnati snijeg"}, {80, "Pljuskovi"}, {81, "Pljuskovi"}, {82, "Jaki pljuskovi"},
        {85, "Snježni pljuskovi"}, {86, "Snježni pljuskovi"}, {95, "Grmljavina"}, {96, "Grmljavina s tučom"},
        {99, "Grmljavina s tučom"}};
    const auto it = kWmo.find(code);
    return it == kWmo.end() ? "—" : it->second;
}

json parse_forecast(const json& raw) {
    const json& cur = raw.at("current");
    const json& d = raw.at("daily");
    json days = json::array();
    for (size_t i = 0; i < d.at("time").size(); ++i) {
        auto at = [&](const char* key) { return d.contains(key) && i < d[key].size() ? d[key][i] : json(nullptr); };
        days.push_back({{"date", at("time")}, {"code", at("weather_code")}, {"tmax", at("temperature_2m_max")},
                        {"tmin", at("temperature_2m_min")}, {"sunrise", at("sunrise")}, {"sunset", at("sunset")},
                        {"radiation_mj", at("shortwave_radiation_sum")}, {"uv", at("uv_index_max")},
                        {"sunshine_h", at("sunshine_duration").is_number() ? json(at("sunshine_duration").get<double>() / 3600) : json(0)},
                        {"rain_pct", at("precipitation_probability_max")}});
    }
    // prosjek zračenja (W/m²) u satu koji ZAVRŠAVA u navedeno lokalno vrijeme: [["2026-10-29T10:00", 312], ...]
    json hourly = json::array();
    if (raw.contains("hourly") && raw["hourly"].contains("time") && raw["hourly"].contains("shortwave_radiation")) {
        const json& h = raw["hourly"];
        for (size_t i = 0; i < h["time"].size() && i < h["shortwave_radiation"].size(); ++i) {
            const json& rad = h["shortwave_radiation"][i];
            hourly.push_back({h["time"][i], rad.is_number() ? rad.get<double>() : 0.0});
        }
    }
    return {{"temperature", cur.at("temperature_2m")}, {"code", cur.at("weather_code")},
            {"is_day", cur.value("is_day", 1)}, {"wind_kmh", cur.at("wind_speed_10m")},
            {"radiation_wm2", cur.at("shortwave_radiation")}, {"days", days}, {"hourly", hourly}};
}

json WeatherService::fetch(double lat, double lon, const std::string& source_ip) {
    char url[640];
    std::snprintf(url, sizeof url,
                  "https://api.open-meteo.com/v1/forecast?latitude=%.4f&longitude=%.4f"
                  "&current=temperature_2m,weather_code,wind_speed_10m,shortwave_radiation,is_day"
                  "&daily=weather_code,temperature_2m_max,temperature_2m_min,sunrise,sunset,shortwave_radiation_sum,"
                  "uv_index_max,sunshine_duration,precipitation_probability_max&hourly=shortwave_radiation"
                  "&timezone=auto&forecast_days=6",
                  lat, lon);
    std::wstring cmd = curl_command() + L" --silent --show-error --fail --max-time 12 ";
    if (!source_ip.empty()) cmd += L"--interface " + widen(source_ip) + L" ";
    cmd += L"\"" + widen(url) + L"\"";
    const ProcessResult r = run_capture(cmd, kTimeoutMs);
    if (r.exit_code != 0) {
        throw std::runtime_error(r.exit_code < 0 ? tr("curl.exe nije dostupan ili nije odgovorio") : trim(r.output));
    }
    try {
        return parse_forecast(json::parse(r.output));
    } catch (const json::exception&) {
        throw std::runtime_error(tr("Neočekivan odgovor poslužitelja prognoze"));
    }
}

json WeatherService::get(const Settings& s) {
    std::lock_guard lock(mutex_);
    const std::string key = std::to_string(s.weather_lat) + "," + std::to_string(s.weather_lon) + "," + s.internet_interface;
    const std::time_t t = now();
    const bool fresh = key == key_ && t - fetched_at_ < (last_.is_null() ? kRetryS : kTtlS);
    if (fresh) return last_;
    fetched_at_ = t;
    try {
        const auto ip = source_ip(s.internet_interface);
        last_ = fetch(s.weather_lat, s.weather_lon, ip.value_or(""));
        key_ = key;
    } catch (const std::exception& e) {
        log_warn(std::string("Prognoza: ") + e.what());
        if (key != key_) last_ = nullptr;  // promijenjena lokacija – stara prognoza ne vrijedi
        key_ = key;
    }
    return last_;
}

json parse_geocoding(const json& raw) {
    json out = json::array();
    if (!raw.contains("results") || !raw["results"].is_array()) return out;
    for (const auto& r : raw["results"]) {
        if (!r.contains("latitude") || !r.contains("longitude") || !r["latitude"].is_number() || !r["longitude"].is_number()) continue;
        std::string label = r.value("name", "");
        for (const char* k : {"admin1", "country"}) {
            const std::string part = r.value(k, "");
            if (!part.empty() && part != label) label += ", " + part;
        }
        out.push_back({{"label", label}, {"name", r.value("name", "")}, {"lat", r["latitude"].get<double>()}, {"lon", r["longitude"].get<double>()}});
    }
    return out;
}

json WeatherService::geocode(const std::string& name, const std::string& language, const std::string& source_ip) {
    // ime ide u adresu potpuno kodirano (%XX) – u naredbenom retku nema navodnika ni razmaka iz unosa
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string q;
    for (unsigned char c : trim(name).substr(0, 100)) {
        if (std::isalnum(c) && c < 0x80) q += static_cast<char>(c);
        else { q += '%'; q += kHex[c >> 4]; q += kHex[c & 15]; }
    }
    if (q.empty()) return json::array();
    std::string lang;
    for (char c : language) if (std::isalpha(static_cast<unsigned char>(c))) lang += c;
    const std::string url = "https://geocoding-api.open-meteo.com/v1/search?name=" + q + "&count=8&format=json&language=" +
                            (lang.empty() ? "en" : lang.substr(0, 5));
    std::wstring cmd = curl_command() + L" --silent --show-error --fail --max-time 12 ";
    if (!source_ip.empty()) cmd += L"--interface " + widen(source_ip) + L" ";
    cmd += L"\"" + widen(url) + L"\"";
    const ProcessResult r = run_capture(cmd, kTimeoutMs);
    if (r.exit_code != 0) throw std::runtime_error(r.exit_code < 0 ? tr("curl.exe nije dostupan ili nije odgovorio") : trim(r.output));
    try {
        return parse_geocoding(json::parse(r.output));
    } catch (const json::exception&) {
        throw std::runtime_error(tr("Neočekivan odgovor poslužitelja prognoze"));
    }
}

}  // namespace sm

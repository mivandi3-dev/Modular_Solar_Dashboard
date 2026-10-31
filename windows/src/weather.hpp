// Vremenska prognoza s Open-Meteo (bez API ključa). HTTPS preko curl.exe (iz instalacije ili Windowsa),
// jer on podržava --interface – promet ide kroz izabranu karticu prema internetu.
#pragma once

#include <mutex>

#include "config.hpp"

namespace sm {

class WeatherService {
public:
    // Prognoza (keš 15 min); ako dohvat zakaže, vraća zadnju uspješnu ili null.
    json get(const Settings& s);
    // Bez keša, s porukom greške (provjera veze u postavkama). Baca std::runtime_error.
    static json fetch(double lat, double lon, const std::string& source_ip);
    // 3.1: grad → mjesta s koordinatama (Open-Meteo geokodiranje, najviše 8). Baca std::runtime_error.
    static json geocode(const std::string& name, const std::string& language, const std::string& source_ip);

private:
    std::mutex mutex_;
    json last_;
    std::time_t fetched_at_ = 0;
    std::string key_;
};

json parse_forecast(const json& raw);    // Open-Meteo odgovor → oblik koji koristi web/dashboard.js
json parse_geocoding(const json& raw);   // [{"label","name","lat","lon"}] – "Zagreb, Grad Zagreb, Hrvatska"
std::string weather_label(int wmo_code);  // hrvatski naziv vremenskih uvjeta (ključ za prijevod)

}  // namespace sm

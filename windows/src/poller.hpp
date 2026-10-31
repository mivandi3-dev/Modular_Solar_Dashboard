// Očitavanje SmartLoggera → SQLite. Radi kao nit u aplikaciji ili samostalno (SolarniMonitor.exe --poller,
// zadatak sustava iz instalacije). Global\ mutex jamči samo jedan poller na računalu.
#pragma once

#include <atomic>
#include <thread>

#include "config.hpp"
#include "storage.hpp"

namespace sm {

inline constexpr wchar_t kPollerMutex[] = L"Global\\SolarniMonitor2Poller";
inline constexpr wchar_t kServerPollerMutex[] = L"Global\\SolarniServerPoller";
// Solarni poslužitelj ima svoj poller (svoja mapa i baza) – može raditi na istom računalu kao klijent.
void set_poller_mutex(const wchar_t* name);

// Očitanje elektrane: SmartLogger ili izravno SUN2000 inverter(i); snaga s mjerača (iz mreže, kW)
struct PlantReading {
    Reading reading;  // e_daily_kwh < 0: uređaj ne daje dnevnu energiju (SunSpec, Fronius GEN24) – računa je poll_once
    std::optional<double> load_kw;
    std::string meter_error;
    std::string device_name;  // npr. "Fronius Symo 10.0-3-M" (za provjeru veze), "" = nepoznato
    // podaci uređaja za widgete: battery_soc (%), battery_kw (+ punjenje), battery_dir (je li smjer poznat),
    // inverter_temp (°C), grid_v (V), grid_hz (Hz) – samo ono što uređaj daje
    json extra = json::object();
};

// Što uređaj daje osim snage i energije: "battery", "temperature", "grid" (widgeti se nude samo za njih).
std::vector<std::string> device_capabilities(const Settings& s);
PlantReading read_plant(const Settings& s);  // baca std::exception s porukom

// Dnevna energija iz ukupne, za uređaje koji je ne daju: ukupno sada − ukupno na početku dana (zadnje očitanje
// prije ponoći, a ako ga nema – prvo današnje). Prvo očitanje dana zato daje 0.
double daily_from_total(Db& db, std::time_t t, double e_total_kwh);
// Ukupna energija iz snage, za uređaje bez brojila energije (Victron GX): zadnje ukupno + prosjek snage × vrijeme
// (trapez). Nakon prekida duljeg od 15 minuta ne dodaje se ništa; prvo očitanje počinje od 0.
double integrate_total(Db& db, std::time_t t, double power_kw);

// Jedno očitanje i upis; greške se zapisuju u log i vraća se false.
bool poll_once(const Settings& s, Db& db);

class Poller {
public:
    ~Poller() { stop(); }
    void start();  // u pozadinskoj niti; ako poller već radi drugdje, povremeno provjerava
    void stop();
    bool active() const { return active_; }  // ova instanca drži mutex i bilježi

private:
    void run();
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> active_{false};
};

int run_poller_mode();  // --poller: radi dok se proces ne zaustavi

}  // namespace sm

// SQLite povijest očitanja – ista shema i format vremena kao Python verzija (solar/storage.py),
// pa se baze mogu međusobno uvoziti. WAL omogućuje istovremeno čitanje (sučelje) i pisanje (poller).
#pragma once

#include <ctime>
#include <optional>
#include <utility>
#include <vector>

#include "config.hpp"
#include "modbus.hpp"
#include "util.hpp"

struct sqlite3;

namespace sm {

struct LatestReading {
    std::time_t ts = 0;
    double power_kw = 0, e_daily_kwh = 0, e_total_kwh = 0;
    std::optional<double> pf, load_kw;
    int status = 0;
    json extra = json::object();  // podaci uređaja: battery_soc, battery_kw, inverter_temp, grid_v, grid_hz
};

struct HourAggregate {
    std::time_t hour = 0;  // početak UTC sata
    int n_total = 0;
    std::optional<double> e_daily_max, e_total_min, e_total_max, power_max;
    // mjerač potrošnje: prosjek snage u satu = energija sata (kWh); vidi solar/energy.py
    int n_load = 0;
    std::optional<double> load_avg, export_avg, import_avg;
};

// 4.0 (SMA-02): jedan redak povijesti za uvoz preko brokera (sučelje čita izvor, broker upisuje)
struct HistoryRow {
    std::string ts_utc;  // "YYYY-MM-DD HH:MM:SS"
    std::optional<double> power_kw, e_daily_kwh, e_total_kwh, pf, load_kw;
    std::optional<int64_t> status;
};
// Retci iz druge baze Solarnog monitora (samo čitanje), po ts_utc, od `after` (isključivo); najviše `limit`.
// Baca ako datoteka nije baza s tablicom readings.
std::vector<HistoryRow> read_history_rows(const fs::path& source, const std::string& after, int limit);
// Provjera retka prije upisa (broker): vrijeme, konačni brojevi u razumnim rasponima
bool valid_history_row(const HistoryRow& r);

class Db {
public:
    // read_only: sučelje u produkciji (mapa data\ je za Users samo za čitanje); baza mora postojati.
    explicit Db(const fs::path& path, bool read_only = false);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    void insert(std::time_t ts, const Reading& r, std::optional<double> load_kw, const json& extra = json::object());
    // Uvezena povijest (izvoz SmartLoggera): samo E-daily, bez snage stanja i ukupne energije; postojeće ostaje.
    void insert_day_yield(std::time_t ts, double kwh);
    // Ukupna energija na početku dana: zadnje očitanje unatrag 7 dana prije `day_start`, inače prvo od `day_start`.
    std::optional<double> day_start_total(std::time_t day_start);
    std::optional<LatestReading> latest();
    std::vector<HourAggregate> hourly_aggregates(std::time_t start, std::time_t end);
    // Prosjek snage elektrane i mjerača (iz mreže) po intervalima od `seconds` sekundi.
    struct Bucket {
        std::time_t t = 0;
        double power_kw = 0;
        std::optional<double> load_kw;
    };
    std::vector<Bucket> power_buckets(std::time_t start, std::time_t end, int seconds);
    int count_between(std::time_t start, std::time_t end);
    std::optional<std::pair<std::time_t, double>> peak_power();
    std::optional<std::pair<std::time_t, double>> peak_power_between(std::time_t start, std::time_t end);
    std::optional<std::time_t> first_timestamp();
    int64_t total_readings();

    int64_t import_history(const fs::path& source);  // vraća broj novih očitanja
    int64_t insert_history_rows(const std::vector<HistoryRow>& rows);  // INSERT OR IGNORE; vraća broj novih
    void backup_to(const fs::path& target);

private:
    sqlite3* db_ = nullptr;
    fs::path path_;
};

// Kopija za danas (ako je nema) i brisanje kopija starijih od keep_days. Vraća putanju nove kopije.
std::optional<fs::path> daily_backup(const fs::path& db, const fs::path& dir, int keep_days, Date today);

}  // namespace sm

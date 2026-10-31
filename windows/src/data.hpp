// Podaci za dashboard (isto kao solar/data_service.py): stanje uživo, krivulja dana, dnevni,
// mjesečni i godišnji iznosi te rekordi. Sve se računa iz satnih agregata u SQL-u.
#pragma once

#include <mutex>
#include <optional>
#include <vector>

#include "config.hpp"
#include "storage.hpp"

namespace sm {

inline constexpr int kStaleAfterS = 10 * 60;  // starije zadnje očitanje → "logger nedostupan"
inline constexpr int kEDailyFromHour = 1;      // E-daily prije 01:00 može još nositi jučerašnji iznos
inline constexpr int kCurveBucketS = 300;      // krivulja dana: prosjek po 5 minuta
inline constexpr int kMaxBarDays = 31;

struct DayKwh {
    Date date;
    double kwh = 0;
    // s mjerača potrošnje (nullopt = taj dan mjerač nije ništa izmjerio)
    std::optional<double> load, import, exported;
};

// Ušteda za proizvedenu energiju: vlastita potrošnja po cijeni iz mreže, višak po otkupnoj cijeni.
double savings(const Settings& s, double produced_kwh, std::optional<double> export_kwh);

// Proizvodnja po lokalnim danima iz satnih agregata (jedna funkcija – testira se zasebno).
std::vector<DayKwh> days_from_aggregates(const std::vector<HourAggregate>& hours, Date start, Date end);

class DataService {
public:
    explicit DataService(fs::path db_path) : db_path_(std::move(db_path)) {}

    // Sve što dashboardu treba u jednom JSON-u (web/dashboard.js).
    json dashboard(const Settings& s);

    std::vector<DayKwh> daily(Date start, Date end);
    std::optional<std::pair<std::time_t, double>> peak_between(std::time_t start, std::time_t end);
    json db_info();

private:
    json realtime(Db& db, const Settings& s, const std::vector<DayKwh>& month);
    json records(Db& db);
    json savings_json(const Settings& s, const std::vector<DayKwh>& recent);
    std::vector<DayKwh> daily(Db& db, Date start, Date end);

    fs::path db_path_;
    std::mutex mutex_;
    json records_cache_;
    std::time_t records_at_ = 0;
    std::vector<DayKwh> all_days_;  // od prvog očitanja (osvježava se s rekordima) – ukupna ušteda
};

}  // namespace sm

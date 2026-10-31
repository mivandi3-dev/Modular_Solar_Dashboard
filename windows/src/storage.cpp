#include "storage.hpp"

#include <sqlite3.h>

#include <stdexcept>

#include "i18n.hpp"

namespace sm {

namespace {

constexpr const char* kSchema =
    "CREATE TABLE IF NOT EXISTS readings (ts_utc TEXT PRIMARY KEY, power_kw REAL, e_daily_kwh REAL,"
    " e_total_kwh REAL, pf REAL, status INTEGER, load_kw REAL)";

// RAII za pripremljeni upit
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &st_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("SQLite: ") + sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(st_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& bind(int i, const std::string& v) { sqlite3_bind_text(st_, i, v.c_str(), -1, SQLITE_TRANSIENT); return *this; }
    Stmt& bind(int i, double v) { sqlite3_bind_double(st_, i, v); return *this; }
    Stmt& bind(int i, int64_t v) { sqlite3_bind_int64(st_, i, v); return *this; }
    Stmt& bind(int i, std::optional<double> v) {
        v ? sqlite3_bind_double(st_, i, *v) : sqlite3_bind_null(st_, i);
        return *this;
    }
    bool step() {
        const int rc = sqlite3_step(st_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw std::runtime_error(std::string("SQLite: ") + sqlite3_errmsg(sqlite3_db_handle(st_)));
    }
    std::optional<double> opt(int col) {
        return sqlite3_column_type(st_, col) == SQLITE_NULL ? std::nullopt : std::optional(sqlite3_column_double(st_, col));
    }
    double num(int col) { return sqlite3_column_double(st_, col); }
    int64_t i64(int col) { return sqlite3_column_int64(st_, col); }
    std::string text(int col) {
        const auto* t = sqlite3_column_text(st_, col);
        return t ? reinterpret_cast<const char*>(t) : "";
    }

private:
    sqlite3_stmt* st_ = nullptr;
};

void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "?";
        sqlite3_free(err);
        throw std::runtime_error("SQLite: " + msg);
    }
}

}  // namespace

Db::Db(const fs::path& path) : path_(path) {
    fs::create_directories(path.parent_path());
    if (sqlite3_open(narrow(path.wstring()).c_str(), &db_) != SQLITE_OK) {
        std::string msg = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        throw std::runtime_error("Baza se ne može otvoriti: " + msg);
    }
    sqlite3_busy_timeout(db_, 10'000);
    exec(db_, "PRAGMA journal_mode=WAL");
    exec(db_, kSchema);
    // stupac extra (JSON s podacima uređaja) – starije baze ga nemaju
    Stmt has_extra(db_, "SELECT COUNT(*) FROM pragma_table_info('readings') WHERE name = 'extra'");
    has_extra.step();
    if (has_extra.i64(0) == 0) exec(db_, "ALTER TABLE readings ADD COLUMN extra TEXT");
}

Db::~Db() { sqlite3_close(db_); }

void Db::insert(std::time_t ts, const Reading& r, std::optional<double> load_kw, const json& extra) {
    Stmt st(db_, "INSERT OR REPLACE INTO readings (ts_utc, power_kw, e_daily_kwh, e_total_kwh, pf, status, load_kw, extra)"
                 " VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    st.bind(8, extra.is_object() && !extra.empty() ? extra.dump() : std::string());
    st.bind(1, utc_text(ts)).bind(2, r.power_kw).bind(3, r.e_daily_kwh).bind(4, r.e_total_kwh).bind(5, r.pf)
        .bind(6, int64_t{r.status}).bind(7, load_kw);
    st.step();
}

void Db::insert_day_yield(std::time_t ts, double kwh) {
    Stmt st(db_, "INSERT OR IGNORE INTO readings (ts_utc, power_kw, e_daily_kwh) VALUES (?, 0, ?)");
    st.bind(1, utc_text(ts)).bind(2, kwh);
    st.step();
}

std::optional<double> Db::day_start_total(std::time_t day_start) {
    Stmt before(db_, "SELECT e_total_kwh FROM readings WHERE ts_utc < ? AND ts_utc >= ? AND e_total_kwh > 0"
                     " ORDER BY ts_utc DESC LIMIT 1");
    before.bind(1, utc_text(day_start)).bind(2, utc_text(day_start - 7 * 86400));
    if (before.step()) return before.opt(0);
    Stmt first(db_, "SELECT e_total_kwh FROM readings WHERE ts_utc >= ? AND e_total_kwh > 0 ORDER BY ts_utc LIMIT 1");
    first.bind(1, utc_text(day_start));
    if (first.step()) return first.opt(0);
    return std::nullopt;
}

std::optional<LatestReading> Db::latest() {
    // uvezena povijest (samo E-daily, bez ukupne energije) nije stvarno očitanje uređaja
    Stmt st(db_, "SELECT ts_utc, power_kw, e_daily_kwh, e_total_kwh, pf, status, load_kw, extra FROM readings"
                 " WHERE e_total_kwh IS NOT NULL ORDER BY ts_utc DESC LIMIT 1");
    if (!st.step()) return std::nullopt;
    LatestReading r;
    r.ts = parse_utc_text(st.text(0)).value_or(0);
    r.power_kw = st.opt(1).value_or(0);
    r.e_daily_kwh = st.opt(2).value_or(0);
    r.e_total_kwh = st.opt(3).value_or(0);
    r.pf = st.opt(4);
    r.status = static_cast<int>(st.i64(5));
    r.load_kw = st.opt(6);
    if (const std::string extra = st.text(7); !extra.empty()) {
        r.extra = json::parse(extra, nullptr, false);
        if (!r.extra.is_object()) r.extra = json::object();
    }
    return r;
}

std::vector<HourAggregate> Db::hourly_aggregates(std::time_t start, std::time_t end) {
    Stmt st(db_, "SELECT substr(ts_utc, 1, 13), COUNT(e_total_kwh), MAX(e_daily_kwh), MIN(e_total_kwh),"
                 " MAX(e_total_kwh), MAX(power_kw), COUNT(load_kw), AVG(load_kw),"
                 " AVG(MAX(COALESCE(power_kw, 0) - load_kw, 0)), AVG(MAX(load_kw - COALESCE(power_kw, 0), 0))"
                 " FROM readings WHERE ts_utc >= ? AND ts_utc < ? GROUP BY 1 ORDER BY 1");
    st.bind(1, utc_text(start)).bind(2, utc_text(end));
    std::vector<HourAggregate> out;
    while (st.step()) {
        HourAggregate h;
        h.hour = parse_utc_text(st.text(0) + ":00:00").value_or(0);
        h.n_total = static_cast<int>(st.i64(1));
        h.e_daily_max = st.opt(2);
        h.e_total_min = st.opt(3);
        h.e_total_max = st.opt(4);
        h.power_max = st.opt(5);
        h.n_load = static_cast<int>(st.i64(6));
        h.load_avg = st.opt(7);
        h.export_avg = st.opt(8);
        h.import_avg = st.opt(9);
        out.push_back(h);
    }
    return out;
}

std::vector<Db::Bucket> Db::power_buckets(std::time_t start, std::time_t end, int seconds) {
    Stmt st(db_, "SELECT (CAST(strftime('%s', ts_utc) AS INTEGER) / ?) * ?, AVG(power_kw), AVG(load_kw) FROM readings"
                 " WHERE ts_utc >= ? AND ts_utc < ? AND power_kw IS NOT NULL GROUP BY 1 ORDER BY 1");
    st.bind(1, int64_t{seconds}).bind(2, int64_t{seconds}).bind(3, utc_text(start)).bind(4, utc_text(end));
    std::vector<Bucket> out;
    while (st.step()) out.push_back({static_cast<std::time_t>(st.i64(0)), st.num(1), st.opt(2)});
    return out;
}

int Db::count_between(std::time_t start, std::time_t end) {
    Stmt st(db_, "SELECT COUNT(*) FROM readings WHERE ts_utc >= ? AND ts_utc < ?");
    st.bind(1, utc_text(start)).bind(2, utc_text(end));
    st.step();
    return static_cast<int>(st.i64(0));
}

std::optional<std::pair<std::time_t, double>> Db::peak_power() {
    Stmt st(db_, "SELECT ts_utc, power_kw FROM readings WHERE power_kw IS NOT NULL ORDER BY power_kw DESC LIMIT 1");
    if (!st.step()) return std::nullopt;
    return std::pair(parse_utc_text(st.text(0)).value_or(0), st.num(1));
}

std::optional<std::pair<std::time_t, double>> Db::peak_power_between(std::time_t start, std::time_t end) {
    Stmt st(db_, "SELECT ts_utc, power_kw FROM readings WHERE ts_utc >= ? AND ts_utc < ? AND power_kw IS NOT NULL"
                 " ORDER BY power_kw DESC LIMIT 1");
    st.bind(1, utc_text(start)).bind(2, utc_text(end));
    if (!st.step()) return std::nullopt;
    return std::pair(parse_utc_text(st.text(0)).value_or(0), st.num(1));
}

std::optional<std::time_t> Db::first_timestamp() {
    Stmt st(db_, "SELECT MIN(ts_utc) FROM readings");
    if (!st.step() || st.text(0).empty()) return std::nullopt;
    return parse_utc_text(st.text(0));
}

int64_t Db::total_readings() {
    Stmt st(db_, "SELECT COUNT(*) FROM readings");
    st.step();
    return st.i64(0);
}

int64_t Db::import_history(const fs::path& source) {
    std::error_code ec;
    if (fs::equivalent(source, path_, ec)) throw std::runtime_error(tr("Odabrana je ista baza koju aplikacija već koristi."));
    const int64_t before = total_readings();
    Stmt attach(db_, "ATTACH DATABASE ? AS src");
    attach.bind(1, narrow(source.wstring()));
    attach.step();
    try {
        Stmt check(db_, "SELECT COUNT(*) FROM src.sqlite_master WHERE type='table' AND name='readings'");
        check.step();
        if (check.i64(0) == 0) throw std::runtime_error(tr("Odabrana datoteka nije baza Solarnog monitora (nema tablice readings)."));
        // load_kw postoji tek u novijim bazama
        Stmt has_load(db_, "SELECT COUNT(*) FROM pragma_table_info('readings', 'src') WHERE name = 'load_kw'");
        has_load.step();
        exec(db_, has_load.i64(0)
                      ? "INSERT OR IGNORE INTO readings (ts_utc, power_kw, e_daily_kwh, e_total_kwh, pf, status, load_kw)"
                        " SELECT ts_utc, power_kw, e_daily_kwh, e_total_kwh, pf, status, load_kw FROM src.readings"
                      : "INSERT OR IGNORE INTO readings (ts_utc, power_kw, e_daily_kwh, e_total_kwh, pf, status)"
                        " SELECT ts_utc, power_kw, e_daily_kwh, e_total_kwh, pf, status FROM src.readings");
    } catch (...) {
        sqlite3_exec(db_, "DETACH DATABASE src", nullptr, nullptr, nullptr);
        throw;
    }
    exec(db_, "DETACH DATABASE src");
    return total_readings() - before;
}

void Db::backup_to(const fs::path& target) {
    sqlite3* dst = nullptr;
    if (sqlite3_open(narrow(target.wstring()).c_str(), &dst) != SQLITE_OK) {
        sqlite3_close(dst);
        throw std::runtime_error("Kopija baze se ne može stvoriti.");
    }
    sqlite3_backup* b = sqlite3_backup_init(dst, "main", db_, "main");
    if (b) {
        sqlite3_backup_step(b, -1);  // dosljedna kopija i dok poller piše
        sqlite3_backup_finish(b);
    }
    const int rc = sqlite3_errcode(dst);
    sqlite3_close(dst);
    if (rc != SQLITE_OK) throw std::runtime_error("Kopija baze nije uspjela.");
}

std::optional<fs::path> daily_backup(const fs::path& db, const fs::path& dir, int keep_days, Date today) {
    if (keep_days <= 0 || !fs::exists(db)) return std::nullopt;
    fs::create_directories(dir);
    const fs::path target = dir / widen("solar_" + iso_date(today) + ".db");
    std::optional<fs::path> created;
    if (!fs::exists(target)) {
        fs::path tmp = target;
        tmp += L".tmp";
        Db(db).backup_to(tmp);
        fs::rename(tmp, target);
        created = target;
    }
    const Date cutoff = add_days(today, -keep_days);
    for (const auto& entry : fs::directory_iterator(dir)) {
        const std::string name = narrow(entry.path().filename().wstring());
        if (name.size() != 19 || name.rfind("solar_", 0) != 0 || entry.path().extension() != L".db") continue;
        const int y = std::stoi(name.substr(6, 4)), m = std::stoi(name.substr(11, 2)), d = std::stoi(name.substr(14, 2));
        const Date date{std::chrono::year{y}, std::chrono::month{static_cast<unsigned>(m)}, std::chrono::day{static_cast<unsigned>(d)}};
        if (date.ok() && date < cutoff) fs::remove(entry.path());
    }
    return created;
}

}  // namespace sm

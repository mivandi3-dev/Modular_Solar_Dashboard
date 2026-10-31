#include "data.hpp"

#include <algorithm>
#include <map>

namespace sm {

namespace {
constexpr int kRecordsTtlS = 15 * 60;
constexpr int kMonthsHistory = 24;  // widget "po mjesecima" ima opciju do 24 mjeseca

Date first_of_month(Date d) { return Date{d.year(), d.month(), std::chrono::day{1}}; }

Date months_back(Date first, int n) {
    const auto ym = std::chrono::year_month{first.year(), first.month()} - std::chrono::months{n};
    return Date{ym.year(), ym.month(), std::chrono::day{1}};
}

json date_json(Date d) { return iso_date(d); }
}  // namespace

std::vector<DayKwh> days_from_aggregates(const std::vector<HourAggregate>& hours, Date start, Date end) {
    struct Acc {
        std::optional<double> e_daily;
        std::optional<double> total_min, total_max;
        int n_total = 0;
        int n_load = 0;
        double load = 0, imp = 0, exp = 0;
    };
    std::map<Date, Acc> acc;
    for (const auto& h : hours) {
        const std::tm t = local_tm(h.hour);
        Acc& a = acc[local_date(h.hour)];
        if (t.tm_hour >= kEDailyFromHour && h.e_daily_max) a.e_daily = std::max(a.e_daily.value_or(*h.e_daily_max), *h.e_daily_max);
        if (h.e_total_min) a.total_min = std::min(a.total_min.value_or(*h.e_total_min), *h.e_total_min);
        if (h.e_total_max) a.total_max = std::max(a.total_max.value_or(*h.e_total_max), *h.e_total_max);
        a.n_total += h.n_total;
        if (h.n_load > 0) {
            a.n_load += h.n_load;
            a.load += h.load_avg.value_or(0);
            a.imp += h.import_avg.value_or(0);
            a.exp += h.export_avg.value_or(0);
        }
    }
    std::vector<DayKwh> out;
    for (Date d = start; d <= end; d = add_days(d, 1)) {
        DayKwh day{d};
        if (auto it = acc.find(d); it != acc.end()) {
            const Acc& a = it->second;
            if (a.e_daily && *a.e_daily > 0) day.kwh = *a.e_daily;
            else if (a.n_total >= 2 && a.total_min && a.total_max) day.kwh = *a.total_max - *a.total_min;
            if (a.n_load > 0) {
                day.load = a.load;
                day.import = a.imp;
                day.exported = a.exp;
            }
        }
        out.push_back(day);
    }
    return out;
}

double savings(const Settings& s, double produced_kwh, std::optional<double> export_kwh) {
    const double exported = std::clamp(export_kwh.value_or(0.0), 0.0, std::max(produced_kwh, 0.0));
    return (produced_kwh - exported) * s.price_kwh + exported * s.feedin_price_kwh;
}

std::vector<DayKwh> DataService::daily(Db& db, Date start, Date end) {
    return days_from_aggregates(db.hourly_aggregates(local_midnight(start), local_midnight(add_days(end, 1))), start, end);
}

std::vector<DayKwh> DataService::daily(Date start, Date end) {
    Db db(db_path_, read_only_);
    return daily(db, start, end);
}

json DataService::realtime(Db& db, const Settings& s, const std::vector<DayKwh>& month) {
    const std::time_t t = now();
    const auto last = db.latest();
    const bool stale = !last || t - last->ts > kStaleAfterS;
    const double power = last ? last->power_kw : 0.0;
    double month_kwh = 0;
    for (const auto& d : month) month_kwh += d.kwh;
    const std::time_t midnight = local_midnight(local_date(t));
    const double expected = static_cast<double>(t - midnight) / std::max(s.poll_interval_s, 1);
    const int count = db.count_between(midnight, t + 1);
    json rt = {
        {"power_kw", power},
        {"running", !stale && power > 0},
        {"stale", stale},
        {"day_kwh", month.empty() ? 0.0 : month.back().kwh},
        {"month_kwh", month_kwh},
        {"total_kwh", last ? last->e_total_kwh : 0.0},
        {"status", last ? last->status : 0},
        {"pf", last && last->pf && !stale ? json(*last->pf) : json(nullptr)},
        {"load_kw", last && last->load_kw && !stale ? json(*last->load_kw) : json(nullptr)},
        {"availability", expected >= 1 ? json(std::min(100.0, count / expected * 100)) : json(nullptr)},
        {"updated_at", last ? json(static_cast<int64_t>(last->ts)) : json(nullptr)},
        // podaci uređaja (baterija, temperatura, mreža) – samo dok očitanje nije zastarjelo
        {"extra", last && !stale ? last->extra : json::object()},
    };
    return rt;
}

json DataService::records(Db& db) {
    const std::time_t t = now();
    if (!records_cache_.is_null() && t - records_at_ < kRecordsTtlS) return records_cache_;
    json rec = json::object();
    if (const auto first = db.first_timestamp()) {
        const Date first_day = local_date(*first), today = local_date(t);
        const auto days = daily(db, first_day, today);
        const auto best = std::max_element(days.begin(), days.end(), [](auto& a, auto& b) { return a.kwh < b.kwh; });
        std::map<Date, double> months;
        int producing = 0;
        for (const auto& d : days) {
            months[first_of_month(d.date)] += d.kwh;
            producing += d.kwh > 0;
        }
        const auto best_month = std::max_element(months.begin(), months.end(), [](auto& a, auto& b) { return a.second < b.second; });
        rec["first_day"] = date_json(first_day);
        if (best != days.end()) rec["best_day"] = {date_json(best->date), best->kwh};
        if (best_month != months.end()) rec["best_month"] = {date_json(best_month->first), best_month->second};
        if (const auto peak = db.peak_power()) rec["peak_power"] = {static_cast<int64_t>(peak->first), peak->second};
        rec["producing_days"] = producing;
        all_days_ = days;
    }
    records_cache_ = rec;
    records_at_ = t;
    return rec;
}

json DataService::savings_json(const Settings& s, const std::vector<DayKwh>& recent) {
    if (recent.empty() || records_cache_.is_null() || !records_cache_.contains("first_day")) return json::object();
    const Date today = recent.back().date;
    const Date month_start = first_of_month(today);
    const Date year_start{today.year(), std::chrono::January, std::chrono::day{1}};
    double day = 0, month = 0, year = 0, total = 0;
    bool metered = false;
    for (const auto& d : all_days_) {  // dani prije svježeg razdoblja (iz keša rekorda)
        if (d.date < recent.front().date) total += savings(s, d.kwh, d.exported);
    }
    for (const auto& d : recent) {
        const double v = savings(s, d.kwh, d.exported);
        metered = metered || d.exported.has_value();
        total += v;
        if (d.date >= year_start) year += v;
        if (d.date >= month_start) month += v;
        if (d.date == today) day = v;
    }
    return {{"today", day}, {"month", month}, {"year", year}, {"total", total},
            {"first_day", records_cache_["first_day"]}, {"metered", metered}};
}

json DataService::dashboard(const Settings& s) {
    std::lock_guard lock(mutex_);
    Db db(db_path_, read_only_);
    const std::time_t t = now();
    const Date today = local_date(t);
    const Date month_start = first_of_month(today);
    const Date prev_month_start = months_back(month_start, 1);
    const Date year_start{today.year(), std::chrono::January, std::chrono::day{1}};

    // Dnevni iznosi od najranijeg potrebnog datuma: 24 mjeseca (mjesečni grafikon) i prošla godina (usporedba).
    const Date history_start = std::min(months_back(month_start, kMonthsHistory - 1),
                                        Date{today.year() - std::chrono::years{1}, std::chrono::January, std::chrono::day{1}});
    const auto days = daily(db, history_start, today);

    std::vector<DayKwh> month;
    json daily_json = json::array();
    std::map<Date, double> months;
    double year_this = 0, year_last = 0;
    // isti dan prošle godine (29. veljače → 28. veljače)
    Date last_year_end{today.year() - std::chrono::years{1}, today.month(), today.day()};
    if (!last_year_end.ok()) last_year_end = Date{last_year_end.year(), std::chrono::February, std::chrono::day{28}};
    const Date last_year_start{last_year_end.year(), std::chrono::January, std::chrono::day{1}};
    const Date bars_start = std::min(prev_month_start, add_days(today, -(kMaxBarDays - 1)));
    for (const auto& d : days) {
        if (d.date >= month_start) month.push_back(d);
        if (d.date >= bars_start) {
            auto opt = [](const std::optional<double>& v) { return v ? json(*v) : json(nullptr); };
            daily_json.push_back({date_json(d.date), d.kwh, opt(d.load), opt(d.import), opt(d.exported)});
        }
        months[first_of_month(d.date)] += d.kwh;
        if (d.date >= year_start) year_this += d.kwh;
        if (d.date >= last_year_start && d.date <= last_year_end) year_last += d.kwh;
    }
    json monthly = json::array();
    for (int i = kMonthsHistory - 1; i >= 0; --i) {
        const Date m = months_back(month_start, i);
        monthly.push_back({date_json(m), months.count(m) ? months[m] : 0.0});
    }
    json curve = json::array();
    // [vrijeme, snaga elektrane, snaga s mjerača ili null]
    for (const auto& b : db.power_buckets(local_midnight(today), local_midnight(add_days(today, 1)), kCurveBucketS)) {
        curve.push_back({static_cast<int64_t>(b.t), b.power_kw, b.load_kw ? json(*b.load_kw) : json(nullptr)});
    }
    return {
        {"now", static_cast<int64_t>(t)},
        {"today", date_json(today)},
        {"realtime", realtime(db, s, month)},
        {"curve", curve},
        {"daily", daily_json},
        {"monthly", monthly},
        {"year", {year_this, year_last}},
        {"records", records(db)},
        {"savings", savings_json(s, days)},
    };
}

std::optional<std::pair<std::time_t, double>> DataService::peak_between(std::time_t start, std::time_t end) {
    std::lock_guard lock(mutex_);
    Db db(db_path_, read_only_);
    return db.peak_power_between(start, end);
}

json DataService::db_info() {
    std::lock_guard lock(mutex_);
    if (!fs::exists(db_path_)) return {{"path", narrow(db_path_.wstring())}, {"readings", 0}};
    Db db(db_path_, read_only_);
    const auto first = db.first_timestamp();
    const auto last = db.latest();
    return {{"path", narrow(db_path_.wstring())}, {"readings", db.total_readings()},
            {"first", first ? json(utc_text(*first)) : json(nullptr)},
            {"last", last ? json(utc_text(last->ts)) : json(nullptr)}};
}

}  // namespace sm

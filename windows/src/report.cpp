#include "report.hpp"

#include <cstdio>

#include "i18n.hpp"

namespace sm {

namespace {

using namespace std::chrono;

json opt(const std::optional<double>& v) { return v ? json(*v) : json(nullptr); }

Date last_day(int year, unsigned month) { return Date{std::chrono::year{year} / std::chrono::month{month} / last}; }

double month_kwh(DataService& data, int year, unsigned month) {
    double sum = 0;
    for (const auto& d : data.daily(Date{std::chrono::year{year}, std::chrono::month{month}, day{1}}, last_day(year, month))) sum += d.kwh;
    return sum;
}

std::string local_text(std::time_t t, const char* format) {
    const std::tm tm = local_tm(t);
    char buf[32];
    std::strftime(buf, sizeof buf, format, &tm);
    return buf;
}

// Datum prema uzorku jezika (meta.date, npr. "{d:02}.{m:02}.{y}.")
std::string format_date(const std::string& pattern, Date d) {
    std::string out = pattern;
    auto put = [&](const std::string& key, const std::string& value) {
        for (size_t pos; (pos = out.find(key)) != std::string::npos;) out.replace(pos, key.size(), value);
    };
    char dd[4], mm[4];
    std::snprintf(dd, sizeof dd, "%02u", static_cast<unsigned>(d.day()));
    std::snprintf(mm, sizeof mm, "%02u", static_cast<unsigned>(d.month()));
    put("{d:02}", dd);
    put("{m:02}", mm);
    put("{d}", std::to_string(static_cast<unsigned>(d.day())));
    put("{m}", std::to_string(static_cast<unsigned>(d.month())));
    put("{y}", std::to_string(static_cast<int>(d.year())));
    return out;
}

}  // namespace

json build_report(DataService& data, const Settings& s, int year, unsigned month) {
    const Date today = local_date(now());
    const Date first{std::chrono::year{year}, std::chrono::month{month}, day{1}};
    if (!first.ok() || first > today) throw std::runtime_error(tr("Izvještaj za budući mjesec nije moguć."));
    const Date month_end = last_day(year, month);
    const Date until = std::min(month_end, today);
    const auto days = data.daily(first, until);

    json day_rows = json::array();
    double kwh = 0, load = 0, imported = 0, exported = 0, total_savings = 0;
    bool metered = false;
    const DayKwh* best = nullptr;
    for (const auto& d : days) {
        const double self = d.kwh - d.exported.value_or(0);
        const double sv = savings(s, d.kwh, d.exported);
        day_rows.push_back({{"date", iso_date(d.date)}, {"kwh", d.kwh}, {"load", opt(d.load)}, {"import", opt(d.import)},
                            {"export", opt(d.exported)}, {"self", self}, {"savings", sv}});
        kwh += d.kwh;
        total_savings += sv;
        if (d.load) {
            metered = true;
            load += *d.load;
            imported += d.import.value_or(0);
            exported += d.exported.value_or(0);
        }
        if (d.kwh > 0 && (!best || d.kwh > best->kwh)) best = &d;
    }
    const double self_kwh = kwh - (metered ? exported : 0);
    const Date prev = add_days(first, -1);
    const auto peak = data.peak_between(local_midnight(first), local_midnight(add_days(until, 1)));
    json r = {
        {"plant", s.plant_name}, {"location", s.location}, {"kwp", s.peak_power_kwp}, {"currency", s.currency},
        {"price", s.price_kwh}, {"feedin", s.feedin_price_kwh}, {"co2_factor", s.co2_factor},
        {"year", year}, {"month", month}, {"complete", until == month_end}, {"until", iso_date(until)},
        {"generated", local_text(now(), "%Y-%m-%dT%H:%M")}, {"metered", metered}, {"days", day_rows},
        {"totals", {{"kwh", kwh}, {"load", metered ? json(load) : json(nullptr)}, {"import", metered ? json(imported) : json(nullptr)},
                    {"export", metered ? json(exported) : json(nullptr)}, {"self", self_kwh},
                    {"self_share", metered && kwh > 0 ? json(self_kwh / kwh * 100) : json(nullptr)},
                    {"autarky", metered && load > 0 ? json(self_kwh / load * 100) : json(nullptr)},
                    {"savings", total_savings}, {"co2_kg", kwh * s.co2_factor}}},
        {"compare", {{"prev_month", month_kwh(data, static_cast<int>(prev.year()), static_cast<unsigned>(prev.month()))},
                     {"last_year", month_kwh(data, year - 1, month)}}},
        {"best_day", best ? json{{"date", iso_date(best->date)}, {"kwh", best->kwh}} : json(nullptr)},
        // uvezena povijest može imati samo dnevne iznose (snaga 0) – tada vrh nije poznat
        {"peak", peak && peak->second > 0 ? json{{"ts", local_text(peak->first, "%Y-%m-%dT%H:%M")}, {"kw", peak->second}} : json(nullptr)},
    };
    return r;
}

std::string report_csv(const json& r) {
    const json meta = i18n_bundle(language()).value("meta", json::object());
    const std::string decimal = meta.value("decimal", ","), pattern = meta.value("date", "{d:02}.{m:02}.{y}.");
    const std::string sep = decimal == "," ? ";" : ",";
    const std::string cur = r.value("currency", "€");
    auto num = [&](const json& v) {
        if (!v.is_number()) return std::string{};
        char buf[48];
        std::snprintf(buf, sizeof buf, "%.2f", v.get<double>());
        std::string text = buf;
        if (decimal != ".") for (size_t pos; (pos = text.find('.')) != std::string::npos;) text.replace(pos, 1, decimal);
        return text;
    };
    std::string out = "\xEF\xBB\xBF";
    out += tr("Datum") + sep + tr("Proizvodnja") + " (kWh)" + sep + tr("Potrošnja") + " (kWh)" + sep + tr("Iz mreže") + " (kWh)" + sep +
           tr("Predaja u mrežu") + " (kWh)" + sep + tr("Vlastita potrošnja") + " (kWh)" + sep + tr("Ušteda") + " (" + cur + ")\r\n";
    for (const auto& d : r["days"]) {
        int y = 0;
        unsigned m = 0, dd = 0;
        std::sscanf(d.value("date", "").c_str(), "%d-%u-%u", &y, &m, &dd);
        out += format_date(pattern, Date{std::chrono::year{y}, std::chrono::month{m}, std::chrono::day{dd}}) + sep + num(d["kwh"]) + sep +
               num(d["load"]) + sep + num(d["import"]) + sep + num(d["export"]) + sep + num(d["self"]) + sep + num(d["savings"]) + "\r\n";
    }
    const json& t = r["totals"];
    out += tr("Ukupno") + sep + num(t["kwh"]) + sep + num(t["load"]) + sep + num(t["import"]) + sep + num(t["export"]) + sep +
           num(t["self"]) + sep + num(t["savings"]) + "\r\n";
    return out;
}

}  // namespace sm

#include "dashboard.hpp"

#include <algorithm>
#include <cmath>

#include "images.hpp"
#include "poller.hpp"

namespace sm {

json ui_settings(const Settings& s) {
    return {{"theme", s.theme}, {"palette", s.palette}, {"icon_theme", s.icon_theme}, {"plant_name", s.plant_name}, {"location", s.location}, {"commissioned", s.commissioned},
            {"speedo_max_kw", s.speedo_max_kw}, {"peak_power_kwp", s.peak_power_kwp}, {"co2_factor", s.co2_factor},
            {"meter_unit_id", s.meter_unit_id}, {"modbus_host", s.modbus_host}, {"poll_interval_s", s.poll_interval_s},
            {"hide_idle_cursor", s.hide_idle_cursor}, {"headline", s.headline}, {"language", s.language},
            {"device_type", s.device_type},
            {"headline_running", s.headline_running}, {"headline_idle", s.headline_idle},
            {"currency", s.currency}, {"price_kwh", s.price_kwh}, {"feedin_price_kwh", s.feedin_price_kwh},
            {"night_mode", s.night_mode}, {"night_from", s.night_from}, {"night_to", s.night_to}, {"forecast_days", s.forecast_days}};
}

json build_dashboard(DataService& data, WeatherService& weather, const Catalog& catalog, const Settings& s) {
    json d = data.dashboard(s);
    d["settings"] = ui_settings(s);
    d["weather"] = weather.get(s);
    d.update(pages_json(load_pages(catalog, layout_file())));
    d["images"] = {{"hero", image_url("hero")}, {"drawing", image_url("drawing")}, {"logo", image_url("logo")}};
    d["version"] = SOLARI_VERSION;
    d["capabilities"] = device_capabilities(s);  // widgeti za bateriju, temperaturu i mrežu
    return d;
}

void apply_local_display(json& out, const Settings& local) {
    out["theme"] = local.theme;
    out["palette"] = local.palette;  // paleta je postavka svakog ekrana, kao i tema
    out["icon_theme"] = local.icon_theme;  // i tema ikona
    out["language"] = local.language;
    out["hide_idle_cursor"] = local.hide_idle_cursor;
    out["night_mode"] = local.night_mode;
    out["night_from"] = local.night_from;
    out["night_to"] = local.night_to;
    out["forecast_days"] = local.forecast_days;  // broj dana prognoze je postavka svakog ekrana
    // 5.0.1 (audit W-03): vrijednosti s poslužitelja u razumnom rasponu – npr. 1e9 bi zamrznuo brzinomjer (petlja po kW)
    const auto clamp_num = [&](const char* key, double fallback) {
        const double v = out.contains(key) && out[key].is_number() ? out[key].get<double>() : fallback;
        out[key] = std::isfinite(v) ? std::clamp(v, 0.0, 100000.0) : fallback;
    };
    clamp_num("speedo_max_kw", local.speedo_max_kw);
    clamp_num("peak_power_kwp", local.peak_power_kwp);
}

}  // namespace sm

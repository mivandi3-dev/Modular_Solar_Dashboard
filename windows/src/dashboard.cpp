#include "dashboard.hpp"

#include "images.hpp"
#include "poller.hpp"

namespace sm {

json ui_settings(const Settings& s) {
    return {{"theme", s.theme}, {"palette", s.palette}, {"plant_name", s.plant_name}, {"location", s.location}, {"commissioned", s.commissioned},
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
    out["language"] = local.language;
    out["hide_idle_cursor"] = local.hide_idle_cursor;
    out["night_mode"] = local.night_mode;
    out["night_from"] = local.night_from;
    out["night_to"] = local.night_to;
    out["forecast_days"] = local.forecast_days;  // broj dana prognoze je postavka svakog ekrana
    out["speedo_max_kw"] = out.value("speedo_max_kw", local.speedo_max_kw);
}

}  // namespace sm

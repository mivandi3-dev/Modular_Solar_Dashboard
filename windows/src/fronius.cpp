#include "fronius.hpp"

#include "cloud.hpp"
#include "i18n.hpp"
#include "poller.hpp"

namespace sm {

namespace {
constexpr int kTimeoutMs = 8000;
constexpr const char* kPowerFlowPath = "/solar_api/v1/GetPowerFlowRealtimeData.fcgi";

std::optional<double> number(const json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key) || !obj[key].is_number()) return std::nullopt;
    return obj[key].get<double>();
}

// Zbroj polja po inverterima (Inverters: {"1": {...}, "2": {...}}); nullopt ako ga nijedan nema.
std::optional<double> inverters_sum(const json& data, const char* key) {
    if (!data.contains("Inverters") || !data["Inverters"].is_object()) return std::nullopt;
    std::optional<double> sum;
    for (const auto& [_, inv] : data["Inverters"].items()) {
        if (const auto v = number(inv, key)) sum = sum.value_or(0) + *v;
    }
    return sum;
}
}  // namespace

PlantReading parse_fronius_powerflow(const json& body, bool with_meter) {
    const json& head = body.value("Head", json::object());
    if (const json st = head.value("Status", json::object()); st.value("Code", 0) != 0) {
        throw std::runtime_error(tr("Fronius javlja grešku: {error}", {{"error", st.value("Reason", std::to_string(st.value("Code", 0)))}}));
    }
    const json& data = body.value("Body", json::object()).value("Data", json::object());
    const json& site = data.value("Site", json::object());
    if (!site.is_object() || site.empty()) throw std::runtime_error(tr("Neočekivan odgovor uređaja."));
    PlantReading out;
    const auto pv = number(site, "P_PV");  // null noću
    out.reading.power_kw = std::max(0.0, pv.value_or(inverters_sum(data, "P").value_or(0))) / 1000.0;
    const auto total = number(site, "E_Total") ? number(site, "E_Total") : inverters_sum(data, "E_Total");
    if (!total) throw std::runtime_error(tr("Fronius ne daje ukupnu proizvedenu energiju."));
    out.reading.e_total_kwh = *total / 1000.0;
    const auto day = number(site, "E_Day") ? number(site, "E_Day") : inverters_sum(data, "E_Day");
    out.reading.e_daily_kwh = day ? *day / 1000.0 : -1;  // GEN24 bez E_Day – računa poller
    out.reading.pf = 0;
    out.reading.status = out.reading.power_kw > 0 ? 1 : 0;
    if (with_meter) {
        if (const auto grid = number(site, "P_Grid")) out.load_kw = *grid / 1000.0;  // + iz mreže
        else out.meter_error = tr("Fronius ne javlja snagu mreže (P_Grid) – je li Smart Meter spojen?");
    }
    // baterija (GEN24, Symo Hybrid): P_Akku > 0 pražnjenje, SOC po inverteru
    if (const auto akku = number(site, "P_Akku")) {
        std::optional<double> soc;
        if (data.contains("Inverters") && data["Inverters"].is_object()) {
            for (const auto& [_, inv] : data["Inverters"].items()) {
                if (const auto s = number(inv, "SOC")) soc = s;
            }
        }
        if (soc) {
            out.extra["battery_soc"] = *soc;
            out.extra["battery_kw"] = -*akku / 1000.0;
            out.extra["battery_dir"] = true;
        }
    }
    out.device_name = "Fronius";
    return out;
}

PlantReading read_fronius(const Settings& s) {
    const std::string base = "http://" + s.modbus_host + (s.modbus_port == 80 ? "" : ":" + std::to_string(s.modbus_port));
    HttpResult r;
    try {
        HttpCall call;
        call.path = kPowerFlowPath;
        call.timeout_ms = kTimeoutMs;
        r = http_call(base, call);
    } catch (const CloudError& e) {
        throw std::runtime_error(tr("Fronius ({host}) ne odgovara: {error}", {{"host", s.modbus_host}, {"error", e.what()}}));
    }
    if (r.status == 404) throw std::runtime_error(tr("Uređaj na {host} nema Fronius Solar API.", {{"host", s.modbus_host}}));
    if (r.status != 200) throw std::runtime_error(tr("Uređaj je vratio grešku {code}.", {{"code", std::to_string(r.status)}}));
    try {
        return parse_fronius_powerflow(json::parse(r.body), s.meter_unit_id != 0);
    } catch (const json::exception&) {
        throw std::runtime_error(tr("Neočekivan odgovor uređaja."));
    }
}

}  // namespace sm

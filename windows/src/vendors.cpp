#include "vendors.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <memory>

#include "i18n.hpp"
#include "net.hpp"
#include "poller.hpp"
#include "serial.hpp"

namespace sm {

namespace {
constexpr int kTimeoutMs = 8000;
constexpr uint16_t kMaxRead = 125, kMaxGap = 8;
constexpr int kSolarmanPort = 8899;

VendorPoint u16(uint16_t a, double scale = 1) { return {a, 0, false, false, scale}; }
VendorPoint temp_deye(uint16_t a) { return {a, 0, false, false, 0.1, 1000}; }  // (sirovo − 1000) × 0,1 °C
VendorPoint s16(uint16_t a, double scale = 1) { return {a, 0, false, true, scale}; }
VendorPoint u32(uint16_t lo, uint16_t hi, double scale = 1) { return {lo, hi, true, false, scale}; }
VendorPoint s32(uint16_t lo, uint16_t hi, double scale = 1) { return {lo, hi, true, true, scale}; }
// Big-endian riječi (viša riječ na nižoj adresi) – GoodWe, Solis, Fox ESS, Growatt
VendorPoint u32be(uint16_t a, double scale = 1) { return u32(static_cast<uint16_t>(a + 1), a, scale); }
VendorPoint s32be(uint16_t a, double scale = 1) { return s32(static_cast<uint16_t>(a + 1), a, scale); }

std::vector<VendorPoint> range16(uint16_t from, uint16_t to) {
    std::vector<VendorPoint> v;
    for (uint16_t a = from; a <= to; ++a) v.push_back(u16(a));
    return v;
}

// Adrese su adrese u Modbus zahtjevu (od 0). Gdje dokumentacija broji od 1 (Sungrow), oduzeto je 1.
std::vector<VendorProfile> make_profiles() {
    std::vector<VendorProfile> p;
    // Victron Energy GX (Cerbo, Venus): com.victronenergy.system, adresa 100 – victronenergy/dbus_modbustcp attributes.csv.
    // PV: AC na izlazu/mreži/agregatu po fazama (808–816) + DC PV (850); mreža 820–822 (+ uzimanje). Energije nema.
    {
        auto pv = range16(808, 816);
        pv.push_back(u16(850));
        p.push_back({"victron", "Victron Energy GX", 3, VendorLink::Tcp, 502, 100, pv, std::nullopt, std::nullopt,
                     {s16(820), s16(821), s16(822)}, true});
    }
    // Sungrow – SunGather registers-sungrow.yaml (input registri, 32 bita: niža riječ prva)
    p.push_back({"sungrow_sg", "Sungrow SG", 4, VendorLink::Tcp, 502, 1, {u32(5030, 5031)}, u16(5002, 0.1),
                 u32(5003, 5004), {s32(5215, 5216)}, false});
    p.push_back({"sungrow_sh", "Sungrow SH", 4, VendorLink::Tcp, 502, 1, {u32(5016, 5017)}, u16(13001, 0.1),
                 u32(13002, 13003, 0.1), {s32(13009, 13010)}, false});
    // GoodWe – marcelblijleven/goodwe et.py / dt.py (holding; Wi-Fi/LAN modul: UDP 8899, adresa 0xF7 / 0x7F)
    p.push_back({"goodwe_et", "GoodWe ET / EH / BT", 3, VendorLink::GoodweUdp, 8899, 0xF7,
                 {u32be(35105), u32be(35109), u32be(35113), u32be(35117)}, u32be(35193, 0.1), u32be(35191, 0.1),
                 {s16(35140)}, false});
    p.push_back({"goodwe_dt", "GoodWe DT / SDT / SMT", 3, VendorLink::GoodweUdp, 8899, 0x7F, {u32be(30127)},
                 u16(30144, 0.1), u32be(30145, 0.1), {s32be(30195)}, false});
    // Deye / Sunsynk – davidrapan/ha-solarman inverter_definitions (holding; 32 bita: niža riječ prva; logger 8899)
    p.push_back({"deye_string", "Deye SUN-K-G", 3, VendorLink::Solarman, 8899, 1, {u32(0x56, 0x57, 0.1)},
                 u16(0x3C, 0.1), u32(0x3F, 0x40, 0.1), {s32(0xCB, 0xCC)}, true});
    p.push_back({"deye_hybrid", "Deye / Sunsynk SG01LP1 (1~)", 3, VendorLink::Solarman, 8899, 1,
                 range16(0xBA, 0xBD), u16(0x6C, 0.1), u32(0x60, 0x61, 0.1), {s16(0xA9)}, true});
    p.push_back({"deye_hybrid3", "Deye / Sunsynk SG04LP3 / HP3 (3~)", 3, VendorLink::Solarman, 8899, 1,
                 range16(0x2A0, 0x2A3), std::nullopt, u32(0x216, 0x217, 0.1), {s32(0x271, 0x2B2)}, true});
    // Solis – ha-solarman solis_1p-5g / solis_3p-5g (input registri, viša riječ prva)
    p.push_back({"solis_string", "Solis 4G / 5G", 4, VendorLink::Tcp, 502, 1, {u32be(3006)}, u16(3014, 0.1),
                 u32be(3008), {}, false});
    p.push_back({"solis_hybrid", "Solis RHI / S6 hybrid", 4, VendorLink::Tcp, 502, 1, {u32be(33057)}, u16(33035, 0.1),
                 u32be(33029), {s32be(33263)}, false});
    // Fox ESS H1 / H3 – nathanmarlor/foxess_modbus (LAN, holding, adresa 247)
    p.push_back({"foxess", "Fox ESS H1 / H3", 3, VendorLink::Tcp, 502, 247, {s16(31002), s16(31005)}, u16(32002, 0.1),
                 u32be(32000, 0.1), {s16(31014)}, false});
    // Growatt – Modbus RTU protokol v1.24 (input registri 0–124), preko RS485 → Modbus TCP pristupnika
    p.push_back({"growatt", "Growatt (MIC / MIN / MOD / MAX)", 4, VendorLink::Tcp, 502, 1, {u32be(35, 0.1)},
                 u32be(53, 0.1), u32be(55, 0.1), {}, false});

    // ---- otočni sustavi preko serijskog porta (3.2) – NISU isprobani na stvarnim uređajima
    // Growatt SPF (off-grid) – OffGrid SPF5000 Modbus RS485/RS232 RTU Protocol (input registri; 32 bita: viša riječ prva)
    p.push_back({"growatt_spf", "Growatt SPF (off-grid)", 4, VendorLink::Serial, 9600, 1, {u32be(3, 0.1)},
                 u32be(48, 0.1), u32be(50, 0.1), {}, false});
    // EPEver Tracer / UPower / IPower – EPEver Modbus protokol V2.3 (input registri; 32 bita: niža riječ prva)
    p.push_back({"epever", "EPEver Tracer / UPower", 4, VendorLink::Serial, 115200, 1, {u32(0x3102, 0x3103, 0.01)},
                 u32(0x330C, 0x330D, 0.01), u32(0x3312, 0x3313, 0.01), {}, false});
    // SRNE (HF / ML / ASF) – SRNE Solar Charge Inverter MODBUS Protocol 1.96 (holding; ha-solarman srne_asf)
    p.push_back({"srne", "SRNE (HF / ML / ASF)", 3, VendorLink::Serial, 9600, 1, {u16(0x0109), u16(0x0111)},
                 u16(0xF02F, 0.1), u32(0xF038, 0xF039, 0.1), {}, false});

    // Podaci za widgete (isti izvori kao gore)
    auto set = [&](const char* key, std::vector<std::pair<const char*, VendorPoint>> extras, int battery_sign = 0) {
        for (auto& prof : p) {
            if (std::string(prof.key) == key) {
                prof.extras = std::move(extras);
                prof.battery_sign = battery_sign;
            }
        }
    };
    // /Dc/Battery: > 0 punjenje; 3.2: napon baterije (12/24/48 V) i AC potrošnja po fazama (817–819)
    set("victron", {{"battery_soc", u16(843)}, {"battery_w", s16(842)}, {"battery_v", u16(840, 0.1)},
                    {"ac_load_w", u16(817)}, {"ac_load_w", u16(818)}, {"ac_load_w", u16(819)}}, +1);
    set("growatt_spf", {{"battery_soc", u16(18)}, {"battery_w", s32be(77, 0.1)}, {"battery_v", u16(17, 0.01)},
                        {"inverter_temp", u16(25, 0.1)}, {"grid_v", u16(20, 0.1)}, {"grid_hz", u16(21, 0.01)},
                        {"ac_out_v", u16(22, 0.1)}, {"ac_out_hz", u16(23, 0.01)}, {"ac_load_w", u32be(9, 0.1)},
                        {"load_pct", u16(27, 0.1)}}, -1);  // Bat_Watt > 0 pražnjenje
    set("epever", {{"battery_soc", u16(0x311A)}, {"battery_v", u16(0x331A, 0.01)}, {"battery_a", s32(0x331B, 0x331C, 0.01)},
                   {"inverter_temp", s16(0x3111, 0.01)}, {"ac_load_w", u32(0x310E, 0x310F, 0.01)}}, +1);  // struja > 0 punjenje
    set("srne", {{"battery_soc", u16(0x0100)}, {"battery_v", u16(0x0101, 0.1)}, {"battery_a", s16(0x0102, 0.1)},
                 {"inverter_temp", u16(0x0220, 0.1)}, {"grid_v", u16(0x0213, 0.1)}, {"grid_hz", u16(0x0215, 0.01)},
                 {"ac_load_w", u16(0x021B)}}, +1);
    set("sungrow_sg", {{"inverter_temp", s16(5007, 0.1)}, {"grid_v", u16(5018, 0.1)}, {"grid_hz", u16(5035, 0.1)}});
    set("sungrow_sh", {{"inverter_temp", s16(5007, 0.1)}, {"grid_v", u16(5018, 0.1)}, {"grid_hz", u16(5035, 0.1)},
                       {"battery_soc", u16(13022, 0.1)}, {"battery_w", s16(13021)}});
    set("goodwe_et", {{"inverter_temp", s16(35176, 0.1)}, {"grid_v", u16(35121, 0.1)}, {"grid_hz", u16(35123, 0.01)},
                      {"battery_soc", u16(37007)}, {"battery_w", s32be(35182)}}, -1);  // pbattery1 > 0 pražnjenje
    set("deye_string", {{"inverter_temp", temp_deye(0x5B)}, {"grid_v", u16(0x49, 0.1)}, {"grid_hz", u16(0x4F, 0.01)}});
    set("deye_hybrid", {{"inverter_temp", temp_deye(0x5B)}, {"grid_v", u16(0x96, 0.1)}, {"grid_hz", u16(0x4F, 0.01)},
                        {"battery_soc", u16(0xB8)}, {"battery_w", s16(0xBE)}}, -1);
    set("deye_hybrid3", {{"inverter_temp", temp_deye(0x21D)}, {"grid_v", u16(0x256, 0.1)}, {"grid_hz", u16(0x261, 0.01)},
                         {"battery_soc", u16(0x24C)}, {"battery_w", s16(0x24E)}}, -1);
    set("solis_string", {{"inverter_temp", s16(3041, 0.1)}});
    set("solis_hybrid", {{"inverter_temp", s16(33093, 0.1)}, {"battery_soc", u16(33139)}, {"battery_w", s32be(33149)}});
    set("growatt", {{"inverter_temp", u16(93, 0.1)}, {"grid_v", u16(38, 0.1)}, {"grid_hz", u16(37, 0.01)}});
    return p;
}

using Regs = std::vector<std::pair<uint16_t, uint16_t>>;

// Podaci za widgete; ako uređaj neku adresu nema (npr. hibrid bez baterije), čitaju se pojedinačno i preskaču.
json read_extras(const VendorProfile& prof, const std::function<Regs(const std::vector<const VendorPoint*>&)>& read) {
    json x = json::object();
    if (prof.extras.empty()) return x;
    double battery_a = std::nan("");
    auto store = [&](const char* key, double v) {
        const std::string k = key;
        if (k == "battery_w") {
            x["battery_kw"] = (prof.battery_sign < 0 ? -v : v) / 1000.0;
            x["battery_dir"] = prof.battery_sign != 0;
        } else if (k == "battery_a") {
            battery_a = v;
        } else if (k == "ac_load_w") {  // po fazama se zbraja
            x["ac_load_kw"] = x.value("ac_load_kw", 0.0) + v / 1000.0;
        } else {
            x[k] = v;
        }
    };
    std::vector<const VendorPoint*> all;
    for (const auto& [key, point] : prof.extras) all.push_back(&point);
    try {
        const Regs regs = read(all);
        for (const auto& [key, point] : prof.extras) store(key, vendor_value(point, regs));
    } catch (const ModbusError&) {
        x = json::object();  // djelomično upisano iz neuspjelog skupnog čitanja
        battery_a = std::nan("");
        for (const auto& [key, point] : prof.extras) {
            try {
                store(key, vendor_value(point, read({&point})));
            } catch (const ModbusError&) {
            }
        }
    }
    if (!x.contains("battery_kw") && !std::isnan(battery_a) && x.contains("battery_v")) {  // snaga = napon × struja
        const double w = x["battery_v"].get<double>() * battery_a;
        x["battery_kw"] = (prof.battery_sign < 0 ? -w : w) / 1000.0;
        x["battery_dir"] = prof.battery_sign != 0;
    }
    if (!x.contains("battery_soc")) {  // bez baterije nema ni snage baterije
        x.erase("battery_kw");
        x.erase("battery_dir");
    }
    return x;
}

void collect(const VendorPoint& p, std::vector<uint16_t>& out) {
    out.push_back(p.lo);
    if (p.wide) out.push_back(p.hi);
}

double sum(const std::vector<VendorPoint>& points, const std::vector<std::pair<uint16_t, uint16_t>>& regs) {
    double total = 0;
    for (const auto& p : points) total += vendor_value(p, regs);
    return total;
}
}  // namespace

const std::vector<VendorProfile>& vendor_profiles() {
    static const std::vector<VendorProfile> profiles = make_profiles();
    return profiles;
}

const VendorProfile* find_vendor(const std::string& key) {
    for (const auto& p : vendor_profiles()) {
        if (key == p.key) return &p;
    }
    return nullptr;
}

double vendor_value(const VendorPoint& p, const std::vector<std::pair<uint16_t, uint16_t>>& regs) {
    auto word = [&](uint16_t a) {
        const auto it = std::find_if(regs.begin(), regs.end(), [&](const auto& r) { return r.first == a; });
        if (it == regs.end()) throw ModbusError(tr("Neočekivan odgovor uređaja."));
        return it->second;
    };
    if (!p.wide) {
        const uint16_t w = word(p.lo);
            return ((p.sign ? static_cast<int16_t>(w) : static_cast<double>(w)) - p.offset) * p.scale;
    }
    const uint32_t v = (static_cast<uint32_t>(word(p.hi)) << 16) | word(p.lo);
    return ((p.sign ? static_cast<int32_t>(v) : static_cast<double>(v)) - p.offset) * p.scale;
}

std::vector<std::pair<uint16_t, uint16_t>> vendor_ranges(std::vector<uint16_t> a) {
    std::sort(a.begin(), a.end());
    a.erase(std::unique(a.begin(), a.end()), a.end());
    std::vector<std::pair<uint16_t, uint16_t>> out;  // (početak, broj)
    for (const uint16_t addr : a) {
        if (!out.empty()) {
            auto& [start, count] = out.back();
            const uint32_t end = start + count;  // prva adresa iza raspona
            if (addr < end) continue;
            if (addr - end <= kMaxGap && addr - start + 1u <= kMaxRead) {
                count = static_cast<uint16_t>(addr - start + 1);
                continue;
            }
        }
        out.emplace_back(addr, 1);
    }
    return out;
}

PlantReading read_vendor(const Settings& s) {
    const VendorProfile* prof = find_vendor(s.device_profile);
    if (!prof) throw std::runtime_error(tr("Odaberite proizvođača i model invertera."));
    const auto units = parse_units(s.inverter_units);
    if (!units) throw std::runtime_error(tr("Upišite adrese invertera odvojene zarezom, npr. 1 ili 1,2,3 (0–247, najviše 10)."));
    // otočni uređaji: Modbus RTU na COM portu (umjesto mreže)
    std::unique_ptr<SerialPort> com;
    if (prof->link == VendorLink::Serial) {
        if (!is_serial_port_name(s.serial_port)) throw std::runtime_error(tr("Izaberite serijski port (npr. COM3) ili USB."));
        com = std::make_unique<SerialPort>(s.serial_port, s.serial_baud ? s.serial_baud : prof->port, 2000);
    }
    Framing framing = Framing::Tcp;
    uint32_t serial = 0;
    if (s.modbus_port == kSolarmanPort && prof->link == VendorLink::Solarman) {
        framing = Framing::Solarman;
        const auto sn = parse_logger_serial(s.logger_serial);
        if (!sn) throw std::runtime_error(tr("Upišite serijski broj Wi-Fi loggera (10 znamenki, s naljepnice na loggeru)."));
        serial = *sn;
    } else if (s.modbus_port == kSolarmanPort && prof->link == VendorLink::GoodweUdp) {
        framing = Framing::GoodweUdp;
    }
    std::unique_ptr<ModbusClient> client;
    if (!com) {
        const auto src = source_ip(s.logger_interface);
        client = std::make_unique<ModbusClient>(s.modbus_host, s.modbus_port, units->front(), src.value_or(""), kTimeoutMs, prof->name,
                                                framing, serial);
        client->connect();
    }

    auto read_points = [&](int unit, const std::vector<const VendorPoint*>& points) {
        std::vector<uint16_t> addresses;
        for (const auto* p : points) collect(*p, addresses);
        std::vector<std::pair<uint16_t, uint16_t>> regs;
        for (const auto& [start, count] : vendor_ranges(addresses)) {
            const auto words = com ? rtu_serial_read(*com, unit, prof->fc, start, count) : client->read_registers(start, count, unit, prof->fc);
            for (uint16_t i = 0; i < count; ++i) regs.emplace_back(static_cast<uint16_t>(start + i), words[i]);
        }
        return regs;
    };

    PlantReading out;
    out.device_name = prof->name;
    double today = 0, total = 0;
    for (size_t i = 0; i < units->size(); ++i) {
        std::vector<const VendorPoint*> points;
        for (const auto& p : prof->power) points.push_back(&p);
        if (prof->today) points.push_back(&*prof->today);
        if (prof->total) points.push_back(&*prof->total);
        const auto regs = read_points((*units)[i], points);
        out.reading.power_kw += std::max(0.0, sum(prof->power, regs)) / 1000.0;
        if (prof->today) today += vendor_value(*prof->today, regs);
        if (prof->total) total += vendor_value(*prof->total, regs);
    }
    out.reading.e_daily_kwh = prof->today ? today : -1;  // bez dnevne – računa poller
    out.reading.e_total_kwh = prof->total ? total : -1;  // bez ukupne (Victron) – poller integrira snagu
    out.reading.status = out.reading.power_kw > 0 ? 1 : 0;
    out.extra = read_extras(*prof, [&](const std::vector<const VendorPoint*>& pts) { return read_points(units->front(), pts); });
    if (s.meter_unit_id && !prof->meter.empty()) {
        try {  // greška mjerača ne poništava očitanje elektrane
            std::vector<const VendorPoint*> points;
            for (const auto& p : prof->meter) points.push_back(&p);
            const double w = sum(prof->meter, read_points(units->front(), points));
            const bool import_positive = prof->meter_import_positive != s.meter_invert;
            out.load_kw = (import_positive ? w : -w) / 1000.0;  // load_kw: pozitivno = uzimanje iz mreže
        } catch (const ModbusError& e) {
            out.meter_error = e.what();
        }
    }
    return out;
}

}  // namespace sm

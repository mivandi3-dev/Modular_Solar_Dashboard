#include "offgrid.hpp"

#include <cmath>
#include <sstream>

#include "i18n.hpp"
#include "poller.hpp"
#include "serial.hpp"

namespace sm {

namespace {
constexpr int kVoltronicBaud = 2400, kVeDirectBaud = 19200;
constexpr int kVeListenMs = 2500;  // uređaj šalje blok svake sekunde (BMV/SmartShunt dva bloka)

std::vector<std::string> split_ports(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : text + ",") {
        if (c == ',' || c == ';' || c == ' ') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }
    return out;
}

double num(const VeBlock& b, const char* key, double scale) {
    const auto it = b.find(key);
    if (it == b.end()) return std::nan("");
    char* end = nullptr;
    const double v = std::strtod(it->second.c_str(), &end);
    return end && *end == '\0' ? v * scale : std::nan("");
}
}  // namespace

int nominal_system_voltage(double v) {
    if (!(v > 8)) return 0;
    if (v < 17) return 12;
    if (v < 34) return 24;
    if (v < 68) return 48;
    return 0;
}

// ---------------------------------------------------------------- Voltronic
uint16_t voltronic_crc(const std::string& data) {
    uint16_t crc = 0;
    for (unsigned char c : data) {
        crc ^= static_cast<uint16_t>(c) << 8;
        for (int i = 0; i < 8; ++i) crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021) : static_cast<uint16_t>(crc << 1);
    }
    uint8_t hi = crc >> 8, lo = crc & 0xFF;
    for (uint8_t* b : {&hi, &lo}) if (*b == 0x28 || *b == 0x0D || *b == 0x0A) ++*b;  // bajtovi koje protokol ne smije poslati
    return static_cast<uint16_t>((hi << 8) | lo);
}

std::string voltronic_frame(const std::string& command) {
    const uint16_t crc = voltronic_crc(command);
    return command + static_cast<char>(crc >> 8) + static_cast<char>(crc & 0xFF) + '\r';
}

std::string voltronic_unwrap(const std::string& raw) {
    const size_t start = raw.find('('), end = raw.find('\r', start == std::string::npos ? 0 : start);
    if (start == std::string::npos || end == std::string::npos || end < start + 3) throw SerialError(tr("Izmjenjivač nije odgovorio."));
    const std::string body = raw.substr(start, end - start - 2);  // "(…" bez CRC-a
    const uint16_t crc = static_cast<uint16_t>((static_cast<uint8_t>(raw[end - 2]) << 8) | static_cast<uint8_t>(raw[end - 1]));
    if (voltronic_crc(body) != crc) throw SerialError(tr("Odgovor izmjenjivača je oštećen (CRC)."));
    if (body.rfind("(NAK", 0) == 0) throw SerialError(tr("Izmjenjivač ne podržava upit."));
    return body.substr(1);
}

std::optional<VoltronicStatus> parse_qpigs(const std::string& fields) {
    std::istringstream in(fields);
    std::vector<std::string> f;
    for (std::string w; in >> w;) f.push_back(w);
    if (f.size() < 16) return std::nullopt;
    auto d = [&](size_t i) { return i < f.size() ? std::strtod(f[i].c_str(), nullptr) : 0.0; };
    VoltronicStatus s;
    s.grid_v = d(0); s.grid_hz = d(1); s.out_v = d(2); s.out_hz = d(3); s.out_va = d(4); s.out_w = d(5); s.load_pct = d(6);
    s.battery_v = d(8); s.charge_a = d(9); s.battery_pct = d(10); s.heatsink_c = d(11); s.pv_a = d(12); s.pv_v = d(13);
    s.discharge_a = d(15);
    s.pv_w = f.size() > 19 ? d(19) : s.pv_a * s.pv_v;  // novije verzije: snaga punjenja iz PV-a (W)
    return s;
}

PlantReading read_voltronic(const Settings& s) {
    std::string fields;
    if (s.serial_port.empty() || s.serial_port == "USB") {
        fields = voltronic_hid_query("QPIGS");
    } else {
        SerialPort port(s.serial_port, s.serial_baud ? s.serial_baud : kVoltronicBaud, 3000);
        port.write(voltronic_frame("QPIGS"));
        fields = voltronic_unwrap(port.read_until(3000, [](const std::string& r, size_t) { return r.find('\r') != std::string::npos; }));
    }
    const auto st = parse_qpigs(fields);
    if (!st) throw SerialError(tr("Neočekivan odgovor izmjenjivača."));
    PlantReading out;
    out.device_name = "Voltronic";
    out.reading.power_kw = std::max(0.0, st->pv_w) / 1000.0;
    out.reading.e_daily_kwh = -1;  // energiju poller računa iz snage
    out.reading.e_total_kwh = -1;
    out.reading.status = out.reading.power_kw > 0 ? 1 : 0;
    out.extra = {{"battery_soc", st->battery_pct}, {"battery_v", st->battery_v},
                 {"battery_kw", st->battery_v * (st->charge_a - st->discharge_a) / 1000.0}, {"battery_dir", true},
                 {"inverter_temp", st->heatsink_c}, {"ac_load_kw", st->out_w / 1000.0}, {"ac_out_v", st->out_v},
                 {"ac_out_hz", st->out_hz}, {"load_pct", st->load_pct}};
    if (st->grid_v > 50) out.extra.update({{"grid_v", st->grid_v}, {"grid_hz", st->grid_hz}});  // bez mreže (otok) polja su 0
    return out;
}

// ---------------------------------------------------------------- Victron VE.Direct
std::vector<VeBlock> parse_vedirect(const std::string& stream) {
    std::vector<VeBlock> out;
    // blok počinje s "\r\n" i završava poljem Checksum (jedan bajt); HEX poruke (":…\n") se preskaču
    size_t pos = 0;
    while (true) {
        const size_t start = stream.find("\r\n", pos);
        if (start == std::string::npos) break;
        const size_t ck = stream.find("\r\nChecksum\t", start);
        if (ck == std::string::npos || ck + 12 > stream.size()) break;
        const size_t end = ck + 12;  // uključuje bajt kontrolnog zbroja
        // blok je od zadnjeg "\r\n" koji započinje polje nakon prethodnog kontrolnog zbroja
        std::string block = stream.substr(start, end - start);
        unsigned sum = 0;
        for (unsigned char c : block) sum += c;
        // HEX poruke unutar bloka pokvare zbroj – takav se blok odbacuje (sljedeći dolazi za sekundu)
        if ((sum & 0xFF) == 0) {
            VeBlock b;
            std::istringstream in(block.substr(2, ck - start - 2));
            for (std::string line; std::getline(in, line);) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                const size_t tab = line.find('\t');
                if (tab != std::string::npos && line[0] != ':') b[line.substr(0, tab)] = line.substr(tab + 1);
            }
            if (!b.empty()) out.push_back(std::move(b));
        }
        pos = end;
    }
    return out;
}

VeSummary summarize_vedirect(const std::vector<VeBlock>& blocks) {
    VeSummary s;
    // isti uređaj šalje više blokova – zadnja vrijednost po serijskom broju (SER#) ili PID-u
    std::map<std::string, VeBlock> devices;
    for (const auto& b : blocks) {
        const auto ser = b.find("SER#"), pid = b.find("PID");
        const std::string key = ser != b.end() ? ser->second : pid != b.end() ? pid->second : "?";
        for (const auto& [k, v] : b) devices[key][k] = v;
    }
    double battery_v = std::nan(""), soc = std::nan(""), shunt_w = std::nan(""), mppt_charge_w = 0, ac_va = 0, ac_v = std::nan("");
    bool any_ac = false;
    for (const auto& [key, d] : devices) {
        const double ppv = num(d, "PPV", 1);
        if (!std::isnan(ppv)) {  // MPPT punjač
            s.pv_w += ppv;
            const double h20 = num(d, "H20", 0.01), h19 = num(d, "H19", 0.01);
            if (!std::isnan(h20)) { s.today_kwh += h20; s.has_yield = true; }
            if (!std::isnan(h19)) s.total_kwh += h19;
            const double v = num(d, "V", 0.001), i = num(d, "I", 0.001);
            if (!std::isnan(v) && !std::isnan(i)) mppt_charge_w += v * i;
            if (std::isnan(battery_v) && !std::isnan(v)) battery_v = v;
        }
        const double soc_pm = num(d, "SOC", 0.1);  // SmartShunt / BMV: promili
        if (!std::isnan(soc_pm)) {
            soc = soc_pm;
            const double v = num(d, "V", 0.001), p = num(d, "P", 1);
            if (!std::isnan(v)) battery_v = v;  // šant mjeri najtočnije
            if (!std::isnan(p)) shunt_w = p;    // > 0 punjenje
        }
        const double va = num(d, "AC_OUT_S", 1);  // Phoenix izmjenjivač
        if (!std::isnan(va)) {
            ac_va += va;
            any_ac = true;
            const double v = num(d, "AC_OUT_V", 0.01);
            if (!std::isnan(v)) ac_v = v;
        }
    }
    if (!std::isnan(battery_v)) s.extra["battery_v"] = battery_v;
    if (!std::isnan(soc)) {
        s.extra["battery_soc"] = soc;
        s.extra["battery_kw"] = (std::isnan(shunt_w) ? mppt_charge_w : shunt_w) / 1000.0;
        s.extra["battery_dir"] = true;
    }
    if (any_ac) {
        s.extra["ac_load_kw"] = ac_va / 1000.0;  // prividna snaga (VA) ≈ W kod omskih trošila
        if (!std::isnan(ac_v)) s.extra["ac_out_v"] = ac_v;
    }
    return s;
}

PlantReading read_vedirect(const Settings& s) {
    const auto ports = split_ports(s.serial_port);
    if (ports.empty()) throw SerialError(tr("Upišite COM port VE.Direct kabela, npr. COM3 (više uređaja: COM3, COM4)."));
    std::vector<VeBlock> blocks;
    std::string errors;
    for (const auto& p : ports) {
        try {
            SerialPort port(p, kVeDirectBaud, 500);
            const auto got = parse_vedirect(port.read_until(kVeListenMs, nullptr));
            if (got.empty()) errors += (errors.empty() ? "" : "; ") + tr("{port}: nema podataka", {{"port", p}});
            blocks.insert(blocks.end(), got.begin(), got.end());
        } catch (const SerialError& e) {
            errors += (errors.empty() ? "" : "; ") + std::string(e.what());
        }
    }
    if (blocks.empty()) throw SerialError(errors.empty() ? tr("VE.Direct uređaj ne šalje podatke.") : errors);
    const VeSummary sum = summarize_vedirect(blocks);
    PlantReading out;
    out.device_name = "Victron VE.Direct";
    out.reading.power_kw = sum.pv_w / 1000.0;
    out.reading.e_daily_kwh = sum.has_yield ? sum.today_kwh : -1;
    out.reading.e_total_kwh = sum.has_yield ? sum.total_kwh : -1;
    out.reading.status = out.reading.power_kw > 0 ? 1 : 0;
    out.extra = sum.extra;
    if (!errors.empty()) log_warn("VE.Direct: " + errors);
    return out;
}

}  // namespace sm

#include "sunspec.hpp"

#include <windows.h>

#include <cmath>
#include <cstring>
#include <map>
#include <mutex>

#include "i18n.hpp"
#include "net.hpp"
#include "poller.hpp"

namespace sm {

namespace {
constexpr uint16_t kMarker0 = 0x5375, kMarker1 = 0x6E53;  // "SunS"
constexpr uint16_t kBases[] = {40000, 0, 50000};
constexpr uint16_t kEndId = 0xFFFF;
constexpr int kMaxModels = 64;
constexpr uint16_t kMaxRead = 125;  // FC03
constexpr int kTimeoutMs = 8000;

// neimplementirane točke (SunSpec): int16 0x8000, uint16 0xFFFF, acc32 0, float NaN
constexpr uint16_t kNotI16 = 0x8000, kNotU16 = 0xFFFF;

double scaled(int16_t value, uint16_t sf_raw) {
    const auto sf = static_cast<int16_t>(sf_raw);
    if (static_cast<uint16_t>(value) == kNotI16 || sf_raw == kNotI16) return 0;
    return value * std::pow(10.0, sf);
}

double scaled_u32(uint32_t value, uint16_t sf_raw) {
    if (value == 0 || sf_raw == kNotI16) return 0;
    return value * std::pow(10.0, static_cast<int16_t>(sf_raw));
}

float f32(const std::vector<uint16_t>& d, size_t at) {
    const uint32_t bits = (static_cast<uint32_t>(d.at(at)) << 16) | d.at(at + 1);
    float f;
    std::memcpy(&f, &bits, 4);
    return std::isfinite(f) ? f : 0.0f;
}

uint32_t u32(const std::vector<uint16_t>& d, size_t at) { return (static_cast<uint32_t>(d.at(at)) << 16) | d.at(at + 1); }

// cos φ: SunSpec ga daje u postotcima (-100…100); neki uređaji ipak kao -1…1
double power_factor(double pf) { return std::fabs(pf) > 1.5 ? pf / 100.0 : pf; }

std::vector<uint16_t> read_block(const RegisterReader& read, uint16_t address, uint16_t count) {
    std::vector<uint16_t> out;
    out.reserve(count);
    while (count > 0) {
        const uint16_t n = std::min(count, kMaxRead);
        const auto part = read(address, n);
        out.insert(out.end(), part.begin(), part.end());
        address = static_cast<uint16_t>(address + n);
        count = static_cast<uint16_t>(count - n);
    }
    return out;
}

// Popis modela po uređaju (host:port/unit) – ne mijenja se, pa se ne traži pri svakom očitanju.
std::mutex g_cache_mutex;
std::map<std::string, std::vector<SunSpecModel>> g_cache;

std::vector<SunSpecModel> models_for(ModbusClient& client, const std::string& key, int unit) {
    {
        std::lock_guard lock(g_cache_mutex);
        if (auto it = g_cache.find(key); it != g_cache.end()) return it->second;
    }
    const auto models = sunspec_discover([&](uint16_t a, uint16_t n) { return client.read_registers(a, n, unit); });
    if (!models.empty()) {
        std::lock_guard lock(g_cache_mutex);
        g_cache[key] = models;
    }
    return models;
}

void forget_models(const std::string& key) {
    std::lock_guard lock(g_cache_mutex);
    g_cache.erase(key);
}
}  // namespace

std::vector<SunSpecModel> sunspec_discover(const RegisterReader& read) {
    for (const uint16_t base : kBases) {
        std::vector<uint16_t> marker;
        try {
            marker = read(base, 2);
        } catch (const ModbusError&) {
            continue;  // adresa ne postoji na ovom uređaju
        }
        if (marker.size() < 2 || marker[0] != kMarker0 || marker[1] != kMarker1) continue;
        std::vector<SunSpecModel> models;
        uint32_t at = base + 2u;
        for (int i = 0; i < kMaxModels && at + 2 <= 0xFFFF; ++i) {
            const auto head = read(static_cast<uint16_t>(at), 2);
            if (head.size() < 2 || head[0] == kEndId || head[0] == 0) break;
            models.push_back({head[0], head[1], static_cast<uint16_t>(at + 2)});
            at += 2u + head[1];
        }
        return models;
    }
    return {};
}

std::optional<SunSpecModel> sunspec_find(const std::vector<SunSpecModel>& models, uint16_t lo, uint16_t hi) {
    for (const auto& m : models) {
        if (m.id >= lo && m.id <= hi) return m;
    }
    return std::nullopt;
}

Reading sunspec_inverter(uint16_t model_id, const std::vector<uint16_t>& d) {
    Reading r;
    r.e_daily_kwh = -1;  // SunSpec nema dnevnu energiju
    if (model_id >= 101 && model_id <= 103) {
        // A(0) … W(12) W_SF(13) … PF(20) PF_SF(21) WH(22–23) WH_SF(24) … St(36)
        if (d.size() < 37) throw ModbusError(tr("Neočekivan odgovor uređaja."));
        r.power_kw = scaled(static_cast<int16_t>(d[12]), d[13]) / 1000.0;
        r.pf = power_factor(scaled(static_cast<int16_t>(d[20]), d[21]));
        r.e_total_kwh = scaled_u32(u32(d, 22), d[24]) / 1000.0;
        r.status = d[36] == kNotU16 ? 0 : d[36];
    } else if (model_id >= 111 && model_id <= 113) {
        // float32: A(0) … W(20) Hz(22) VA(24) VAr(26) PF(28) WH(30) … St(46)
        if (d.size() < 47) throw ModbusError(tr("Neočekivan odgovor uređaja."));
        r.power_kw = f32(d, 20) / 1000.0;
        r.pf = power_factor(f32(d, 28));
        r.e_total_kwh = f32(d, 30) / 1000.0;
        r.status = d[46] == kNotU16 ? 0 : d[46];
    } else {
        throw ModbusError(tr("Uređaj nema SunSpec model invertera."));
    }
    if (r.power_kw < 0) r.power_kw = 0;  // noću neki uređaji javljaju malu negativnu snagu (vlastita potrošnja)
    return r;
}

json sunspec_extras(uint16_t model_id, const std::vector<uint16_t>& d) {
    json x = json::object();
    auto put = [&](const char* key, double v, bool ok) { if (ok && std::isfinite(v) && v != 0) x[key] = v; };
    if (model_id >= 101 && model_id <= 103 && d.size() >= 37) {
        // PhVphA(8) V_SF(11), Hz(14) Hz_SF(15), TmpCab(31) Tmp_SF(35)
        put("grid_v", scaled(static_cast<int16_t>(d[8]), d[11]), d[8] != kNotU16 && d[8] != kNotI16);
        put("grid_hz", scaled(static_cast<int16_t>(d[14]), d[15]), d[14] != kNotU16 && d[14] != kNotI16);
        put("inverter_temp", scaled(static_cast<int16_t>(d[31]), d[35]), d[31] != kNotI16);
    } else if (model_id >= 111 && model_id <= 113 && d.size() >= 47) {
        put("grid_v", f32(d, 14), true);
        put("grid_hz", f32(d, 22), true);
        put("inverter_temp", f32(d, 38), true);
    }
    return x;
}

std::optional<double> sunspec_meter_w(uint16_t model_id, const std::vector<uint16_t>& d) {
    if (model_id >= 201 && model_id <= 204) {
        // A(0) AphA–C(1–3) A_SF(4) PhV…PPVphCA(5–12) V_SF(13) Hz(14) Hz_SF(15) W(16) WphA–C(17–19) W_SF(20)
        if (d.size() < 21 || d[16] == kNotI16) return std::nullopt;
        return scaled(static_cast<int16_t>(d[16]), d[20]);
    }
    if (model_id >= 211 && model_id <= 214) {
        // float32: A, AphA–C, PhV, PhVphA–C, PPV, PPVphAB–CA, Hz (0–25), W (26)
        if (d.size() < 28) return std::nullopt;
        return f32(d, 26);
    }
    return std::nullopt;
}

std::string sunspec_common_name(const std::vector<uint16_t>& d) {
    auto text = [&](size_t at, size_t words) {
        std::string s;
        for (size_t i = at; i < at + words && i < d.size(); ++i) {
            for (const char c : {static_cast<char>(d[i] >> 8), static_cast<char>(d[i] & 0xFF)}) {
                if (c >= 32 && c < 127) s += c;
            }
        }
        while (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    };
    const std::string mn = text(0, 16), md = text(16, 16);  // Mn(0–15), Md(16–31)
    return md.empty() ? mn : mn.empty() ? md : mn + " " + md;
}

PlantReading read_sunspec(const Settings& s) {
    const auto units = parse_units(s.inverter_units);
    if (!units) throw std::runtime_error(tr("Upišite adrese invertera odvojene zarezom, npr. 1 ili 1,2,3 (0–247, najviše 10)."));
    const auto src = source_ip(s.logger_interface);
    ModbusClient client(s.modbus_host, s.modbus_port, units->front(), src.value_or(""), kTimeoutMs, "SunSpec");
    client.connect();
    const std::string base = s.modbus_host + ":" + std::to_string(s.modbus_port) + "/";
    PlantReading out;
    for (size_t i = 0; i < units->size(); ++i) {
        const int unit = (*units)[i];
        const std::string key = base + std::to_string(unit);
        try {
            const auto models = models_for(client, key, unit);
            if (models.empty()) {
                throw ModbusError(tr("Na adresi {unit} nema SunSpec podataka – uključite SunSpec Modbus na uređaju.",
                                     {{"unit", std::to_string(unit)}}));
            }
            const auto inv = sunspec_find(models, 101, 113);
            if (!inv || (inv->id > 103 && inv->id < 111)) throw ModbusError(tr("Uređaj nema SunSpec model invertera."));
            const auto data = read_block([&](uint16_t a, uint16_t n) { return client.read_registers(a, n, unit); },
                                         inv->address, inv->length);
            const Reading r = sunspec_inverter(inv->id, data);
            if (i == 0) out.extra = sunspec_extras(inv->id, data);
            out.reading.power_kw += r.power_kw;
            out.reading.e_total_kwh += r.e_total_kwh;
            if (i == 0) {
                out.reading.pf = r.pf;
                out.reading.status = r.status;
                if (const auto common = sunspec_find(models, 1, 1)) {
                    out.device_name = sunspec_common_name(read_block([&](uint16_t a, uint16_t n) {
                        return client.read_registers(a, n, unit);
                    }, common->address, std::min<uint16_t>(common->length, 32)));
                }
            }
        } catch (const ModbusError&) {
            forget_models(key);  // npr. promijenjen firmware – sljedeći put iznova
            throw;
        }
    }
    out.reading.e_daily_kwh = -1;
    if (s.meter_unit_id) {
        const std::string key = base + std::to_string(s.meter_unit_id);
        try {  // greška mjerača ne poništava očitanje elektrane
            const auto models = models_for(client, key, s.meter_unit_id);
            const auto meter = sunspec_find(models, 201, 214);
            if (!meter || (meter->id > 204 && meter->id < 211)) throw ModbusError(tr("Na toj adresi nema SunSpec mjerača."));
            const auto w = sunspec_meter_w(meter->id, read_block([&](uint16_t a, uint16_t n) {
                return client.read_registers(a, n, s.meter_unit_id);
            }, meter->address, meter->length));
            if (!w) throw ModbusError(tr("Mjerač ne daje ukupnu snagu."));
            // load_kw: pozitivno = uzimanje iz mreže
            out.load_kw = (s.meter_export_positive ? -*w : *w) / 1000.0;
        } catch (const ModbusError& e) {
            forget_models(key);
            out.meter_error = e.what();
        }
    }
    return out;
}

}  // namespace sm

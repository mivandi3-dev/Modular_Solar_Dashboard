// Simulacijski testovi uređaja, drugi dio (4.0): integracije koje do sada nisu imale test razine S.
//
// Razina S = simulirani uređaj na 127.0.0.1, cijeli put read_plant(Settings) → prijenos → simulator → dekodiranje.
// Razina P = okvir zahtjeva i dekodiranje odgovora kroz javne funkcije drivera (bez prijenosa); koristi se samo
// gdje prijenos (COM port, USB HID) nije moguće zamijeniti bez izmjene produkcijskog koda.
// NIJE dokaz rada sa stvarnim uređajem. Očekivane vrijednosti su ručno izračunate iz tablica registara u
// src/vendors.cpp (adresa, vrsta, skaliranje, redoslijed riječi) i iz src/offgrid.cpp – ne iz rezultata.
//
// Pomoćnici (FakeRegisters, LocalServer, rtu_answer, solarman_response…) su kopije iz test_main.cpp (anonimni
// namespace), proširene: LocalServer i UDP uređaj mogu slušati na zadanom portu (8899), simulator vraća
// Modbus iznimku 0x02 za nepostojeće registre i bilježi zahtjeve.
#include <doctest/doctest.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <functional>
#include <map>
#include <mutex>
#include <thread>

#include <winsock2.h>

#include "config.hpp"
#include "modbus.hpp"
#include "net.hpp"
#include "offgrid.hpp"
#include "poller.hpp"
#include "serial.hpp"
#include "vendors.hpp"

using namespace sm;

namespace {

constexpr int kVendorPort8899 = 8899;  // Solarman V5 i GoodWe UDP: read_vendor ih bira samo na portu 8899
constexpr uint32_t kLoggerSerial = 2712345678u;

// ---------------------------------------------------------------- simulirani registri
struct FakeRegisters {
    std::map<uint16_t, uint16_t> regs;
    std::vector<uint16_t> read(uint16_t a, uint16_t n) const {
        std::vector<uint16_t> out;
        for (uint16_t i = 0; i < n; ++i) {
            const auto it = regs.find(static_cast<uint16_t>(a + i));
            if (it == regs.end()) throw ModbusError("illegal data address");
            out.push_back(it->second);
        }
        return out;
    }
};

void fill(FakeRegisters& f, uint16_t from, uint16_t to) {
    for (uint32_t a = from; a <= to; ++a) if (!f.regs.count(static_cast<uint16_t>(a))) f.regs[static_cast<uint16_t>(a)] = 0;
}
void put32(FakeRegisters& f, uint16_t hi_addr, uint16_t lo_addr, uint32_t v) {
    f.regs[hi_addr] = static_cast<uint16_t>(v >> 16);
    f.regs[lo_addr] = static_cast<uint16_t>(v & 0xFFFF);
}

struct Request {
    int unit;
    uint8_t fc;
    uint16_t address, count;
};

// ---------------------------------------------------------------- Modbus RTU okviri
std::vector<uint8_t> with_crc(std::vector<uint8_t> r) {
    const uint16_t crc = modbus_crc(r.data(), r.size());
    r.push_back(static_cast<uint8_t>(crc));
    r.push_back(static_cast<uint8_t>(crc >> 8));
    return r;
}

std::vector<uint8_t> rtu_answer(int unit, uint8_t fc, const std::vector<uint16_t>& words) {
    std::vector<uint8_t> r = {static_cast<uint8_t>(unit), fc, static_cast<uint8_t>(words.size() * 2)};
    for (uint16_t w : words) {
        r.push_back(static_cast<uint8_t>(w >> 8));
        r.push_back(static_cast<uint8_t>(w));
    }
    return with_crc(r);
}

std::vector<uint8_t> rtu_exception(int unit, uint8_t fc) {
    return with_crc({static_cast<uint8_t>(unit), static_cast<uint8_t>(fc | 0x80), 0x02});
}

// Simulirani RTU uređaj: zahtjev (8 bajtova s CRC-om) → odgovor; krivi CRC → nema odgovora (prazno), drugi unit ili
// funkcija ili nepostojeći registar → iznimka 0x02. Zahtjev se bilježi.
std::vector<uint8_t> rtu_device(const uint8_t* req, size_t n, int unit, uint8_t fc, const FakeRegisters& dev,
                                std::vector<Request>* log = nullptr) {
    if (n != 8 || modbus_crc(req, 6) != (req[6] | (req[7] << 8))) return {};
    const Request r{req[0], req[1], static_cast<uint16_t>((req[2] << 8) | req[3]), static_cast<uint16_t>((req[4] << 8) | req[5])};
    if (log) log->push_back(r);
    if (r.unit != unit || r.fc != fc) return rtu_exception(r.unit, r.fc);
    try {
        return rtu_answer(r.unit, r.fc, dev.read(r.address, r.count));
    } catch (const ModbusError&) {
        return rtu_exception(r.unit, r.fc);
    }
}

std::vector<uint8_t> solarman_response(uint32_t serial, uint8_t seq, const std::vector<uint8_t>& rtu) {
    const uint16_t length = static_cast<uint16_t>(14 + rtu.size());
    std::vector<uint8_t> f = {0xA5, static_cast<uint8_t>(length), static_cast<uint8_t>(length >> 8), 0x10, 0x15, seq, 0,
                              static_cast<uint8_t>(serial), static_cast<uint8_t>(serial >> 8), static_cast<uint8_t>(serial >> 16),
                              static_cast<uint8_t>(serial >> 24), 0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    f.insert(f.end(), rtu.begin(), rtu.end());
    uint8_t sum = 0;
    for (size_t i = 1; i < f.size(); ++i) sum = static_cast<uint8_t>(sum + f[i]);
    f.push_back(sum);
    f.push_back(0x15);
    return f;
}

// ---------------------------------------------------------------- TCP poslužitelj (kopija iz test_main.cpp + zadani port)
class LocalServer {
public:
    using Handler = std::function<void(SOCKET)>;
    explicit LocalServer(Handler handler, int port = 0) : handler_(std::move(handler)) {
        listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<u_short>(port));
        if (bind(listener_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0 || listen(listener_, 8) != 0) {
            closesocket(listener_);
            listener_ = INVALID_SOCKET;
            return;
        }
        int len = sizeof a;
        getsockname(listener_, reinterpret_cast<sockaddr*>(&a), &len);
        port_ = ntohs(a.sin_port);
        thread_ = std::thread([this] {
            for (;;) {
                SOCKET c = accept(listener_, nullptr, nullptr);
                if (c == INVALID_SOCKET) return;
                ++connections_;
                handler_(c);
                closesocket(c);
            }
        });
    }
    ~LocalServer() {
        if (listener_ != INVALID_SOCKET) closesocket(listener_);
        if (thread_.joinable()) thread_.join();
    }
    bool ok() const { return port_ != 0; }
    int port() const { return port_; }
    int connections() const { return connections_; }

private:
    Handler handler_;
    SOCKET listener_ = INVALID_SOCKET;
    std::thread thread_;
    int port_ = 0;
    std::atomic<int> connections_{0};
};

bool recv_n(SOCKET s, char* buf, int n) {
    for (int got = 0; got < n;) {
        const int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

// Solarman V5 logger (TCP): prije svakog odgovora pošalje i svoj okvir (otkucaj 0x47), kao stvarni logger.
// Logger s drugim serijskim brojem ne odgovara (zatvara vezu).
void serve_solarman(SOCKET c, uint32_t serial, int unit, uint8_t fc, const FakeRegisters& dev, std::vector<Request>& log,
                    std::mutex& m) {
    for (;;) {
        unsigned char head[3];
        if (!recv_n(c, reinterpret_cast<char*>(head), 3)) return;
        std::vector<uint8_t> f(13u + (head[1] | (head[2] << 8)));
        std::memcpy(f.data(), head, 3);
        if (!recv_n(c, reinterpret_cast<char*>(f.data() + 3), static_cast<int>(f.size() - 3))) return;
        const uint32_t got = f[7] | (f[8] << 8) | (f[9] << 16) | (static_cast<uint32_t>(f[10]) << 24);
        if (f[0] != 0xA5 || f[4] != 0x45 || got != serial || f.size() < 28) return;
        const auto heartbeat = std::vector<uint8_t>{0xA5, 0x01, 0x00, 0x10, 0x47, 0x00, 0x00, f[7], f[8], f[9], f[10], 0x00,
                                                    static_cast<uint8_t>(0x01 + 0x10 + 0x47 + f[7] + f[8] + f[9] + f[10]), 0x15};
        send(c, reinterpret_cast<const char*>(heartbeat.data()), static_cast<int>(heartbeat.size()), 0);
        std::vector<uint8_t> rtu;
        {
            std::lock_guard<std::mutex> lock(m);
            rtu = rtu_device(f.data() + 26, f.size() - 28, unit, fc, dev, &log);
        }
        if (rtu.empty()) return;
        const auto resp = solarman_response(got, f[5], rtu);
        send(c, reinterpret_cast<const char*>(resp.data()), static_cast<int>(resp.size()), 0);
    }
}

// ---------------------------------------------------------------- UDP uređaj (GoodWe Wi-Fi/LAN modul)
class UdpDevice {
public:
    using Respond = std::function<std::vector<uint8_t>(const uint8_t*, size_t)>;
    UdpDevice(int port, Respond respond) : respond_(std::move(respond)) {
        sock_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        BOOL exclusive = TRUE;
        setsockopt(sock_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof exclusive);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<u_short>(port));
        if (bind(sock_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) {
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
            return;
        }
        const DWORD t = 200;
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof t);
        ok_ = true;
        thread_ = std::thread([this] {
            while (!stop_) {
                unsigned char buf[600];
                sockaddr_in from{};
                int flen = sizeof from;
                const int n = recvfrom(sock_, reinterpret_cast<char*>(buf), sizeof buf, 0, reinterpret_cast<sockaddr*>(&from), &flen);
                if (n <= 0) continue;
                const auto resp = respond_(buf, static_cast<size_t>(n));
                if (!resp.empty()) {
                    sendto(sock_, reinterpret_cast<const char*>(resp.data()), static_cast<int>(resp.size()), 0,
                           reinterpret_cast<sockaddr*>(&from), flen);
                }
            }
        });
    }
    ~UdpDevice() {
        stop_ = true;
        if (thread_.joinable()) thread_.join();
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
    }
    bool ok() const { return ok_; }

private:
    Respond respond_;
    SOCKET sock_ = INVALID_SOCKET;
    std::atomic<bool> stop_{false};
    bool ok_ = false;
    std::thread thread_;
};

// GoodWe: odgovor = AA 55 + Modbus RTU odgovor
UdpDevice::Respond goodwe_device(int unit, const FakeRegisters& dev, std::vector<Request>& log, std::mutex& m) {
    return [unit, &dev, &log, &m](const uint8_t* req, size_t n) {
        std::lock_guard<std::mutex> lock(m);
        const auto rtu = rtu_device(req, n, unit, 3, dev, &log);
        if (rtu.empty()) return rtu;
        std::vector<uint8_t> out = {0xAA, 0x55};
        out.insert(out.end(), rtu.begin(), rtu.end());
        return out;
    };
}

Settings vendor_settings(const char* profile, int port, const char* units) {
    Settings s;
    s.device_type = "vendor";
    s.device_profile = profile;
    s.modbus_host = "127.0.0.1";
    s.modbus_port = port;
    s.logger_interface = "";
    s.inverter_units = units;
    s.meter_unit_id = 1;
    return s;
}

// Stroža usporedba od zadane (doctest::Approx dopušta ~1e-5 relativno, npr. ±1,5 kWh na 123.456,7)
doctest::Approx tight(double v) { return doctest::Approx(v).epsilon(1e-9); }

double x(const PlantReading& p, const char* key) { return p.extra.at(key).get<double>(); }

bool all_requests(const std::vector<Request>& log, int unit, uint8_t fc) {
    return !log.empty() && std::all_of(log.begin(), log.end(), [&](const Request& r) { return r.unit == unit && r.fc == fc; });
}

bool requested(const std::vector<Request>& log, uint16_t address, uint16_t count) {
    return std::any_of(log.begin(), log.end(), [&](const Request& r) { return r.address == address && r.count == count; });
}

// ---------------------------------------------------------------- razina P: serijski Modbus RTU bez COM porta
// Isti koraci kao read_vendor → read_points → rtu_serial_read, ali okvir ide u simulator umjesto na COM port:
// adrese točaka (lo + hi) → vendor_ranges → rtu_read_request → simulator → parse_rtu_response → (adresa, riječ).
std::vector<std::pair<uint16_t, uint16_t>> rtu_p_read(const VendorProfile& prof, int unit, const FakeRegisters& dev,
                                                      const std::vector<const VendorPoint*>& points, std::vector<Request>& log) {
    std::vector<uint16_t> addresses;
    for (const auto* p : points) {
        addresses.push_back(p->lo);
        if (p->wide) addresses.push_back(p->hi);
    }
    std::vector<std::pair<uint16_t, uint16_t>> regs;
    for (const auto& [start, count] : vendor_ranges(addresses)) {
        const auto req = rtu_read_request(unit, prof.fc, start, count);
        const auto resp = rtu_device(req.data(), req.size(), unit, prof.fc, dev, &log);
        REQUIRE_FALSE(resp.empty());  // CRC zahtjeva je ispravan
        const auto words = parse_rtu_response(resp.data(), resp.size(), prof.fc, count);
        for (uint16_t i = 0; i < count; ++i) regs.emplace_back(static_cast<uint16_t>(start + i), words[i]);
    }
    return regs;
}

const VendorPoint& extra_point(const VendorProfile& prof, const char* key) {
    for (const auto& [k, p] : prof.extras) if (std::string(k) == key) return p;
    throw std::runtime_error(std::string("nema točke ") + key);
}

// COM port koji na ovom računalu sigurno ne postoji (za provjeru da read_plant ide na COM port, ne na mrežu)
std::string missing_com_port() {
    const auto ports = list_serial_ports();
    for (int i = 256; i > 200; --i) {
        const std::string name = "COM" + std::to_string(i);
        if (std::find(ports.begin(), ports.end(), name) == ports.end()) return name;
    }
    return "COM256";
}

}  // namespace

// ================================================================ 1. GoodWe ET / EH / BT – GoodWe UDP, cijeli put
TEST_CASE("[device][vendor][S] GW-ET: GoodWe ET/EH/BT preko GoodWe UDP-a (127.0.0.1:8899) – snaga, energije, mjerač, baterija") {
    NetInit net;
    // Tablica (vendors.cpp, goodwe_et): FC03, unit 0xF7, sve 32-bitne vrijednosti viša riječ prva (u32be(a): hi=a, lo=a+1)
    //   snaga  = PV1 u32be(35105) + PV2 u32be(35109) + PV3 u32be(35113) + PV4 u32be(35117)   [W]
    //   danas  = u32be(35193) × 0,1 kWh, ukupno = u32be(35191) × 0,1 kWh
    //   mjerač = s16(35140) W, meter_import_positive = false → load_kw = −w / 1000
    //   dodaci: inverter_temp s16(35176)×0,1; grid_v u16(35121)×0,1; grid_hz u16(35123)×0,01; battery_soc u16(37007);
    //           battery_w s32be(35182) (hi 35182, lo 35183), battery_sign −1 → battery_kw = −w / 1000
    FakeRegisters f;
    fill(f, 35100, 35200);
    fill(f, 37000, 37010);
    put32(f, 35105, 35106, 2000);                              // PV1 2.000 W
    put32(f, 35109, 35110, 1500);                              // PV2 1.500 W
    put32(f, 35113, 35114, 500);                               // PV3   500 W
    put32(f, 35117, 35118, 0);                                 // PV4     0 W  → 4,0 kW
    put32(f, 35193, 35194, 256);                               // danas 25,6 kWh
    put32(f, 35191, 35192, 1234567);                           // ukupno 0x0012:D687 → 123.456,7 kWh (viša riječ ≠ 0)
    f.regs[35140] = static_cast<uint16_t>(-800);               // mjerač −800 W → load_kw = +0,8
    f.regs[35176] = static_cast<uint16_t>(-52);                // −5,2 °C (s16)
    f.regs[35121] = 2315;                                      // 231,5 V
    f.regs[35123] = 5002;                                      // 50,02 Hz
    f.regs[37007] = 76;                                        // SOC 76 %
    put32(f, 35182, 35183, static_cast<uint32_t>(-1500));      // pbattery −1.500 W (< 0 = punjenje) → battery_kw = +1,5
    std::vector<Request> log;
    std::mutex m;
    UdpDevice dev(kVendorPort8899, goodwe_device(0xF7, f, log, m));
    REQUIRE_MESSAGE(dev.ok(), "UDP 127.0.0.1:8899 nije slobodan – razina S za GoodWe nije moguća na ovom računalu");
    Settings s = vendor_settings("goodwe_et", kVendorPort8899, "247");
    const PlantReading p = read_plant(s);
    CHECK(p.device_name == "GoodWe ET / EH / BT");
    CHECK(p.reading.power_kw == tight(4.0));
    CHECK(p.reading.e_daily_kwh == tight(25.6));
    CHECK(p.reading.e_total_kwh == tight(123456.7));
    CHECK(p.reading.status == 1);
    REQUIRE(p.load_kw);
    CHECK(*p.load_kw == tight(0.8));
    CHECK(p.meter_error.empty());
    CHECK(x(p, "inverter_temp") == tight(-5.2));
    CHECK(x(p, "grid_v") == tight(231.5));
    CHECK(x(p, "grid_hz") == tight(50.02));
    CHECK(x(p, "battery_soc") == tight(76.0));
    CHECK(x(p, "battery_kw") == tight(1.5));
    CHECK(p.extra.at("battery_dir") == true);
    {
        std::lock_guard<std::mutex> lock(m);
        CHECK(all_requests(log, 0xF7, 3));                     // RTU okvir: unit 0xF7, FC03, CRC ispravan (inače bez odgovora)
        CHECK(requested(log, 35105, 14));                      // PV1–PV4 u jednom zahtjevu
        CHECK(requested(log, 35191, 4));                       // ukupno + danas
        CHECK(requested(log, 35140, 1));                       // mjerač
    }
    s.meter_invert = true;                                     // obrnuti predznak mjerača
    const PlantReading q = read_plant(s);
    REQUIRE(q.load_kw);
    CHECK(*q.load_kw == tight(-0.8));

    // hibrid bez baterije: 37007 ne postoji → skupno čitanje dodataka ne uspije, pojedinačno se preskače samo baterija
    FakeRegisters nb = f;
    nb.regs.erase(37007);
    {
        std::lock_guard<std::mutex> lock(m);
        f = nb;                                                // isti simulator, tablica bez SOC-a
    }
    s.meter_invert = false;
    const PlantReading r = read_plant(s);
    CHECK(r.reading.power_kw == tight(4.0));
    CHECK(x(r, "inverter_temp") == tight(-5.2));
    CHECK_FALSE(r.extra.contains("battery_soc"));
    CHECK_FALSE(r.extra.contains("battery_kw"));
}

// ================================================================ 2. GoodWe DT / SDT / SMT – GoodWe UDP, cijeli put
TEST_CASE("[device][vendor][S] GW-DT: GoodWe DT/SDT/SMT preko GoodWe UDP-a (127.0.0.1:8899) – snaga, energije, mjerač") {
    NetInit net;
    // Tablica (goodwe_dt): FC03, unit 0x7F; snaga u32be(30127) (hi 30127, lo 30128) W; danas u16(30144)×0,1 kWh;
    // ukupno u32be(30145)×0,1 kWh (hi 30145, lo 30146); mjerač s32be(30195) (hi 30195, lo 30196), import_positive = false;
    // bez dodataka (extras prazno)
    FakeRegisters f;
    fill(f, 30100, 30200);
    put32(f, 30127, 30128, 80000);                             // 0x0001:3880 → 80.000 W = 80,0 kW
    f.regs[30144] = 412;                                       // 41,2 kWh
    put32(f, 30145, 30146, 987654);                            // 0x000F:1206 → 98.765,4 kWh
    put32(f, 30195, 30196, static_cast<uint32_t>(-2500));      // mjerač −2.500 W → load_kw = +2,5
    std::vector<Request> log;
    std::mutex m;
    UdpDevice dev(kVendorPort8899, goodwe_device(0x7F, f, log, m));
    REQUIRE_MESSAGE(dev.ok(), "UDP 127.0.0.1:8899 nije slobodan – razina S za GoodWe nije moguća na ovom računalu");
    Settings s = vendor_settings("goodwe_dt", kVendorPort8899, "127");
    const PlantReading p = read_plant(s);
    CHECK(p.device_name == "GoodWe DT / SDT / SMT");
    CHECK(p.reading.power_kw == tight(80.0));
    CHECK(p.reading.e_daily_kwh == tight(41.2));
    CHECK(p.reading.e_total_kwh == tight(98765.4));
    CHECK(p.reading.status == 1);
    REQUIRE(p.load_kw);
    CHECK(*p.load_kw == tight(2.5));
    CHECK(p.extra.empty());
    {
        std::lock_guard<std::mutex> lock(m);
        CHECK(all_requests(log, 0x7F, 3));
        CHECK(requested(log, 30127, 2));
        CHECK(requested(log, 30144, 3));
        CHECK(requested(log, 30195, 2));
    }
    // noću: snaga 0 → stanje 0; bez mjerača (meter_unit_id 0) nema load_kw
    {
        std::lock_guard<std::mutex> lock(m);
        put32(f, 30127, 30128, 0);
    }
    s.meter_unit_id = 0;                                       // bez mjerača
    const PlantReading n = read_plant(s);
    CHECK(n.reading.power_kw == tight(0.0));
    CHECK(n.reading.status == 0);
    CHECK_FALSE(n.load_kw);
}

// ================================================================ 3. Deye SUN-K-G – Solarman V5, cijeli put
TEST_CASE("[device][vendor][S] DY-STR: Deye SUN-K-G preko Solarman V5 (127.0.0.1:8899) – snaga, energije, mjerač, dodaci") {
    NetInit net;
    // Tablica (deye_string): FC03, unit 1, 32 bita niža riječ prva (u32(lo, hi));
    //   snaga u32(0x56, 0x57) × 0,1 W; danas u16(0x3C) × 0,1 kWh; ukupno u32(0x3F, 0x40) × 0,1 kWh;
    //   mjerač s32(0xCB, 0xCC) W, import_positive = true → load_kw = +w / 1000;
    //   dodaci: inverter_temp (u16(0x5B) − 1000) × 0,1; grid_v u16(0x49) × 0,1; grid_hz u16(0x4F) × 0,01; bez baterije
    FakeRegisters f;
    fill(f, 0x00, 0x100);
    put32(f, 0x57, 0x56, 70000);                               // lo 0x56 = 0x1170, hi 0x57 = 0x0001 → 7.000,0 W
    f.regs[0x3C] = 187;                                        // 18,7 kWh
    put32(f, 0x40, 0x3F, 765432);                              // lo 0x3F = 0xADF8, hi 0x40 = 0x000B → 76.543,2 kWh
    put32(f, 0xCC, 0xCB, static_cast<uint32_t>(-1200));        // −1.200 W (predaja) → load_kw = −1,2
    f.regs[0x5B] = 1385;                                       // (1385 − 1000) × 0,1 = 38,5 °C
    f.regs[0x49] = 2298;                                       // 229,8 V
    f.regs[0x4F] = 4999;                                       // 49,99 Hz
    std::vector<Request> log;
    std::mutex m;
    LocalServer logger([&](SOCKET c) { serve_solarman(c, kLoggerSerial, 1, 3, f, log, m); }, kVendorPort8899);
    REQUIRE_MESSAGE(logger.ok(), "TCP 127.0.0.1:8899 nije slobodan – razina S za Solarman nije moguća na ovom računalu");
    Settings s = vendor_settings("deye_string", kVendorPort8899, "1");
    s.logger_serial = "2712345678";
    const PlantReading p = read_plant(s);
    CHECK(p.device_name == "Deye SUN-K-G");
    CHECK(p.reading.power_kw == tight(7.0));
    CHECK(p.reading.e_daily_kwh == tight(18.7));
    CHECK(p.reading.e_total_kwh == tight(76543.2));
    CHECK(p.reading.status == 1);
    REQUIRE(p.load_kw);
    CHECK(*p.load_kw == tight(-1.2));
    CHECK(x(p, "inverter_temp") == tight(38.5));
    CHECK(x(p, "grid_v") == tight(229.8));
    CHECK(x(p, "grid_hz") == tight(49.99));
    CHECK_FALSE(p.extra.contains("battery_soc"));
    CHECK_FALSE(p.extra.contains("battery_kw"));
    {
        std::lock_guard<std::mutex> lock(m);
        CHECK(all_requests(log, 1, 3));
        CHECK(requested(log, 0x3C, 5));                        // danas 0x3C + ukupno 0x3F–0x40 u jednom zahtjevu
        CHECK(requested(log, 0x56, 2));
        CHECK(requested(log, 0xCB, 2));
    }
    // pogrešan serijski broj loggera: logger ne odgovara → greška s uputom o serijskom broju (ne visi dulje od roka)
    s.logger_serial = "2712345679";
    s.meter_unit_id = 0;
    CHECK_THROWS_WITH(read_plant(s), doctest::Contains("serijski"));
}

// ================================================================ 4. Deye / Sunsynk 3~ – Solarman V5, cijeli put
TEST_CASE("[device][vendor][S] DY-HY3: Deye/Sunsynk SG04LP3/HP3 preko Solarman V5 (127.0.0.1:8899) – PV, ukupno, razdvojeni mjerač, baterija") {
    NetInit net;
    // Tablica (deye_hybrid3): FC03, unit 1; snaga = u16(0x2A0) + u16(0x2A1) + u16(0x2A2) + u16(0x2A3) W; danas nema
    // (e_daily_kwh = −1, računa poller); ukupno u32(0x216, 0x217) × 0,1 kWh; mjerač s32(0x271, 0x2B2) – niža riječ
    // 0x271, viša 0x2B2 (razdvojeni registri), import_positive = true;
    // dodaci: inverter_temp (u16(0x21D) − 1000) × 0,1; grid_v u16(0x256) × 0,1; grid_hz u16(0x261) × 0,01;
    //         battery_soc u16(0x24C); battery_w s16(0x24E), battery_sign −1 → battery_kw = −w / 1000
    FakeRegisters f;
    fill(f, 0x200, 0x2C0);
    f.regs[0x2A0] = 2100;
    f.regs[0x2A1] = 1900;                                      // PV 4.000 W → 4,0 kW
    put32(f, 0x217, 0x216, 234567);                            // lo 0x216 = 0x9447, hi 0x217 = 0x0003 → 23.456,7 kWh
    put32(f, 0x2B2, 0x271, static_cast<uint32_t>(-3000));      // lo 0x271 = 0xF448, hi 0x2B2 = 0xFFFF → −3.000 W → −3,0
    f.regs[0x21D] = 1250;                                      // 25,0 °C
    f.regs[0x256] = 2341;                                      // 234,1 V
    f.regs[0x261] = 5001;                                      // 50,01 Hz
    f.regs[0x24C] = 63;                                        // SOC 63 %
    f.regs[0x24E] = static_cast<uint16_t>(-2000);              // −2.000 W (< 0 = punjenje) → battery_kw = +2,0
    std::vector<Request> log;
    std::mutex m;
    LocalServer logger([&](SOCKET c) { serve_solarman(c, kLoggerSerial, 1, 3, f, log, m); }, kVendorPort8899);
    REQUIRE_MESSAGE(logger.ok(), "TCP 127.0.0.1:8899 nije slobodan – razina S za Solarman nije moguća na ovom računalu");
    Settings s = vendor_settings("deye_hybrid3", kVendorPort8899, "1");
    s.logger_serial = "2712345678";
    const PlantReading p = read_plant(s);
    CHECK(p.device_name == "Deye / Sunsynk SG04LP3 / HP3 (3~)");
    CHECK(p.reading.power_kw == tight(4.0));
    CHECK(p.reading.e_daily_kwh < 0);
    CHECK(p.reading.e_total_kwh == tight(23456.7));
    REQUIRE(p.load_kw);
    CHECK(*p.load_kw == tight(-3.0));
    CHECK(x(p, "inverter_temp") == tight(25.0));
    CHECK(x(p, "grid_v") == tight(234.1));
    CHECK(x(p, "grid_hz") == tight(50.01));
    CHECK(x(p, "battery_soc") == tight(63.0));
    CHECK(x(p, "battery_kw") == tight(2.0));
    CHECK(p.extra.at("battery_dir") == true);
    {
        std::lock_guard<std::mutex> lock(m);
        CHECK(all_requests(log, 1, 3));
        CHECK(requested(log, 0x2A0, 4));
        CHECK(requested(log, 0x216, 2));
        CHECK(requested(log, 0x271, 1));                       // razdvojeni mjerač: dva zahtjeva
        CHECK(requested(log, 0x2B2, 1));
    }
}

// ================================================================ 5.–7. serijski Modbus RTU (Growatt SPF, EPEver, SRNE)
// read_vendor za VendorLink::Serial uvijek otvara SerialPort("\\.\COMn") (CreateFileW + SetCommState) i čita s
// rtu_serial_read(SerialPort&, …). SerialPort nema sučelje ni zamjenu, a vrsta veze ovisi samo o profilu – zato
// ovdje: (a) provjera da read_plant ide na COM port, a ne na mrežu, (b) razina P za okvir i dekodiranje.
TEST_CASE("[device][vendor][P] serijski profili: read_plant ide na COM port, ne na mrežu (Growatt SPF, EPEver, SRNE)") {
    NetInit net;
    LocalServer tcp([](SOCKET) {});                            // mamac: ako bi driver pao na Modbus TCP, ovdje bi se spojio
    REQUIRE(tcp.ok());
    const std::string com = missing_com_port();
    for (const char* key : {"growatt_spf", "epever", "srne"}) {
        INFO(key);
        Settings s = vendor_settings(key, tcp.port(), "1");
        s.serial_port = "";
        CHECK_THROWS_WITH(read_plant(s), doctest::Contains("serijski port"));
        s.serial_port = com;
        CHECK_THROWS_WITH(read_plant(s), doctest::Contains(com.c_str()));
    }
    CHECK(tcp.connections() == 0);
}

TEST_CASE("[device][vendor][P] SPF: Growatt SPF – RTU okvir (FC04) i dekodiranje prema tablici") {
    // Tablica (growatt_spf): FC04, unit 1, 32 bita viša riječ prva; snaga u32be(3) × 0,1 W; danas u32be(48) × 0,1 kWh;
    // ukupno u32be(50) × 0,1 kWh; dodaci: battery_soc u16(18); battery_w s32be(77) × 0,1 (battery_sign −1);
    // battery_v u16(17) × 0,01; inverter_temp u16(25) × 0,1; grid_v u16(20) × 0,1; grid_hz u16(21) × 0,01;
    // ac_out_v u16(22) × 0,1; ac_out_hz u16(23) × 0,01; ac_load_w u32be(9) × 0,1; load_pct u16(27) × 0,1
    const VendorProfile& prof = *find_vendor("growatt_spf");
    REQUIRE(prof.fc == 4);
    REQUIRE(prof.link == VendorLink::Serial);
    FakeRegisters f;
    fill(f, 0, 100);
    put32(f, 3, 4, 45000);                                     // 4.500,0 W
    put32(f, 48, 49, 123);                                     // 12,3 kWh
    put32(f, 50, 51, 87654);                                   // 0x0001:5666 → 8.765,4 kWh
    f.regs[18] = 88;
    put32(f, 77, 78, static_cast<uint32_t>(-12345));           // −1.234,5 W
    f.regs[17] = 5260;                                         // 52,60 V
    f.regs[25] = 412;                                          // 41,2 °C
    f.regs[20] = 2302;                                         // 230,2 V
    f.regs[21] = 5000;                                         // 50,00 Hz
    f.regs[22] = 2300;                                         // 230,0 V
    f.regs[23] = 4998;                                         // 49,98 Hz
    put32(f, 9, 10, 15000);                                    // 1.500,0 W
    f.regs[27] = 253;                                          // 25,3 %
    std::vector<Request> log;
    std::vector<const VendorPoint*> main_points;
    for (const auto& p : prof.power) main_points.push_back(&p);
    main_points.push_back(&*prof.today);
    main_points.push_back(&*prof.total);
    const auto regs = rtu_p_read(prof, 1, f, main_points, log);
    double power = 0;
    for (const auto& p : prof.power) power += vendor_value(p, regs);
    CHECK(power == tight(4500.0));
    CHECK(vendor_value(*prof.today, regs) == tight(12.3));
    CHECK(vendor_value(*prof.total, regs) == tight(8765.4));
    std::vector<const VendorPoint*> extras;
    for (const auto& [k, p] : prof.extras) extras.push_back(&p);
    const auto xr = rtu_p_read(prof, 1, f, extras, log);
    CHECK(vendor_value(extra_point(prof, "battery_soc"), xr) == tight(88.0));
    CHECK(vendor_value(extra_point(prof, "battery_w"), xr) == tight(-1234.5));
    CHECK(prof.battery_sign == -1);                            // read_extras: battery_kw = +1,2345 (punjenje) – nije izvršeno
    CHECK(vendor_value(extra_point(prof, "battery_v"), xr) == tight(52.6));
    CHECK(vendor_value(extra_point(prof, "inverter_temp"), xr) == tight(41.2));
    CHECK(vendor_value(extra_point(prof, "grid_v"), xr) == tight(230.2));
    CHECK(vendor_value(extra_point(prof, "grid_hz"), xr) == tight(50.0));
    CHECK(vendor_value(extra_point(prof, "ac_out_v"), xr) == tight(230.0));
    CHECK(vendor_value(extra_point(prof, "ac_out_hz"), xr) == tight(49.98));
    CHECK(vendor_value(extra_point(prof, "ac_load_w"), xr) == tight(1500.0));
    CHECK(vendor_value(extra_point(prof, "load_pct"), xr) == tight(25.3));
    CHECK(all_requests(log, 1, 4));
    CHECK(requested(log, 3, 2));
    CHECK(requested(log, 48, 4));
    CHECK(requested(log, 9, 19));                              // 9–27 (rupe ≤ 8 se čitaju)
    CHECK(requested(log, 77, 2));
}

TEST_CASE("[device][vendor][P] EPV: EPEver Tracer/UPower – RTU okvir (FC04) i dekodiranje prema tablici") {
    // Tablica (epever): FC04, unit 1, 32 bita niža riječ prva (u32(lo, hi)); snaga u32(0x3102, 0x3103) × 0,01 W;
    // danas u32(0x330C, 0x330D) × 0,01 kWh; ukupno u32(0x3312, 0x3313) × 0,01 kWh;
    // dodaci: battery_soc u16(0x311A); battery_v u16(0x331A) × 0,01; battery_a s32(0x331B, 0x331C) × 0,01 (battery_sign +1);
    // inverter_temp s16(0x3111) × 0,01; ac_load_w u32(0x310E, 0x310F) × 0,01
    const VendorProfile& prof = *find_vendor("epever");
    REQUIRE(prof.fc == 4);
    REQUIRE(prof.link == VendorLink::Serial);
    FakeRegisters f;
    fill(f, 0x3100, 0x3120);
    fill(f, 0x3300, 0x3320);
    put32(f, 0x3103, 0x3102, 123456);                          // lo 0xE240, hi 0x0001 → 1.234,56 W
    put32(f, 0x330D, 0x330C, 345);                             // 3,45 kWh
    put32(f, 0x3313, 0x3312, 98765);                           // lo 0x81CD, hi 0x0001 → 987,65 kWh
    f.regs[0x311A] = 95;
    f.regs[0x331A] = 2712;                                     // 27,12 V
    put32(f, 0x331C, 0x331B, static_cast<uint32_t>(-525));     // −5,25 A
    f.regs[0x3111] = 3550;                                     // 35,50 °C
    put32(f, 0x310F, 0x310E, 45678);                           // 456,78 W
    std::vector<Request> log;
    std::vector<const VendorPoint*> main_points;
    for (const auto& p : prof.power) main_points.push_back(&p);
    main_points.push_back(&*prof.today);
    main_points.push_back(&*prof.total);
    const auto regs = rtu_p_read(prof, 1, f, main_points, log);
    double power = 0;
    for (const auto& p : prof.power) power += vendor_value(p, regs);
    CHECK(power == tight(1234.56));
    CHECK(vendor_value(*prof.today, regs) == tight(3.45));
    CHECK(vendor_value(*prof.total, regs) == tight(987.65));
    std::vector<const VendorPoint*> extras;
    for (const auto& [k, p] : prof.extras) extras.push_back(&p);
    const auto xr = rtu_p_read(prof, 1, f, extras, log);
    CHECK(vendor_value(extra_point(prof, "battery_soc"), xr) == tight(95.0));
    CHECK(vendor_value(extra_point(prof, "battery_v"), xr) == tight(27.12));
    CHECK(vendor_value(extra_point(prof, "battery_a"), xr) == tight(-5.25));
    CHECK(prof.battery_sign == 1);                             // read_extras: battery_kw = 27,12 × −5,25 / 1000 – nije izvršeno
    CHECK(vendor_value(extra_point(prof, "inverter_temp"), xr) == tight(35.5));
    CHECK(vendor_value(extra_point(prof, "ac_load_w"), xr) == tight(456.78));
    CHECK(all_requests(log, 1, 4));
    CHECK(requested(log, 0x3102, 2));
    CHECK(requested(log, 0x330C, 8));                          // danas + ukupno u jednom zahtjevu
    CHECK(requested(log, 0x310E, 13));
    CHECK(requested(log, 0x331A, 3));
}

TEST_CASE("[device][vendor][P] SRN: SRNE HF/ML/ASF – RTU okvir (FC03) i dekodiranje prema tablici") {
    // Tablica (srne): FC03, unit 1; snaga = u16(0x0109) + u16(0x0111) W; danas u16(0xF02F) × 0,1 kWh;
    // ukupno u32(0xF038, 0xF039) × 0,1 kWh (niža riječ prva);
    // dodaci: battery_soc u16(0x0100); battery_v u16(0x0101) × 0,1; battery_a s16(0x0102) × 0,1 (battery_sign +1);
    // inverter_temp u16(0x0220) × 0,1; grid_v u16(0x0213) × 0,1; grid_hz u16(0x0215) × 0,01; ac_load_w u16(0x021B)
    const VendorProfile& prof = *find_vendor("srne");
    REQUIRE(prof.fc == 3);
    REQUIRE(prof.link == VendorLink::Serial);
    FakeRegisters f;
    fill(f, 0x0100, 0x0120);
    fill(f, 0x0210, 0x0225);
    fill(f, 0xF020, 0xF040);
    f.regs[0x0109] = 1500;
    f.regs[0x0111] = 800;                                      // 2.300 W
    f.regs[0xF02F] = 64;                                       // 6,4 kWh
    put32(f, 0xF039, 0xF038, 543210);                          // lo 0x49EA, hi 0x0008 → 54.321,0 kWh
    f.regs[0x0100] = 70;
    f.regs[0x0101] = 532;                                      // 53,2 V
    f.regs[0x0102] = static_cast<uint16_t>(-123);              // −12,3 A
    f.regs[0x0220] = 385;                                      // 38,5 °C
    f.regs[0x0213] = 2295;                                     // 229,5 V
    f.regs[0x0215] = 5003;                                     // 50,03 Hz
    f.regs[0x021B] = 1100;                                     // 1.100 W
    std::vector<Request> log;
    std::vector<const VendorPoint*> main_points;
    for (const auto& p : prof.power) main_points.push_back(&p);
    main_points.push_back(&*prof.today);
    main_points.push_back(&*prof.total);
    const auto regs = rtu_p_read(prof, 1, f, main_points, log);
    double power = 0;
    for (const auto& p : prof.power) power += vendor_value(p, regs);
    CHECK(power == tight(2300.0));
    CHECK(vendor_value(*prof.today, regs) == tight(6.4));
    CHECK(vendor_value(*prof.total, regs) == tight(54321.0));
    std::vector<const VendorPoint*> extras;
    for (const auto& [k, p] : prof.extras) extras.push_back(&p);
    const auto xr = rtu_p_read(prof, 1, f, extras, log);
    CHECK(vendor_value(extra_point(prof, "battery_soc"), xr) == tight(70.0));
    CHECK(vendor_value(extra_point(prof, "battery_v"), xr) == tight(53.2));
    CHECK(vendor_value(extra_point(prof, "battery_a"), xr) == tight(-12.3));
    CHECK(prof.battery_sign == 1);
    CHECK(vendor_value(extra_point(prof, "inverter_temp"), xr) == tight(38.5));
    CHECK(vendor_value(extra_point(prof, "grid_v"), xr) == tight(229.5));
    CHECK(vendor_value(extra_point(prof, "grid_hz"), xr) == tight(50.03));
    CHECK(vendor_value(extra_point(prof, "ac_load_w"), xr) == tight(1100.0));
    CHECK(all_requests(log, 1, 3));
    CHECK(requested(log, 0x0109, 9));                          // 0x109–0x111 (rupa 7)
    CHECK(requested(log, 0xF02F, 11));                         // 0xF02F–0xF039 (rupa 8)
    CHECK(requested(log, 0x0100, 3));
    CHECK(requested(log, 0x0213, 14));                         // 0x213–0x220
}

// ================================================================ 8. Voltronic/Axpert i Victron VE.Direct
// read_voltronic: "USB" → voltronic_hid_query (SetupDi + HidD_*, VID 0665 / PID 5161), "COMn" → SerialPort;
// read_vedirect: samo SerialPort. Nijedan put nema zamjenjiv prijenos, pa: usmjeravanje + razina P.
TEST_CASE("[device][offgrid][P] VOL: Voltronic – upit QPIGS, odgovor simuliranog izmjenjivača, NAK i usmjeravanje na COM") {
    // Simulirani izmjenjivač: prima točno okvir voltronic_frame("QPIGS"), odgovara "(" + polja + CRC + CR; inače NAK
    auto inverter = [](const std::string& request, const std::string& fields) {
        const std::string body = request == voltronic_frame("QPIGS") ? "(" + fields : "(NAK";
        const uint16_t crc = voltronic_crc(body);
        return body + static_cast<char>(crc >> 8) + static_cast<char>(crc & 0xFF) + "\r";
    };
    // otočni rad: mreža 0 V; izlaz 230,1 V / 50,0 Hz, 412 W, 9 %; baterija 51,20 V, punjenje 8 A, 76 %, hladnjak 38 °C,
    // PV 12 A × 245,3 V, pražnjenje 5 A, polje 20 (PV snaga) 294 W
    const std::string fields = "000.0 00.0 230.1 50.0 0460 0412 009 410 51.20 008 076 0038 0012 245.3 51.10 00005 00010110 00 00 00294 010";
    CHECK(voltronic_frame("QPIGS") == std::string("QPIGS\xB7\xA9\r"));
    const std::string raw = inverter(voltronic_frame("QPIGS"), fields);
    const std::string got = voltronic_unwrap(raw);
    CHECK(got == fields);
    const auto st = parse_qpigs(got);
    REQUIRE(st);
    CHECK(st->grid_v == tight(0.0));
    CHECK(st->out_v == tight(230.1));
    CHECK(st->out_hz == tight(50.0));
    CHECK(st->out_w == tight(412.0));
    CHECK(st->load_pct == tight(9.0));
    CHECK(st->battery_v == tight(51.2));
    CHECK(st->charge_a == tight(8.0));
    CHECK(st->battery_pct == tight(76.0));
    CHECK(st->heatsink_c == tight(38.0));
    CHECK(st->discharge_a == tight(5.0));
    CHECK(st->pv_w == tight(294.0));
    // read_voltronic bi iz ovoga dao: power_kw 0,294; battery_kw 51,2 × (8 − 5) / 1000 = 0,1536; ac_load_kw 0,412;
    // bez grid_v/grid_hz (≤ 50 V) – to preslikavanje NIJE izvršeno (nema zamjenjivog prijenosa)
    CHECK_THROWS_WITH(voltronic_unwrap(inverter("QPIGX\x00\x00\r", fields)), doctest::Contains("ne podržava"));
    std::string damaged = raw;
    damaged[3] = '9';
    CHECK_THROWS_AS(voltronic_unwrap(damaged), SerialError);
    CHECK_THROWS_AS(voltronic_unwrap(""), SerialError);        // izmjenjivač šuti

    Settings s;
    s.device_type = "voltronic";
    s.serial_port = missing_com_port();
    CHECK_THROWS_WITH(read_plant(s), doctest::Contains(s.serial_port.c_str()));
}

namespace {
std::string ve_block(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::string b;
    for (const auto& [k, v] : fields) b += "\r\n" + k + "\t" + v;
    b += "\r\nChecksum\t";
    unsigned sum = 0;
    for (unsigned char c : b) sum += c;
    b += static_cast<char>((256 - (sum & 0xFF)) & 0xFF);
    return b;
}
}  // namespace

TEST_CASE("[device][offgrid][P] VED: VE.Direct – 2,5 s toka s dva MPPT-a i SmartShuntom, ponovljeni blokovi, usmjeravanje na COM") {
    // Simulirani tok kakav read_until vrati za 2,5 s (19200 8N1, blok svake sekunde): početak usred bloka, dva MPPT-a
    // (različiti SER#) šalju po dva bloka – vrijedi zadnji; SmartShunt jedan blok.
    const auto mppt = [](const char* ser, const char* ppv, const char* v, const char* i, const char* h19, const char* h20) {
        return ve_block({{"PID", "0xA053"}, {"SER#", ser}, {"V", v}, {"I", i}, {"VPV", "76550"}, {"PPV", ppv}, {"CS", "3"},
                         {"H19", h19}, {"H20", h20}});
    };
    const std::string shunt = ve_block({{"PID", "0xA389"}, {"SER#", "HQS"}, {"V", "26100"}, {"I", "5000"}, {"P", "130"}, {"SOC", "912"}});
    const std::string stream = "\t0\r\nChecksum\tX" + mppt("HQA", "100", "26150", "3000", "1000", "50") +
                               mppt("HQB", "200", "26160", "6000", "2000", "70") + shunt +
                               mppt("HQA", "120", "26150", "3500", "1001", "51") + mppt("HQB", "210", "26160", "6200", "2000", "71");
    const auto blocks = parse_vedirect(stream);
    REQUIRE(blocks.size() == 5);
    const VeSummary s = summarize_vedirect(blocks);
    CHECK(s.pv_w == tight(330.0));                   // zadnji PPV: 120 + 210
    CHECK(s.has_yield);
    CHECK(s.today_kwh == tight(1.22));               // H20: 0,51 + 0,71
    CHECK(s.total_kwh == tight(30.01));              // H19: 10,01 + 20,00
    CHECK(s.extra.at("battery_v").get<double>() == tight(26.1));   // šant
    CHECK(s.extra.at("battery_soc").get<double>() == tight(91.2));
    CHECK(s.extra.at("battery_kw").get<double>() == tight(0.13));  // P šanta, > 0 punjenje
    CHECK_FALSE(s.extra.contains("ac_load_kw"));
    // read_vedirect bi dao power_kw 0,33, e_daily 1,22, e_total 30,01 – to preslikavanje NIJE izvršeno

    Settings v;
    v.device_type = "vedirect";
    v.serial_port = missing_com_port();
    CHECK_THROWS_WITH(read_plant(v), doctest::Contains(v.serial_port.c_str()));
    v.serial_port = "";
    CHECK_THROWS_WITH(read_plant(v), doctest::Contains("COM"));
}

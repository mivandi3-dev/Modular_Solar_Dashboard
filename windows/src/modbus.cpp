#include "modbus.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <cstring>

#include "i18n.hpp"

namespace sm {

namespace {
int words_for(const char* dtype) { return dtype[1] == '3' ? 2 : 1; }  // U32/I32 → 2 riječi
}  // namespace

int64_t decode(const std::vector<uint16_t>& words, const char* dtype) {
    uint64_t value = 0;
    for (uint16_t w : words) value = (value << 16) | w;
    const int bits = static_cast<int>(16 * words.size());
    if (dtype[0] == 'I' && (value >> (bits - 1)) & 1) return static_cast<int64_t>(value) - (int64_t{1} << bits);
    return static_cast<int64_t>(value);
}

uint16_t modbus_crc(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) crc = (crc & 1) ? static_cast<uint16_t>((crc >> 1) ^ 0xA001) : static_cast<uint16_t>(crc >> 1);
    }
    return crc;
}

std::vector<uint8_t> rtu_read_request(int unit, uint8_t fc, uint16_t address, uint16_t count) {
    std::vector<uint8_t> f = {static_cast<uint8_t>(unit), fc, static_cast<uint8_t>(address >> 8), static_cast<uint8_t>(address),
                              static_cast<uint8_t>(count >> 8), static_cast<uint8_t>(count)};
    const uint16_t crc = modbus_crc(f.data(), f.size());
    f.push_back(static_cast<uint8_t>(crc));
    f.push_back(static_cast<uint8_t>(crc >> 8));
    return f;
}

std::vector<uint16_t> parse_rtu_response(const uint8_t* d, size_t n, uint8_t fc, uint16_t count) {
    if (n >= 5 && d[1] == (fc | 0x80)) {
        throw ModbusError(tr("Uređaj je vratio Modbus grešku {code}.", {{"code", std::to_string(d[2])}}));
    }
    const size_t want = 3u + count * 2u + 2u;
    if (n < want || d[1] != fc || d[2] != count * 2) throw ModbusError(tr("Neočekivan odgovor uređaja."));
    const uint16_t crc = static_cast<uint16_t>(d[want - 2] | (d[want - 1] << 8));
    if (modbus_crc(d, want - 2) != crc) throw ModbusError(tr("Neispravan kontrolni zbroj u odgovoru uređaja."));
    std::vector<uint16_t> words(count);
    for (size_t i = 0; i < count; ++i) words[i] = static_cast<uint16_t>((d[3 + 2 * i] << 8) | d[4 + 2 * i]);
    return words;
}

std::vector<uint8_t> solarman_request(uint32_t serial, uint8_t sequence, const std::vector<uint8_t>& rtu) {
    const uint16_t length = static_cast<uint16_t>(15 + rtu.size());
    std::vector<uint8_t> f = {0xA5, static_cast<uint8_t>(length), static_cast<uint8_t>(length >> 8), 0x10, 0x45, sequence, 0x00,
                              static_cast<uint8_t>(serial), static_cast<uint8_t>(serial >> 8), static_cast<uint8_t>(serial >> 16),
                              static_cast<uint8_t>(serial >> 24),
                              0x02, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // vrsta okvira, senzor, 3 × vrijeme
    f.insert(f.end(), rtu.begin(), rtu.end());
    uint8_t sum = 0;
    for (size_t i = 1; i < f.size(); ++i) sum = static_cast<uint8_t>(sum + f[i]);
    f.push_back(sum);
    f.push_back(0x15);
    return f;
}

std::vector<uint8_t> solarman_rtu(const std::vector<uint8_t>& f, uint32_t serial) {
    if (f.size() < 29 || f.front() != 0xA5 || f.back() != 0x15) throw ModbusError(tr("Neočekivan odgovor uređaja."));
    uint8_t sum = 0;
    for (size_t i = 1; i + 2 < f.size(); ++i) sum = static_cast<uint8_t>(sum + f[i]);
    if (sum != f[f.size() - 2]) throw ModbusError(tr("Neispravan kontrolni zbroj u odgovoru uređaja."));
    const uint32_t sn = f[7] | (f[8] << 8) | (f[9] << 16) | (static_cast<uint32_t>(f[10]) << 24);
    if (sn != serial) throw ModbusError(tr("Odgovor je s drugog loggera – provjerite serijski broj loggera."));
    if (f[4] != 0x15) throw ModbusError(tr("Neočekivan odgovor uređaja."));
    return {f.begin() + 25, f.end() - 2};
}

ModbusClient::ModbusClient(std::string host, int port, int unit_id, std::string source_ip, int timeout_ms,
                           std::string device, Framing framing, uint32_t logger_serial)
    : host_(std::move(host)), source_ip_(std::move(source_ip)), device_(std::move(device)), port_(port), unit_id_(unit_id),
      timeout_ms_(timeout_ms), sock_(INVALID_SOCKET), framing_(framing), logger_serial_(logger_serial) {}

ModbusClient::~ModbusClient() {
    if (sock_ != INVALID_SOCKET) closesocket(sock_);
}

void ModbusClient::connect() {
    const TrArgs where = {{"device", device_}, {"host", host_}, {"port", std::to_string(port_)}};
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    const bool udp = framing_ == Framing::GoodweUdp;
    hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
    if (getaddrinfo(host_.c_str(), std::to_string(port_).c_str(), &hints, &res) != 0 || !res) {
        throw ModbusError(tr("{device} {host}:{port} – adresa nije ispravna.", where));
    }
    sock_ = udp ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!source_ip_.empty()) {
        // Vezanje na adresu kartice: Windows šalje promet kroz tu karticu.
        sockaddr_in local{};
        local.sin_family = AF_INET;
        inet_pton(AF_INET, source_ip_.c_str(), &local.sin_addr);
        if (bind(sock_, reinterpret_cast<sockaddr*>(&local), sizeof local) != 0) {
            freeaddrinfo(res);
            throw ModbusError(tr("Mrežna kartica s adresom {ip} nije dostupna.", {{"ip", source_ip_}}));
        }
    }
    const DWORD t = static_cast<DWORD>(timeout_ms_);
    if (udp) {  // UDP nema uspostave veze – connect samo zapamti odredište
        ::connect(sock_, res->ai_addr, static_cast<int>(res->ai_addrlen));
        freeaddrinfo(res);
        setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof t);
        return;
    }
    u_long nonblocking = 1;
    ioctlsocket(sock_, FIONBIO, &nonblocking);
    ::connect(sock_, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);
    fd_set writable, failed;
    FD_ZERO(&writable); FD_SET(sock_, &writable);
    FD_ZERO(&failed); FD_SET(sock_, &failed);
    timeval tv{timeout_ms_ / 1000, (timeout_ms_ % 1000) * 1000};
    if (select(0, nullptr, &writable, &failed, &tv) <= 0 || FD_ISSET(sock_, &failed)) {
        throw ModbusError(tr("{device} {host}:{port} nije dostupan (provjerite mrežu i je li Modbus TCP uključen).", where));
    }
    nonblocking = 0;
    ioctlsocket(sock_, FIONBIO, &nonblocking);
    setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof t);
    setsockopt(sock_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof t);
}

void ModbusClient::send_all(const uint8_t* data, int len) {
    while (len > 0) {
        const int n = send(sock_, reinterpret_cast<const char*>(data), len, 0);
        if (n <= 0) throw ModbusError(tr("Slanje prema uređaju nije uspjelo."));
        data += n;
        len -= n;
    }
}

void ModbusClient::recv_all(uint8_t* data, int len) {
    while (len > 0) {
        const int n = recv(sock_, reinterpret_cast<char*>(data), len, 0);
        if (n == 0 || (n < 0 && WSAGetLastError() == WSAECONNRESET)) {
            // Logger prihvati vezu pa je odmah prekine kad IP klijenta nije na popisu dopuštenih.
            throw ModbusError(tr("{device} {host}:{port} je prekinuo vezu – IP ovog računala vjerojatno nije na popisu "
                                 "dopuštenih (Modbus TCP → Enable (Limited)).",
                                 {{"device", device_}, {"host", host_}, {"port", std::to_string(port_)}}));
        }
        if (n < 0) throw ModbusError(tr("{device} {host} ne odgovara (isteklo vrijeme).", {{"device", device_}, {"host", host_}}));
        data += n;
        len -= n;
    }
}

std::vector<uint16_t> ModbusClient::read_registers(uint16_t address, uint16_t count, int unit_id, uint8_t fc) {
    switch (framing_) {
        case Framing::Solarman: return read_solarman(address, count, unit_id, fc);
        case Framing::GoodweUdp: return read_goodwe(address, count, unit_id, fc);
        default: return read_tcp(address, count, unit_id, fc);
    }
}

std::vector<uint16_t> ModbusClient::read_solarman(uint16_t address, uint16_t count, int unit_id, uint8_t fc) {
    const uint8_t seq = static_cast<uint8_t>(++transaction_);
    const auto request = solarman_request(logger_serial_, seq, rtu_read_request(unit_id, fc, address, count));
    send_all(request.data(), static_cast<int>(request.size()));
    for (int skipped = 0; skipped < 5; ++skipped) {  // logger šalje i svoje okvire (otkucaji) – preskače se sve osim odgovora
        std::vector<uint8_t> frame(3);
        try {
            recv_all(frame.data(), 3);
        } catch (const ModbusError& e) {  // logger s drugim serijskim brojem ne odgovara uopće
            throw ModbusError(std::string(e.what()) + " " + tr("Provjerite i serijski broj loggera."));
        }
        const int length = frame[1] | (frame[2] << 8);
        frame.resize(13u + length);
        recv_all(frame.data() + 3, static_cast<int>(frame.size()) - 3);
        if (frame[4] != 0x15 || frame[5] != seq) continue;
        const auto rtu = solarman_rtu(frame, logger_serial_);
        return parse_rtu_response(rtu.data(), rtu.size(), fc, count);
    }
    throw ModbusError(tr("Neočekivan odgovor uređaja."));
}

std::vector<uint16_t> ModbusClient::read_goodwe(uint16_t address, uint16_t count, int unit_id, uint8_t fc) {
    const auto request = rtu_read_request(unit_id, fc, address, count);
    for (int attempt = 0; attempt < 3; ++attempt) {  // UDP: zahtjev ili odgovor se mogu izgubiti
        send(sock_, reinterpret_cast<const char*>(request.data()), static_cast<int>(request.size()), 0);
        uint8_t buf[600];
        const int n = recv(sock_, reinterpret_cast<char*>(buf), sizeof buf, 0);
        if (n <= 0) continue;
        if (n < 7 || buf[0] != 0xAA || buf[1] != 0x55) throw ModbusError(tr("Neočekivan odgovor uređaja."));
        return parse_rtu_response(buf + 2, static_cast<size_t>(n - 2), fc, count);  // AA 55 + RTU odgovor
    }
    throw ModbusError(tr("{device} {host} ne odgovara (isteklo vrijeme).", {{"device", device_}, {"host", host_}}));
}

std::vector<uint16_t> ModbusClient::read_tcp(uint16_t address, uint16_t count, int unit_id, uint8_t fc) {
    const uint16_t tid = ++transaction_;
    const std::array<uint8_t, 12> request = {
        static_cast<uint8_t>(tid >> 8), static_cast<uint8_t>(tid), 0, 0, 0, 6, static_cast<uint8_t>(unit_id),
        fc, static_cast<uint8_t>(address >> 8), static_cast<uint8_t>(address), static_cast<uint8_t>(count >> 8),
        static_cast<uint8_t>(count)};
    send_all(request.data(), static_cast<int>(request.size()));
    std::array<uint8_t, 9> head{};
    recv_all(head.data(), 7 + 2);  // MBAP (7) + funkcija + broj bajtova / kod greške
    const int function = head[7];
    if (function & 0x80) {
        throw ModbusError(tr("{device} je za registar {reg} vratio grešku: {error}",
                             {{"device", device_}, {"reg", std::to_string(address)}, {"error", "kod " + std::to_string(head[8])}}));
    }
    const int bytes = head[8];
    if (bytes != count * 2) throw ModbusError(tr("Neočekivan odgovor uređaja."));
    std::vector<uint8_t> payload(static_cast<size_t>(bytes));
    recv_all(payload.data(), bytes);
    std::vector<uint16_t> words(count);
    for (size_t i = 0; i < count; ++i) words[i] = static_cast<uint16_t>((payload[2 * i] << 8) | payload[2 * i + 1]);
    return words;
}

double ModbusClient::read_value(const Register& reg, int unit_id) {
    const auto words = read_registers(reg.address, static_cast<uint16_t>(words_for(reg.dtype)), unit_id < 0 ? unit_id_ : unit_id);
    return static_cast<double>(decode(words, reg.dtype)) / reg.gain;
}

Reading ModbusClient::read_inverter(int unit_id) {
    Reading r;
    r.power_kw = read_value(kInvPowerKw, unit_id);
    r.e_daily_kwh = read_value(kInvEDailyKwh, unit_id);
    r.e_total_kwh = read_value(kInvETotalKwh, unit_id);
    r.pf = read_value(kInvPowerFactor, unit_id);
    r.status = static_cast<int>(read_value(kInvStatus, unit_id));
    return r;
}

Reading ModbusClient::read() {
    Reading r;
    r.power_kw = read_value(kPowerKw);
    r.e_daily_kwh = read_value(kEDailyKwh);
    r.e_total_kwh = read_value(kETotalKwh);
    r.pf = read_value(kPowerFactor);
    r.status = static_cast<int>(read_value(kStatus));
    return r;
}

}  // namespace sm

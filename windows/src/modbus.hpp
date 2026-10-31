// Huawei SmartLogger 3000 preko Modbus TCP-a (FC03, holding registri) – ista tablica registara
// i skaliranje kao Python verzija (solar/modbus_client.py).
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace sm {

class ModbusError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Register {
    uint16_t address;
    const char* dtype;  // U16 | I16 | U32 | I32
    double gain;        // skalirana vrijednost = sirova / gain
};

inline constexpr Register kPowerKw{40525, "I32", 1000};
inline constexpr Register kEDailyKwh{40562, "U32", 10};
inline constexpr Register kETotalKwh{40560, "U32", 10};
inline constexpr Register kPowerFactor{40532, "I16", 1000};
inline constexpr Register kStatus{40543, "U16", 1};
inline constexpr Register kMeterPowerKw{32278, "I32", 1000};  // mjerač na COM portu (vlastiti unit ID)

// Huawei SUN2000 inverter izravno (SUN2000 Modbus Interface Definitions)
inline constexpr Register kInvPowerKw{32080, "I32", 1000};
inline constexpr Register kInvEDailyKwh{32114, "U32", 100};
inline constexpr Register kInvETotalKwh{32106, "U32", 100};
inline constexpr Register kInvPowerFactor{32084, "I16", 1000};
inline constexpr Register kInvStatus{32089, "U16", 1};
// Mjerač (DTSU666-H) na inverteru: W, > 0 predaja u mrežu, < 0 uzimanje iz mreže
inline constexpr Register kInvMeterPowerKw{37113, "I32", 1000};

struct Reading {
    double power_kw = 0, e_daily_kwh = 0, e_total_kwh = 0, pf = 0;
    int status = 0;
};

int64_t decode(const std::vector<uint16_t>& words, const char* dtype);  // big-endian, s predznakom za I16/I32

// Kako se Modbus prenosi: Modbus TCP (MBAP), Solarman V5 (Deye/Sunsynk Wi-Fi logger, TCP 8899, Modbus RTU u
// okviru s serijskim brojem loggera) ili GoodWe (Modbus RTU preko UDP-a, port 8899, odgovor s prefiksom AA 55).
enum class Framing { Tcp, Solarman, GoodweUdp };

uint16_t modbus_crc(const uint8_t* data, size_t len);  // CRC-16/MODBUS
std::vector<uint8_t> rtu_read_request(int unit, uint8_t fc, uint16_t address, uint16_t count);
// Podaci iz RTU odgovora (unit, fc, broj bajtova, podaci, CRC); baca ModbusError (iznimka uređaja, CRC, duljina).
std::vector<uint16_t> parse_rtu_response(const uint8_t* data, size_t len, uint8_t fc, uint16_t count);
std::vector<uint8_t> solarman_request(uint32_t logger_serial, uint8_t sequence, const std::vector<uint8_t>& rtu);
// RTU okvir iz Solarman V5 odgovora (provjera početka, kraja, kontrolnog zbroja, koda 0x15 i serijskog broja).
std::vector<uint8_t> solarman_rtu(const std::vector<uint8_t>& frame, uint32_t logger_serial);

class ModbusClient {
public:
    // source_ip: adresa kartice prema loggeru ("" = Windows bira karticu)
    // device: naziv u porukama ("SmartLogger" ili "Inverter")
    ModbusClient(std::string host, int port, int unit_id, std::string source_ip = {}, int timeout_ms = 5000,
                 std::string device = "SmartLogger", Framing framing = Framing::Tcp, uint32_t logger_serial = 0);
    ~ModbusClient();
    ModbusClient(const ModbusClient&) = delete;
    ModbusClient& operator=(const ModbusClient&) = delete;

    void connect();
    double read_value(const Register& reg, int unit_id = -1);
    Reading read();
    Reading read_inverter(int unit_id);
    double read_meter_kw(int unit_id) { return read_value(kMeterPowerKw, unit_id); }
    // FC03 (holding) ili FC04 (input), najviše 125 registara
    std::vector<uint16_t> read_registers(uint16_t address, uint16_t count, int unit_id, uint8_t fc = 3);

private:
    void send_all(const uint8_t* data, int len);
    void recv_all(uint8_t* data, int len);

    std::vector<uint16_t> read_tcp(uint16_t address, uint16_t count, int unit_id, uint8_t fc);
    std::vector<uint16_t> read_solarman(uint16_t address, uint16_t count, int unit_id, uint8_t fc);
    std::vector<uint16_t> read_goodwe(uint16_t address, uint16_t count, int unit_id, uint8_t fc);

    std::string host_, source_ip_, device_;
    int port_, unit_id_, timeout_ms_;
    uintptr_t sock_;
    uint16_t transaction_ = 0;
    Framing framing_;
    uint32_t logger_serial_;
};

}  // namespace sm

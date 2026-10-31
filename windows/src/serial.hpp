// Serijske veze za otočne (off-grid) uređaje (3.2): COM portovi (USB-serijski kabel, RS232, RS485 pretvarač)
// i USB HID (Voltronic/Axpert: USB kabel se javlja kao HID uređaj 0665:5161, ne kao COM port).
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace sm {

class SerialError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class SerialPort {
public:
    SerialPort(const std::string& port, int baud, int timeout_ms = 2000);  // "COM3"; baca SerialError
    ~SerialPort();
    SerialPort(const SerialPort&) = delete;
    SerialPort& operator=(const SerialPort&) = delete;

    void write(const std::string& data);
    // Čita što stigne do isteka (ukupno) ili dok `done` ne kaže da je odgovor potpun
    std::string read_until(int timeout_ms, bool (*done)(const std::string&, size_t), size_t want = 0);
    void purge();  // odbaci staro u međuspremniku (prije novog zahtjeva)

private:
    void* h_ = nullptr;
    std::string name_;
};

std::vector<std::string> list_serial_ports();  // ["COM1", "COM3", …] – postojeći na ovom računalu
bool is_serial_port_name(const std::string& s);  // COM1–COM256

// Modbus RTU preko serijskog porta (Growatt SPF, EPEver, SRNE): FC03/FC04, najviše 125 registara
std::vector<uint16_t> rtu_serial_read(SerialPort& port, int unit, uint8_t fc, uint16_t address, uint16_t count);

// Voltronic preko USB HID: upit (npr. "QPIGS") → odgovor bez "(" i CRC-a; baca SerialError
std::string voltronic_hid_query(const std::string& command, int timeout_ms = 3000);

}  // namespace sm

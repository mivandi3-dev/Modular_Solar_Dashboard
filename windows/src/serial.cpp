#include "serial.hpp"

#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>

#include <cstring>
#include <stdexcept>

#include "i18n.hpp"
#include "modbus.hpp"
#include "offgrid.hpp"
#include "util.hpp"

namespace sm {

namespace {

constexpr USHORT kVoltronicVid = 0x0665, kVoltronicPid = 0x5161;
constexpr size_t kHidReport = 8;  // Voltronic: izvještaji od 8 bajtova (+ ID izvještaja 0)

HANDLE handle(void* h) { return static_cast<HANDLE>(h); }

// HID prijenos s vremenskim ograničenjem (obični ReadFile na HID-u čeka zauvijek ako uređaj ne odgovori)
bool hid_io(HANDLE h, bool write, uint8_t* buf, DWORD len, DWORD timeout_ms, DWORD* done) {
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    BOOL ok = write ? WriteFile(h, buf, len, nullptr, &ov) : ReadFile(h, buf, len, nullptr, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(ov.hEvent, timeout_ms) != WAIT_OBJECT_0) {
            CancelIo(h);
            WaitForSingleObject(ov.hEvent, 1000);
            CloseHandle(ov.hEvent);
            return false;
        }
        ok = TRUE;
    }
    const BOOL res = ok && GetOverlappedResult(h, &ov, done, FALSE);
    CloseHandle(ov.hEvent);
    return res != FALSE;
}

struct Handle {
    HANDLE h = INVALID_HANDLE_VALUE;
    ~Handle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

}  // namespace

// ---------------------------------------------------------------- COM port
bool is_serial_port_name(const std::string& s) {
    if (s.size() < 4 || s.size() > 6 || s.compare(0, 3, "COM") != 0) return false;
    for (size_t i = 3; i < s.size(); ++i) if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
    const int n = std::atoi(s.c_str() + 3);
    return n >= 1 && n <= 256;
}

SerialPort::SerialPort(const std::string& port, int baud, int timeout_ms) : name_(port) {
    if (!is_serial_port_name(port)) throw SerialError(tr("Neispravan serijski port {port}.", {{"port", port}}));
    const std::wstring path = L"\\\\.\\" + widen(port);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        throw SerialError(e == ERROR_ACCESS_DENIED ? tr("Port {port} koristi drugi program.", {{"port", port}})
                                                   : tr("Port {port} ne postoji – provjerite kabel i upravljački program.", {{"port", port}}));
    }
    h_ = h;
    DCB dcb{};
    dcb.DCBlength = sizeof dcb;
    GetCommState(h, &dcb);
    dcb.BaudRate = static_cast<DWORD>(baud);
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    dcb.fOutxCtsFlow = dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fOutX = dcb.fInX = FALSE;
    if (!SetCommState(h, &dcb)) throw SerialError(tr("Port {port} ne prihvaća brzinu {baud}.", {{"port", port}, {"baud", std::to_string(baud)}}));
    COMMTIMEOUTS t{};
    t.ReadIntervalTimeout = 50;  // kratke stanke unutar odgovora
    t.ReadTotalTimeoutConstant = static_cast<DWORD>(timeout_ms);
    t.WriteTotalTimeoutConstant = static_cast<DWORD>(timeout_ms);
    SetCommTimeouts(h, &t);
    purge();
}

SerialPort::~SerialPort() {
    if (h_) CloseHandle(handle(h_));
}

void SerialPort::purge() { PurgeComm(handle(h_), PURGE_RXCLEAR | PURGE_TXCLEAR); }

void SerialPort::write(const std::string& data) {
    DWORD written = 0;
    if (!WriteFile(handle(h_), data.data(), static_cast<DWORD>(data.size()), &written, nullptr) || written != data.size()) {
        throw SerialError(tr("Slanje na port {port} nije uspjelo.", {{"port", name_}}));
    }
}

std::string SerialPort::read_until(int timeout_ms, bool (*done)(const std::string&, size_t), size_t want) {
    std::string out;
    const ULONGLONG end = GetTickCount64() + static_cast<ULONGLONG>(timeout_ms);
    char buf[512];
    while (GetTickCount64() < end) {
        DWORD n = 0;
        if (!ReadFile(handle(h_), buf, sizeof buf, &n, nullptr)) throw SerialError(tr("Čitanje s porta {port} nije uspjelo.", {{"port", name_}}));
        out.append(buf, n);
        if (done && done(out, want)) break;
        if (out.size() > 64 * 1024) break;
    }
    return out;
}

std::vector<std::string> list_serial_ports() {
    std::vector<std::string> out;
    wchar_t target[512];
    for (int i = 1; i <= 256; ++i) {
        const std::wstring name = L"COM" + std::to_wstring(i);
        if (QueryDosDeviceW(name.c_str(), target, 512)) out.push_back(narrow(name));
    }
    return out;
}

// ---------------------------------------------------------------- Modbus RTU
std::vector<uint16_t> rtu_serial_read(SerialPort& port, int unit, uint8_t fc, uint16_t address, uint16_t count) {
    const std::vector<uint8_t> req = rtu_read_request(unit, fc, address, count);
    port.purge();
    port.write(std::string(req.begin(), req.end()));
    // potpun odgovor: 5 + 2·count bajtova, ili 5 kod iznimke (fc | 0x80)
    const auto complete = [](const std::string& s, size_t want) {
        if (s.size() >= 2 && (static_cast<uint8_t>(s[1]) & 0x80)) return s.size() >= 5;
        return s.size() >= want;
    };
    const std::string resp = port.read_until(2000, complete, 5 + 2u * count);
    if (resp.empty()) throw ModbusError(tr("Uređaj na serijskom portu ne odgovara – provjerite kabel, brzinu i Modbus adresu."));
    return parse_rtu_response(reinterpret_cast<const uint8_t*>(resp.data()), resp.size(), fc, count);
}

// ---------------------------------------------------------------- Voltronic USB HID
std::string voltronic_hid_query(const std::string& command, int timeout_ms) {
    GUID hid{};
    HidD_GetHidGuid(&hid);
    HDEVINFO set = SetupDiGetClassDevsW(&hid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) throw SerialError(tr("USB uređaji nisu dostupni."));
    Handle dev;
    SP_DEVICE_INTERFACE_DATA iface{sizeof iface};
    for (DWORD i = 0; dev.h == INVALID_HANDLE_VALUE && SetupDiEnumDeviceInterfaces(set, nullptr, &hid, i, &iface); ++i) {
        DWORD size = 0;
        SetupDiGetDeviceInterfaceDetailW(set, &iface, nullptr, 0, &size, nullptr);
        std::vector<uint8_t> buf(size);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        if (!SetupDiGetDeviceInterfaceDetailW(set, &iface, detail, size, nullptr, nullptr)) continue;
        HANDLE h = CreateFileW(detail->DevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        HIDD_ATTRIBUTES a{sizeof a};
        if (HidD_GetAttributes(h, &a) && a.VendorID == kVoltronicVid && a.ProductID == kVoltronicPid) dev.h = h;
        else CloseHandle(h);
    }
    SetupDiDestroyDeviceInfoList(set);
    if (dev.h == INVALID_HANDLE_VALUE) throw SerialError(tr("Voltronic (Axpert) izmjenjivač nije spojen USB kabelom."));

    const std::string frame = voltronic_frame(command);
    for (size_t pos = 0; pos < frame.size(); pos += kHidReport) {  // izvještaj: ID 0 + 8 bajtova
        uint8_t report[kHidReport + 1] = {0};
        const size_t n = std::min(kHidReport, frame.size() - pos);
        std::memcpy(report + 1, frame.data() + pos, n);
        if (!HidD_SetOutputReport(dev.h, report, sizeof report)) {
            DWORD w = 0;
            if (!hid_io(dev.h, true, report, sizeof report, 1000, &w)) throw SerialError(tr("Slanje izmjenjivaču nije uspjelo."));
        }
    }
    std::string resp;
    const ULONGLONG end = GetTickCount64() + static_cast<ULONGLONG>(timeout_ms);
    while (GetTickCount64() < end && resp.find('\r') == std::string::npos) {
        uint8_t report[kHidReport + 1] = {0};
        DWORD r = 0;
        const DWORD left = static_cast<DWORD>(end - GetTickCount64());
        if (!hid_io(dev.h, false, report, sizeof report, left, &r) || r == 0) break;
        for (DWORD i = 1; i < r; ++i) if (report[i]) resp += static_cast<char>(report[i]);
    }
    return voltronic_unwrap(resp);
}

}  // namespace sm

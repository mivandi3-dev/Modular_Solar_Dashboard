// Otočni (off-grid) sustavi (3.2):
//   * Voltronic Power (Axpert, MPP Solar PIP, EASUN ISolar, PowMr, Mecer, Anern, Must PV18…): ASCII protokol
//     QPIGS, 2400 8N1 preko RS232/USB-serijskog kabela ili USB HID (0665:5161). Odgovor "(" + polja + CRC + CR.
//   * Victron VE.Direct (SmartSolar/BlueSolar MPPT, Phoenix izmjenjivači 12/24/48 V, SmartShunt, BMV): tekstualni
//     protokol, 19200 8N1, uređaj sam šalje blok svake sekunde (naziv TAB vrijednost; blok završava kontrolnim
//     zbrojem – zbroj svih bajtova bloka mod 256 = 0). Više uređaja = više COM portova; vrijednosti se zbrajaju.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "config.hpp"

namespace sm {

struct PlantReading;

// ---- Voltronic
uint16_t voltronic_crc(const std::string& data);       // CRC-16/XMODEM s Voltronic izuzecima ('(', CR, LF → +1)
std::string voltronic_frame(const std::string& command);  // "QPIGS" + CRC + CR
std::string voltronic_unwrap(const std::string& raw);   // "(…" + CRC + CR → polja; baca SerialError (CRC, NAK)

struct VoltronicStatus {
    double grid_v = 0, grid_hz = 0, out_v = 0, out_hz = 0, out_va = 0, out_w = 0, load_pct = 0;
    double battery_v = 0, charge_a = 0, battery_pct = 0, heatsink_c = 0, pv_a = 0, pv_v = 0, discharge_a = 0;
    double pv_w = 0;  // polje 20 (novije) ili struja × napon PV ulaza
};
std::optional<VoltronicStatus> parse_qpigs(const std::string& fields);
PlantReading read_voltronic(const Settings& s);  // serial_port: "USB" (HID) ili "COM3"

// ---- Victron VE.Direct
using VeBlock = std::map<std::string, std::string>;
std::vector<VeBlock> parse_vedirect(const std::string& stream);  // samo blokovi s ispravnim kontrolnim zbrojem
struct VeSummary {
    double pv_w = 0, today_kwh = 0, total_kwh = 0;
    bool has_yield = false;
    json extra = json::object();
};
VeSummary summarize_vedirect(const std::vector<VeBlock>& blocks);  // blokovi svih uređaja (MPPT, Phoenix, SmartShunt)
PlantReading read_vedirect(const Settings& s);  // serial_port: "COM3" ili "COM3, COM4, COM5"

// Nazivni napon sustava iz napona baterije: 12, 24 ili 48 V (0 = nepoznato)
int nominal_system_voltage(double battery_v);

}  // namespace sm

// Inverteri ostalih proizvođača preko Modbusa – tablice registara (izvori uz svaku tablicu u vendors.cpp):
// Sungrow, GoodWe, Deye/Sunsynk, Solis, Fox ESS, Growatt i Victron Energy (GX). Veza je Modbus TCP, a za
// Deye/Sunsynk Wi-Fi logger Solarman V5 (port 8899) i za GoodWe Wi-Fi/LAN modul Modbus RTU preko UDP-a (port 8899).
// 3.2: otočni izmjenjivači i punjači preko serijskog porta (Modbus RTU): Growatt SPF, EPEver, SRNE.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "modbus.hpp"

namespace sm {

struct Settings;
struct PlantReading;

// Jedna vrijednost: 16-bitna (lo) ili 32-bitna (lo + hi riječ, bilo kojim redom i na bilo kojim adresama).
struct VendorPoint {
    uint16_t lo = 0, hi = 0;
    bool wide = false, sign = false;
    double scale = 1;   // (sirova vrijednost − offset) × scale = W, kWh, °C…
    double offset = 0;  // Deye temperature: sirovo 1000 = 0 °C
};

enum class VendorLink { Tcp, Solarman, GoodweUdp, Serial };  // Serial: Modbus RTU na COM portu (port = brzina)

struct VendorProfile {
    const char* key;
    const char* name;  // oznaka serije, ista na svim jezicima, npr. "Sungrow SG"
    uint8_t fc;        // 3 = holding, 4 = input
    VendorLink link;   // veza kad je port 8899 (inače Modbus TCP); Serial: uvijek COM port
    int port, unit;    // uobičajeni port i Modbus adresa (Serial: port = uobičajena brzina, npr. 9600)
    std::vector<VendorPoint> power;           // zbroj – W
    std::optional<VendorPoint> today, total;  // kWh; bez njih poller računa iz ukupne ili integrira snagu
    std::vector<VendorPoint> meter;           // zbroj – W
    bool meter_import_positive;               // predznak mjerača prema dokumentaciji proizvođača
    // podaci za widgete: battery_soc (%), battery_w (W), inverter_temp (°C), grid_v (V), grid_hz (Hz);
    // otočni (3.2): battery_v (V), battery_a (A – s battery_v daje snagu), ac_load_w (W, zbraja se po fazama),
    // ac_out_v (V), ac_out_hz (Hz), load_pct (%)
    std::vector<std::pair<const char*, VendorPoint>> extras = {};
    int battery_sign = 0;  // +1: battery_w > 0 je punjenje, −1: > 0 je pražnjenje, 0: smjer nepoznat
};

const std::vector<VendorProfile>& vendor_profiles();
const VendorProfile* find_vendor(const std::string& key);

// Vrijednost iz pročitanih registara (adresa → riječ).
double vendor_value(const VendorPoint& p, const std::vector<std::pair<uint16_t, uint16_t>>& regs);
// Najmanji broj čitanja: susjedne adrese u jednom zahtjevu (do 125 registara, rupe do 8 registara se čitaju).
std::vector<std::pair<uint16_t, uint16_t>> vendor_ranges(std::vector<uint16_t> addresses);

// Očitanje prema tablici; e_total_kwh < 0: uređaj ne daje energiju (Victron) – poller integrira snagu.
PlantReading read_vendor(const Settings& s);

}  // namespace sm

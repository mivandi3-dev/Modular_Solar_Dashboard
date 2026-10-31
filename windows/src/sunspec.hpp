// SunSpec Modbus – standard koji podržavaju SMA, Fronius, SolarEdge, Kostal, ABB/FIMER, Delta i drugi.
// Registri počinju oznakom "SunS" (na 40000, 0 ili 50000), a za njom slijede blokovi modela: ID, duljina, podaci.
//   inverter: 101/102/103 (cijeli brojevi + faktori skale) ili 111/112/113 (float32)
//   mjerač:   201–204 (cijeli brojevi + faktori skale) ili 211–214 (float32)
// SunSpec nema dnevnu energiju – samo ukupnu (WH); dnevnu računa poller iz ukupne (vidi poll_once).
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "config.hpp"
#include "modbus.hpp"

namespace sm {

struct Settings;
struct PlantReading;

struct SunSpecModel {
    uint16_t id = 0, length = 0;
    uint16_t address = 0;  // prvi registar podataka (iza ID-a i duljine)
};

// Čita `count` holding registara od `address` (baca ModbusError).
using RegisterReader = std::function<std::vector<uint16_t>(uint16_t address, uint16_t count)>;

// Popis modela na uređaju; prazno ako oznake "SunS" nema ni na jednoj početnoj adresi.
std::vector<SunSpecModel> sunspec_discover(const RegisterReader& read);
// Prvi model s ID-om iz [lo, hi].
std::optional<SunSpecModel> sunspec_find(const std::vector<SunSpecModel>& models, uint16_t lo, uint16_t hi);

// Podaci modela invertera (101–103, 111–113): snaga, ukupna energija, cos φ, stanje. e_daily_kwh = -1 (nepoznato).
Reading sunspec_inverter(uint16_t model_id, const std::vector<uint16_t>& data);
// Temperatura (TmpCab), napon faze A i frekvencija iz modela invertera – za widgete; neimplementirano se preskače.
json sunspec_extras(uint16_t model_id, const std::vector<uint16_t>& data);
// Ukupna radna snaga mjerača (W) iz modela 201–204 ili 211–214; nullopt ako je točka neimplementirana.
std::optional<double> sunspec_meter_w(uint16_t model_id, const std::vector<uint16_t>& data);
// Proizvođač i model iz zajedničkog modela 1 (za provjeru veze), npr. "Fronius Symo 10.0-3-M".
std::string sunspec_common_name(const std::vector<uint16_t>& data);

PlantReading read_sunspec(const Settings& s);

}  // namespace sm

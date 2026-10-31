// Uvoz povijesti dnevne proizvodnje iz izvoza SmartLoggera (web sučelje → izvoz logova SmartLoggera, log.zip).
// Modbus (ni SmartLogger ni SUN2000) ne daje povijest – samo današnju i ukupnu energiju – ali SmartLogger u izvozu
// logova sprema svoju bazu performansi; perfmg_day.emap ima dnevnu proizvodnju elektrane od puštanja u rad.
//
// perfmg_day.emap (little-endian): zaglavlje 8 B, zatim zapisi po 16 B
//   u16 uređaj (0x0002 = elektrana), u16 KPI (0x3011 = dnevna proizvodnja elektrane), u32 razdoblje,
//   u32 vrijeme (Unix, 00:00 UTC dana na koji se zapis odnosi), i32 vrijednost (0,01 kWh; -1 = nema podatka)
#pragma once

#include <map>
#include <string_view>

#include "storage.hpp"
#include "util.hpp"

namespace sm {

inline constexpr const char* kPerfmgDayFile = "perfmg_day.emap";

// Dnevna proizvodnja elektrane (kWh) po danima; ostali uređaji i KPI-jevi se preskaču.
std::map<Date, double> parse_perfmg_day(std::string_view bytes);

// Sadržaj perfmg_day.emap iz log.zip (i ZIP-ova u njemu), iz raspakirane mape ili sama .emap datoteka.
std::string read_perfmg_day(const fs::path& source);

struct ExportImport {
    int imported = 0;  // upisanih dana
    int skipped = 0;   // dana koje je poller već zabilježio (njegova očitanja ostaju)
    std::optional<Date> first, last;
    double kwh = 0;    // ukupno uvezeno
};

// Upiše po jedno očitanje (lokalno 23:00, E-daily = proizvodnja dana) za svaki dan prije `today`
// koji u bazi još nema očitanja – kao i stari uvoz povijesti, dnevni iznosi su MAX(E-daily).
ExportImport import_perfmg_days(Db& db, const std::map<Date, double>& days, Date today);

}  // namespace sm

// Zajednički pomoćni alati: UTF-8/UTF-16, putanje, zapisnik (log), vrijeme, datoteke.
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sm {

namespace fs = std::filesystem;

// ---------------------------------------------------------------- tekst
std::wstring widen(std::string_view s);
std::string narrow(std::wstring_view s);
std::string base64(const std::vector<uint8_t>& bytes);
std::string trim(std::string_view s);

// ---------------------------------------------------------------- putanje
// exe_dir: mapa programa (web/, assets/). home_dir: %ProgramData%\SolarniMonitor2 ili SOLARI2_HOME.
fs::path exe_dir();
fs::path home_dir();
fs::path data_dir();     // home/data: solar.db, layout.json, images/, backups/, logs/
fs::path config_file();  // home/config.json
fs::path db_file();
fs::path layout_file();
fs::path images_dir();
fs::path logs_dir();       // zapisi sučelja (data\logs)
fs::path backups_dir();    // 4.0: service\backups (piše samo SYSTEM)
// 4.0 (SMA-02): mapa u koju piše samo zadatak sustava (SYSTEM) – instalacija joj daje ACL samo za SYSTEM i
// administratore (Users čitanje): sigurnosne kopije, alerts.json, zapisi pollera i servisa
fs::path service_dir();
fs::path service_logs_dir();
// true ako ni jedna mapa od home_dir() do `dir` (uključivo) nije točka ponovne obrade (spojnica, simbolička veza);
// prije svakog upisa procesa SYSTEM – inače bi korisnik spojnicom preusmjerio upis u sistemsku mapu
bool no_reparse_points(const fs::path& dir);

// ---------------------------------------------------------------- zapisnik
enum class Level { Info, Warn, Error };
void log_open(const fs::path& file);  // rotacija na 2 MB, 3 stare datoteke
void log(Level level, std::string_view message);
inline void log_info(std::string_view m) { log(Level::Info, m); }
inline void log_warn(std::string_view m) { log(Level::Warn, m); }
inline void log_error(std::string_view m) { log(Level::Error, m); }

// ---------------------------------------------------------------- vrijeme
// Baza čuva UTC kao tekst "YYYY-MM-DD HH:MM:SS" (isto kao Python verzija – baze su međusobno prenosive).
// Lokalno vrijeme je vremenska zona računala (u Hrvatskoj Europe/Zagreb).
using Clock = std::chrono::system_clock;
using Date = std::chrono::year_month_day;

std::string utc_text(std::time_t t);
std::optional<std::time_t> parse_utc_text(std::string_view text);
std::tm local_tm(std::time_t t);
Date local_date(std::time_t t);
std::time_t local_midnight(Date d);  // početak lokalnog dana (DST ispravno preko mktime)
Date add_days(Date d, int days);
int days_between(Date a, Date b);  // b - a
std::string iso_date(Date d);      // "2026-10-29"
std::time_t now();

// ---------------------------------------------------------------- datoteke
std::optional<std::string> read_file(const fs::path& path);
void write_file_atomic(const fs::path& path, std::string_view content);  // privremena + zamjena
void write_private_file(const fs::path& path, std::string_view content);  // nova datoteka (CREATE_NEW) samo za vlasnika, SYSTEM i administratore

}  // namespace sm

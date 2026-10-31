#include "util.hpp"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>

namespace sm {

// ---------------------------------------------------------------- tekst
std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(std::wstring_view s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string base64(const std::vector<uint8_t>& bytes) {
    static constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < bytes.size(); i += 3) {
        uint32_t v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        for (int k = 18; k >= 0; k -= 6) out += kTable[(v >> k) & 63];
    }
    if (i < bytes.size()) {
        uint32_t v = bytes[i] << 16;
        if (i + 1 < bytes.size()) v |= bytes[i + 1] << 8;
        out += kTable[(v >> 18) & 63];
        out += kTable[(v >> 12) & 63];
        out += i + 1 < bytes.size() ? kTable[(v >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

std::string trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(first, last - first + 1));
}

// ---------------------------------------------------------------- putanje
fs::path exe_dir() {
    std::wstring buf(MAX_PATH, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    buf.resize(n);
    return fs::path(buf).parent_path();
}

fs::path home_dir() {
    if (const wchar_t* env = _wgetenv(L"SOLARI2_HOME"); env && *env) return fs::path(env);
    const wchar_t* pd = _wgetenv(L"PROGRAMDATA");
    return fs::path(pd ? pd : L"C:\\ProgramData") / L"SolarniMonitor2";
}

fs::path data_dir() { return home_dir() / L"data"; }
fs::path config_file() { return home_dir() / L"config.json"; }
fs::path db_file() { return data_dir() / L"solar.db"; }
fs::path layout_file() { return data_dir() / L"layout.json"; }
fs::path images_dir() { return data_dir() / L"images"; }
fs::path logs_dir() { return data_dir() / L"logs"; }
fs::path backups_dir() { return data_dir() / L"backups"; }

// ---------------------------------------------------------------- zapisnik
namespace {
std::mutex g_log_mutex;
fs::path g_log_file;
constexpr uintmax_t kLogMaxBytes = 2'000'000;
constexpr int kLogBackups = 3;

void rotate_if_needed() {
    std::error_code ec;
    if (g_log_file.empty() || fs::file_size(g_log_file, ec) < kLogMaxBytes || ec) return;
    for (int i = kLogBackups - 1; i >= 1; --i) {
        fs::rename(g_log_file.wstring() + L"." + std::to_wstring(i), g_log_file.wstring() + L"." + std::to_wstring(i + 1), ec);
    }
    fs::rename(g_log_file, g_log_file.wstring() + L".1", ec);
}
}  // namespace

void log_open(const fs::path& file) {
    std::lock_guard lock(g_log_mutex);
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    g_log_file = file;
}

void log(Level level, std::string_view message) {
    std::lock_guard lock(g_log_mutex);
    const char* tag = level == Level::Info ? "INFO   " : level == Level::Warn ? "WARNING" : "ERROR  ";
    const std::tm t = local_tm(now());
    std::ostringstream line;
    line << std::put_time(&t, "%Y-%m-%d %H:%M:%S") << ' ' << tag << ' ' << message << '\n';
    OutputDebugStringW(widen(line.str()).c_str());
    if (g_log_file.empty()) return;
    rotate_if_needed();
    std::ofstream out(g_log_file, std::ios::app | std::ios::binary);
    out << line.str();
}

// ---------------------------------------------------------------- vrijeme
std::time_t now() { return Clock::to_time_t(Clock::now()); }

std::string utc_text(std::time_t t) {
    std::tm tm{};
    gmtime_s(&tm, &t);
    char buf[24];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::optional<std::time_t> parse_utc_text(std::string_view text) {
    std::tm tm{};
    std::istringstream in{std::string(text)};
    in >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (in.fail()) return std::nullopt;
    return _mkgmtime(&tm);
}

std::tm local_tm(std::time_t t) {
    std::tm tm{};
    localtime_s(&tm, &t);
    return tm;
}

Date local_date(std::time_t t) {
    const std::tm tm = local_tm(t);
    return Date{std::chrono::year{tm.tm_year + 1900}, std::chrono::month{static_cast<unsigned>(tm.tm_mon + 1)},
                std::chrono::day{static_cast<unsigned>(tm.tm_mday)}};
}

std::time_t local_midnight(Date d) {
    std::tm tm{};
    tm.tm_year = static_cast<int>(d.year()) - 1900;
    tm.tm_mon = static_cast<int>(static_cast<unsigned>(d.month())) - 1;
    tm.tm_mday = static_cast<int>(static_cast<unsigned>(d.day()));
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

Date add_days(Date d, int days) { return Date{std::chrono::sys_days{d} + std::chrono::days{days}}; }

int days_between(Date a, Date b) { return static_cast<int>((std::chrono::sys_days{b} - std::chrono::sys_days{a}).count()); }

std::string iso_date(Date d) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%04d-%02u-%02u", static_cast<int>(d.year()), static_cast<unsigned>(d.month()),
                  static_cast<unsigned>(d.day()));
    return buf;
}

// ---------------------------------------------------------------- datoteke
std::optional<std::string> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void write_file_atomic(const fs::path& path, std::string_view content) {
    fs::create_directories(path.parent_path());
    fs::path tmp = path;
    tmp += L".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("Datoteka se ne može zapisati: " + narrow(tmp.wstring()));
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        throw std::runtime_error("Datoteka se ne može zamijeniti: " + narrow(path.wstring()));
    }
}

}  // namespace sm

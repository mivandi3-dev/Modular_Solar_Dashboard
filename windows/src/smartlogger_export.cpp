#include "smartlogger_export.hpp"

#include <windows.h>

#include <cstring>

#include "i18n.hpp"
#include "system.hpp"

namespace sm {

namespace {
constexpr size_t kHeaderSize = 8, kRecordSize = 16;
constexpr uint16_t kPlantDevice = 0x0002, kKpiPlantDayYield = 0x3011;
constexpr int32_t kNoValue = -1;
constexpr uint32_t kFirstValidTs = 946'684'800;  // 1. 1. 2000.
constexpr double kValueGain = 100;            // 0,01 kWh
constexpr unsigned kExtractTimeoutMs = 180'000;
constexpr int kImportHour = 23;               // lokalno – mora biti >= kEDailyFromHour (data.hpp)

template <typename T>
T le(std::string_view b, size_t at) {
    T v{};
    std::memcpy(&v, b.data() + at, sizeof(T));  // x64 je little-endian, kao i SmartLogger
    return v;
}

// PowerShell (Expand-Archive) postoji i na Windows Serveru 2016; tar.exe tek od Windowsa 10 1803.
void extract_zip(const fs::path& zip, const fs::path& dir) {
    auto quote = [](std::wstring s) {
        for (size_t i = 0; (i = s.find(L'\'', i)) != std::wstring::npos; i += 2) s.insert(i, 1, L'\'');
        return L"'" + s + L"'";
    };
    const std::wstring cmd = L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
                             L"$ProgressPreference='SilentlyContinue'; Expand-Archive -LiteralPath " + quote(zip.wstring()) +
                             L" -DestinationPath " + quote(dir.wstring()) + L" -Force\"";
    const ProcessResult r = run_capture(cmd, kExtractTimeoutMs);
    if (r.exit_code != 0) {
        throw std::runtime_error(tr("Arhivu nije moguće raspakirati: {error}",
                                    {{"error", r.output.empty() ? std::to_string(r.exit_code) : r.output.substr(0, 300)}}));
    }
}

std::optional<fs::path> find_day_file(const fs::path& dir) {
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(dir, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (it->is_regular_file(ec) && it->path().filename() == kPerfmgDayFile) return it->path();
    }
    return std::nullopt;
}

struct TempDir {
    fs::path path = fs::temp_directory_path() / (L"solari_smartlogger_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                                                 std::to_wstring(GetTickCount64()));
    TempDir() { fs::create_directories(path); }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string read_day_file(const fs::path& file) {
    auto bytes = read_file(file);
    if (!bytes) throw std::runtime_error(tr("Datoteku nije moguće pročitati."));
    return *bytes;
}

std::string not_found() {
    return tr("U izvozu nema datoteke {file} – izvezite logove SmartLoggera (ne invertera).", {{"file", kPerfmgDayFile}});
}
}  // namespace

std::map<Date, double> parse_perfmg_day(std::string_view bytes) {
    if (bytes.size() < kHeaderSize + kRecordSize) throw std::runtime_error(tr("Datoteka nije izvoz SmartLoggera."));
    std::map<Date, double> days;
    for (size_t at = kHeaderSize; at + kRecordSize <= bytes.size(); at += kRecordSize) {
        const auto device = le<uint16_t>(bytes, at), kpi = le<uint16_t>(bytes, at + 2);
        const auto ts = le<uint32_t>(bytes, at + 8);
        const auto value = le<int32_t>(bytes, at + 12);
        if (device != kPlantDevice || kpi != kKpiPlantDayYield || value == kNoValue || value < 0) continue;
        if (ts < kFirstValidTs) continue;  // prazni zapisi (vrijeme 0 = 1970.)
        const Date day{std::chrono::floor<std::chrono::days>(Clock::from_time_t(static_cast<std::time_t>(ts)))};
        days[day] = value / kValueGain;
    }
    return days;
}

std::string read_perfmg_day(const fs::path& source) {
    std::error_code ec;
    if (fs::is_directory(source, ec)) {
        const auto file = find_day_file(source);
        if (!file) throw std::runtime_error(not_found());
        return read_day_file(*file);
    }
    std::string ext = narrow(source.extension().wstring());
    for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (ext != ".zip") return read_day_file(source);
    TempDir tmp;
    extract_zip(source, tmp.path);
    if (const auto file = find_day_file(tmp.path)) return read_day_file(*file);
    // izvoz može imati ZIP po uređaju – raspakiraj i njih (jedna razina)
    std::vector<fs::path> inner;
    for (auto it = fs::recursive_directory_iterator(tmp.path, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (it->is_regular_file(ec) && it->path().extension() == L".zip") inner.push_back(it->path());
    }
    for (size_t i = 0; i < inner.size(); ++i) {
        const fs::path dir = tmp.path / (L"z" + std::to_wstring(i));
        extract_zip(inner[i], dir);
        if (const auto file = find_day_file(dir)) return read_day_file(*file);
    }
    throw std::runtime_error(not_found());
}

ExportImport import_perfmg_days(Db& db, const std::map<Date, double>& days, Date today) {
    ExportImport out;
    for (const auto& [day, kwh] : days) {
        if (day >= today) continue;
        const std::time_t start = local_midnight(day), end = local_midnight(add_days(day, 1));
        if (db.count_between(start, end) > 0) {
            ++out.skipped;
            continue;
        }
        db.insert_day_yield(end - (24 - kImportHour) * 3600, kwh);
        ++out.imported;
        out.kwh += kwh;
        if (!out.first) out.first = day;
        out.last = day;
    }
    return out;
}

}  // namespace sm

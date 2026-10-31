// 4.0 (SMA-02, W4) – broker postavki klijenta.
// Sučelje (SolarniMonitor.exe) uvijek radi kao prijavljeni korisnik i u produkciji ne smije pisati u
// %ProgramData%\SolarniMonitor2 (config.json, data\). Sve izmjene idu kroz uski posrednik u zadatku sustava
// (SolarniMonitor.exe --poller, SYSTEM) preko kanala \\.\pipe\SolarniMonitor2.Settings.v1:
//   * DACL kanala: SYSTEM i administratori puno, INTERACTIVE samo čitanje/pisanje podataka (bez stvaranja instance);
//   * vlasnik kanala je SYSTEM – sučelje to provjerava prije slanja (zaštita od preuzimanja imena);
//   * svaka izmjena nosi PIN postavki (PBKDF2; 5 pogrešnih → izmjene zaključane 15 min); PIN postavlja instalacija;
//   * zatvoren popis operacija, nijedna ne prima put datoteke; isti validator obrasca kao prije (validate_form);
//   * tajne idu u secrets\secrets.json (SYSTEM + administratori), SMTP lozinka nikad ne napušta broker.
#pragma once

#include <ctime>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "config.hpp"
#include "ipc.hpp"

namespace sm {

inline constexpr wchar_t kBrokerPipe[] = L"\\\\.\\pipe\\SolarniMonitor2.Settings.v1";
// O:SY – vlasnik SYSTEM; 0x12018b = čitanje, upis podataka i atributa, bez FILE_CREATE_PIPE_INSTANCE
inline constexpr wchar_t kBrokerSddl[] = L"O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12018b;;;IU)";
inline constexpr int kBrokerMaxPinFailures = 5;
inline constexpr int kBrokerLockoutS = 15 * 60;
inline constexpr size_t kBrokerMaxRows = 500;  // redaka povijesti po zahtjevu (okvir ≤ 64 KB)

// Logika brokera bez kanala (testira se izravno). Radi nad home_dir() procesa.
class BrokerCore {
public:
    using Interfaces = std::function<std::vector<std::string>()>;
    using Clock = std::function<std::time_t()>;
    explicit BrokerCore(Interfaces interfaces, Clock clock = nullptr);

    // {op, ...} → {ok, ...}; nepoznata operacija ili neispravan tip polja → {ok:false, error:"bad_request"}
    json handle(const json& request, const std::wstring& caller_sid);

private:
    json state(const Settings& s) const;
    // nullopt = PIN je ispravan; inače odgovor s greškom (pin_required, pin_invalid, locked)
    std::optional<json> check_pin(const json& request, const Settings& s);
    json save_form(const json& request, const std::wstring& caller);
    json store_cloud_login(const json& request);
    json import_rows(const json& request);
    json import_days(const json& request);

    Interfaces interfaces_;
    Clock clock_;
    std::mutex mutex_;  // jedan zahtjev u isto vrijeme (broker je u produkciji jedini pisac postavki)
    int failures_ = 0;
    std::time_t locked_until_ = 0;
};

// Zadatak sustava: kanal brokera (baca ako ime već postoji – drugi proces drži kanal).
class BrokerServer {
public:
    // name/sddl samo za testove (proces koji nije SYSTEM ne može postaviti vlasnika O:SY)
    explicit BrokerServer(BrokerCore::Interfaces interfaces, std::wstring name = kBrokerPipe, std::wstring sddl = kBrokerSddl);
    void start();
    void stop();

private:
    BrokerCore core_;
    ipc::PipeServer server_;
};

// Sučelje: jedan poziv brokera (provjerava da je vlasnik kanala SYSTEM). Baca ipc::PipeError.
json broker_call(const json& request, const std::wstring& name = kBrokerPipe, const std::wstring& owner_sid = ipc::kSystemSid);

// Prije pokretanja brokera: mapa postavki ne smije davati Users pravo upisa ni biti spojnica (fail-closed).
// Vraća opis problema ili "" ako je sve u redu.
std::string broker_home_problem();

// Instalacija (administrator): PIN iz datoteke (prvi redak, 4–8 znamenki); datoteka se poslije briše.
int set_pin_from_file(const fs::path& file);

}  // namespace sm

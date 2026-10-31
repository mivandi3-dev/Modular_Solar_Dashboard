// 4.0 – lokalni IPC preko imenovanih kanala (Windows Named Pipe), zajednički za:
//   * broker postavki (SMA-02, W4): \\.\pipe\SolarniMonitor2.Settings.v1 u zadatku sustava (SYSTEM), klijent je sučelje;
//   * API poslužitelja (B1, ADR-001): \\.\pipe\SolarniServer.Api.v1 u servisu poslužitelja (SYSTEM), klijent je
//     Rust gateway (NT SERVICE\SolariGateway).
//
// Okvir: 4 bajta duljine (little-endian) + UTF-8 JSON objekt. Kanal je u načinu bajtova, s
// PIPE_REJECT_REMOTE_CLIENTS i FILE_FLAG_FIRST_PIPE_INSTANCE (ako ime već postoji, poslužitelj se ne pokreće).
// Nakon spajanja poslužitelj šalje {"v":1,"type":"hello","nonce":"<64 hex>"}; svaki zahtjev mora vratiti isti
// "nonce" (vezivanje uz vezu – nakon ponovnog pokretanja bilo koje strane stare veze ne vrijede).
// Poslužitelj provjerava klijenta (SID korisnika procesa), klijent provjerava vlasnika kanala (SID).
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

namespace sm::ipc {

using json = nlohmann::json;

inline constexpr int kProtocolVersion = 1;
inline constexpr size_t kMaxRequestBytes = 64 * 1024;         // zahtjev (ADR §3)
inline constexpr size_t kMaxResponseBytes = 16 * 1024 * 1024;  // odgovor (slike u base64)
inline constexpr wchar_t kSystemSid[] = L"S-1-5-18";

// ---------------------------------------------------------------- okvir (bez Windows API-ja – fuzz i testovi)
std::string encode_frame(const json& message);  // baca std::length_error ako je JSON veći od kMaxResponseBytes
enum class DecodeStatus { Ok, NeedMore, TooLarge, BadJson, NotObject };
struct Decoded {
    DecodeStatus status = DecodeStatus::NeedMore;
    json message;
    size_t consumed = 0;  // bajtova okvira (samo za Ok)
};
// Prvi okvir iz međuspremnika; ne baca iznimke ni za kakav ulaz.
Decoded decode_frame(std::string_view buffer, size_t max_bytes);

// ---------------------------------------------------------------- SID-ovi
std::wstring service_sid(std::wstring_view service_name);  // NT SERVICE\<ime> → S-1-5-80-… (SHA-1 velikih slova)
std::wstring current_user_sid();
std::optional<std::wstring> process_user_sid(uint32_t pid);
std::optional<std::wstring> handle_owner_sid(void* handle);  // vlasnik sigurnosnog opisnika objekta jezgre

// ---------------------------------------------------------------- poslužitelj kanala
struct Caller {
    uint32_t pid = 0;
    std::wstring sid;  // SID korisnika procesa klijenta
};

struct PipeServerConfig {
    std::wstring name;              // npr. L"\\\\.\\pipe\\SolarniMonitor2.Settings.v1"
    std::wstring sddl;              // DACL (i vlasnik "O:SY" u produkciji)
    int instances = 2;              // istodobne veze
    uint32_t io_timeout_ms = 10'000;    // čitanje okvira koji je započeo, upis odgovora
    uint32_t idle_timeout_ms = 10'000;  // čekanje sljedećeg zahtjeva (0 = bez roka)
    int requests_per_connection = 1;    // 0 = neograničeno (gateway drži vezu otvorenom)
    size_t max_request_bytes = kMaxRequestBytes;
    // true = klijent smije; false = veza se prekida bez odgovora (zapisuje se u zapisnik)
    std::function<bool(const Caller&)> authorize;
};

class PipeServer {
public:
    using Handler = std::function<json(const json& request, const Caller& caller)>;
    PipeServer(PipeServerConfig config, Handler handler);
    ~PipeServer();
    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    // Baca std::runtime_error ako ime već postoji (preuzimanje imena) ili se kanal ne može stvoriti.
    void start();
    void stop();
    uint64_t rejected() const { return rejected_; }  // odbijeni klijenti i neispravne poruke (za testove)

private:
    void instance_loop(void* pipe);
    void serve(void* pipe, void* event);
    void* create_instance(bool first);

    PipeServerConfig config_;
    Handler handler_;
    void* stop_event_ = nullptr;
    std::vector<std::thread> threads_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> rejected_{0};
};

// ---------------------------------------------------------------- klijent kanala
struct PipeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};
// Jedan zahtjev: spajanje, provjera vlasnika kanala (expected_owner_sid), hello, zahtjev s nonceom, odgovor.
// Baca PipeError (kanal ne postoji, krivi vlasnik, rok, neispravan odgovor).
json pipe_call(const std::wstring& name, json request, const std::wstring& expected_owner_sid, uint32_t timeout_ms = 10'000,
               size_t max_response_bytes = kMaxResponseBytes);

// Kanal ne postoji (servis ne radi) – za poruku korisniku
bool pipe_exists(const std::wstring& name);

}  // namespace sm::ipc

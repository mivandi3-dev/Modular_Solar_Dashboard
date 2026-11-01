// Korisnici Solarnog poslužitelja (3.0) – zamjenjuju API ključ.
//
// Zaštita:
//   * lozinka: PBKDF2-HMAC-SHA256, 600 000 ponavljanja, 16 B slučajne soli po korisniku – ne može se vratiti
//   * ime, prezime, e-pošta: AES-256-GCM (aad = naziv polja); prijava po e-pošti preko HMAC-a male e-pošte,
//     pa ni pretraga ne otkriva adresu
//   * ključevi (AES i HMAC) u data\users.key, zaštićeni DPAPI-jem računala – baza sama po sebi ne otkriva ništa
//   * prijava: slučajna oznaka od 32 B; baza čuva samo njezin SHA-256. Vrijedi 30 dana od zadnjeg korištenja,
//     najdulje 90 dana (4.0); promjena lozinke, blokiranje, brisanje ili „Odjavi sve uređaje” poništava prijave
//   * novi korisnik (4.0, SMA-03): nema zajedničke početne lozinke – administrator dobiva jednokratni aktivacijski kod
//     (12 znakova, ~60 bita, vrijedi 72 h); u bazi je samo njegov PBKDF2; prijava kodom traži postavljanje vlastite lozinke
//   * 5 pogrešnih lozinaka zaredom → račun zaključan 15 minuta; nepoznata e-pošta troši isto vrijeme kao poznata
//   * dvofaktorska prijava (3.1, src/totp.cpp): administrator je uključi korisniku; pri sljedećoj prijavi korisnik
//     skenira QR kod u aplikaciji autentifikatoru i potvrdi prvi kod. Tajna je šifrirana (AES-GCM), isti kod ne vrijedi
//     dvaput, pogrešni kodovi broje se u zaključavanje, a 8 jednokratnih kodova za oporavak čuva se kao SHA-256
#pragma once

#include <ctime>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "util.hpp"

struct sqlite3;

namespace sm {

inline constexpr uint32_t kPasswordIterations = 600'000;
// Jednokratni aktivacijski kod (4.0, SMA-03): slučajan za svakog korisnika, vrijedi 72 sata
inline constexpr size_t kActivationCodeChars = 12;  // base32 → 60 bita
inline constexpr std::time_t kActivationSeconds = 72 * 3600;
inline constexpr int kUsersSchemaVersion = 2;  // 4.0; 2 = R-14a (login_failures); 1 se nadogradi; bez verzije (3.x) se odbija
inline constexpr size_t kMinPasswordLength = 10;
// 4.0 (SMA-14, R-14a): zaključavanje po paru (račun, izvor) – 5 pogrešnih s istog izvora zaključava samo taj izvor 15 min.
// Izvor = rate_limit_key adrese klijenta (IPv6 po /64, iza tunela CF-Connecting-IP) ili "local" (prozor poslužitelja).
inline constexpr int kMaxFailedLogins = 5;
inline constexpr std::time_t kLockSeconds = 15 * 60;
inline constexpr const char* kLoginSourceLocal = "local";
// Raspodijeljeni napad: više od 50 neuspjeha u 24 h na jedan račun → udaljeni izvori najviše 1 pokušaj u minuti
// (lokalni prozor je izuzet, račun se ne zaključava), a administrator dobiva upozorenje (set_alert_handler)
inline constexpr int kAccountSoftLimit = 50;
inline constexpr std::time_t kAccountWindowSeconds = 24 * 3600;
inline constexpr std::time_t kThrottleSeconds = 60;
// Zaboravljena lozinka (4.0, samoposluživanje): kod XXXX-XXXX (8 znakova base32, 40 bita) e-poštom; vrijedi 30 min,
// najviše 5 pogrešnih pokušaja po kodu, novi kod najranije za 2 min. Stara lozinka vrijedi dok se kod ne iskoristi
// (zahtjev ne može zaključati tuđi račun); u bazi samo PBKDF2 koda. Svaka promjena lozinke poništava neiskorišteni kod.
inline constexpr size_t kResetCodeChars = 8;
inline constexpr std::time_t kResetSeconds = 30 * 60;
inline constexpr std::time_t kResetResendSeconds = 120;
inline constexpr int kResetMaxTries = 5;
inline constexpr std::time_t kSessionIdleSeconds = 30 * 24 * 3600;
inline constexpr std::time_t kSessionMaxSeconds = 90 * 24 * 3600;

enum class Role { Admin, User };
std::string role_name(Role r);                       // "admin" / "user"
std::optional<Role> parse_role(const std::string& s);

struct UserKeys {
    Bytes aes;   // 32 B – šifriranje osobnih podataka
    Bytes hmac;  // 32 B – oznaka e-pošte za pretragu
};
UserKeys load_or_create_user_keys(const fs::path& key_file);  // DPAPI (računalo)

struct UserInfo {
    int64_t id = 0;
    Role role = Role::User;
    std::string first_name, last_name, email;
    bool disabled = false;
    bool totp_required = false;  // administrator je uključio dvofaktorsku prijavu
    bool totp_enabled = false;   // korisnik ju je postavio (skenirao QR kod)
    int recovery_left = 0;       // neiskorišteni kodovi za oporavak
    bool activation_pending = false;    // aktivacijski kod još nije iskorišten
    std::time_t activation_until = 0;   // do kada kod vrijedi
    std::time_t created = 0, last_login = 0, locked_until = 0;
};

struct UserInput {  // novi korisnik ili izmjena (prazna lozinka: novi = aktivacijski kod, izmjena = ne mijenja se)
    std::string first_name, last_name, email, password;
    Role role = Role::User;
    bool totp_required = false;
};

// Greške unosa po poljima (ključevi: first_name, last_name, email, password, role, general)
struct UserError : std::runtime_error {
    std::map<std::string, std::string> fields;
    explicit UserError(std::map<std::string, std::string> f);
};

std::optional<std::string> password_problem(const std::string& password, const std::string& email);  // nullopt = u redu
bool valid_email(const std::string& email);

// Zahtjev za kod: send = false za nepoznatu e-poštu, blokiran račun ili prečest zahtjev (odgovor korisniku je uvijek isti)
struct ResetRequest {
    bool send = false;
    std::string email, first_name, code;
    std::time_t valid_until = 0;
};
struct ResetResult {
    enum class Status { Ok, BadCode, PasswordInvalid } status = Status::BadCode;
    std::string problem;  // PasswordInvalid: poruka za korisnika
};

struct LoginResult {
    // TotpRequired: lozinka točna, treba kod iz aplikacije; TotpSetup: treba postaviti aplikaciju (QR kod u totp_uri);
    // TotpInvalid: kod ne vrijedi (broji se u zaključavanje)
    // ActivationRequired: aktivacijski kod je točan – treba nova lozinka (polje new_password); PasswordInvalid: nova ne
    // zadovoljava pravila (problem). Istekao kod = BadCredentials (ne otkriva se je li račun postojao).
    // Locked/Disabled vraćaju se samo uz točnu lozinku (SMA-13); inače BadCredentials kao za nepostojeći račun.
    enum class Status { Ok, BadCredentials, Locked, Disabled, TotpRequired, TotpSetup, TotpInvalid, ActivationRequired,
                        PasswordInvalid } status = Status::BadCredentials;
    std::string problem;  // PasswordInvalid: poruka za korisnika
    std::string token;          // samo pri uspjehu – klijent ga šalje kao "Authorization: Bearer <token>"
    std::optional<UserInfo> user;
    std::string totp_secret, totp_uri;        // samo pri postavljanju (TotpSetup, TotpInvalid prije postavljanja)
    std::vector<std::string> recovery_codes;  // samo jednom – odmah nakon postavljanja
};

class UserStore {
public:
    UserStore(const fs::path& db_path, UserKeys keys, uint32_t iterations = kPasswordIterations);
    ~UserStore();
    UserStore(const UserStore&) = delete;
    UserStore& operator=(const UserStore&) = delete;

    bool has_admin();
    // baca UserError; bez lozinke: *activation_code = jednokratni kod (prikazuje se administratoru samo jednom)
    int64_t create(const UserInput& in, std::time_t now, std::string* activation_code = nullptr);
    void update(int64_t id, const UserInput& in, std::time_t now);        // baca UserError
    void set_disabled(int64_t id, bool disabled, std::time_t now);        // baca UserError (zadnji administrator)
    void remove(int64_t id);                                              // baca UserError (zadnji administrator)
    std::vector<UserInfo> list();
    std::optional<UserInfo> get(int64_t id);

    LoginResult login(const std::string& email, std::string password, const std::string& device, std::time_t now,
                      const std::string& totp = {},           // kod iz aplikacije autentifikatora ili kod za oporavak
                      std::string new_password = {},          // vlastita lozinka pri aktivaciji
                      const std::string& source = kLoginSourceLocal);  // R-14a: izvor pokušaja
    // R-14a: poziva se jednom po razdoblju kad račun prijeđe kAccountSoftLimit neuspjeha u 24 h (npr. e-poruka administratoru)
    void set_alert_handler(std::function<void(const std::string& message)> handler) { alert_ = std::move(handler); }
    std::string issue_activation_code(int64_t id, std::time_t now);  // administrator: novi kod (stara lozinka i prijave prestaju)
    void revoke_all_sessions(int64_t id);                          // administrator: „Odjavi sve uređaje”
    void reset_totp(int64_t id, std::time_t now);     // izgubljen mobitel: ponovno postavljanje pri sljedećoj prijavi
    std::optional<UserInfo> session_user(const std::string& token, std::time_t now);  // produžuje prijavu
    void logout(const std::string& token);
    void change_password(int64_t id, const std::string& old_password, const std::string& new_password, std::time_t now);
    // Zaboravljena lozinka: kod za e-poštu, zatim nova lozinka uz kod (prijave se poništavaju, aktivacija na čekanju završava)
    ResetRequest request_password_reset(const std::string& email, std::time_t now);
    ResetResult reset_password(const std::string& email, const std::string& code, std::string new_password, std::time_t now);
    int active_sessions(int64_t id, std::time_t now);

private:
    struct Row;
    std::optional<Row> row_by_id(int64_t id);
    std::optional<Row> row_by_email(const std::string& email);
    UserInfo info(const Row& r);
    Bytes email_tag(const std::string& email) const;
    Bytes seal(const std::string& field, const std::string& value) const;
    std::string open(const std::string& field, const Bytes& sealed) const;
    void validate(const UserInput& in, bool require_password, std::optional<int64_t> self);
    void set_password_hash(int64_t id, const std::string& password, std::time_t now, bool activation = false);
    std::string new_activation_code(int64_t id, std::time_t now);
    bool verify_password(const Row& r, const std::string& password) const;
    void revoke_sessions(int64_t id);
    bool second_factor(const Row& r, const std::string& code, std::time_t now, LoginResult& res);
    void count_failure(const Row& r, std::time_t now, LoginResult& res, LoginResult::Status status);
    struct SourceState {
        int failed = 0;
        std::time_t locked_until = 0, last_attempt = 0;
    };
    SourceState source_state(int64_t id, const std::string& source);
    void touch_source(int64_t id, const std::string& source, std::time_t now);
    bool account_throttled(int64_t id, std::time_t now);
    void clear_failures(int64_t id);
    void migrate();
    int admins_enabled(std::optional<int64_t> except);

    std::recursive_mutex mu_;  // API, prozor poslužitelja i radna nit dijele spremište
    sqlite3* db_ = nullptr;
    std::string source_ = kLoginSourceLocal;  // izvor prijave u tijeku (pod mu_)
    std::function<void(const std::string&)> alert_;
    UserKeys keys_;
    uint32_t iterations_;
};

}  // namespace sm

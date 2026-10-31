// Korisnici Solarnog poslužitelja (3.0) – zamjenjuju API ključ.
//
// Zaštita:
//   * lozinka: PBKDF2-HMAC-SHA256, 600 000 ponavljanja, 16 B slučajne soli po korisniku – ne može se vratiti
//   * ime, prezime, e-pošta: AES-256-GCM (aad = naziv polja); prijava po e-pošti preko HMAC-a male e-pošte,
//     pa ni pretraga ne otkriva adresu
//   * ključevi (AES i HMAC) u data\users.key, zaštićeni DPAPI-jem računala – baza sama po sebi ne otkriva ništa
//   * prijava: slučajna oznaka od 32 B; baza čuva samo njezin SHA-256. Vrijedi 30 dana od zadnjeg korištenja,
//     najdulje 180 dana; promjena lozinke, blokiranje ili brisanje korisnika poništava sve njegove prijave
//   * 5 pogrešnih lozinaka zaredom → račun zaključan 15 minuta; nepoznata e-pošta troši isto vrijeme kao poznata
//   * dvofaktorska prijava (3.1, src/totp.cpp): administrator je uključi korisniku; pri sljedećoj prijavi korisnik
//     skenira QR kod u aplikaciji autentifikatoru i potvrdi prvi kod. Tajna je šifrirana (AES-GCM), isti kod ne vrijedi
//     dvaput, pogrešni kodovi broje se u zaključavanje, a 8 jednokratnih kodova za oporavak čuva se kao SHA-256
#pragma once

#include <ctime>
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
// Početna lozinka novog korisnika (3.3): mora se promijeniti pri prvoj prijavi i vrijedi samo 7 dana – svima je ista,
// pa do prve prijave račun može preuzeti tko zna e-poštu; nakon roka administrator je postavlja ponovno.
inline constexpr char kDefaultPassword[] = "12345678";
inline constexpr std::time_t kDefaultPasswordSeconds = 7 * 24 * 3600;
inline constexpr size_t kMinPasswordLength = 10;
inline constexpr int kMaxFailedLogins = 5;
inline constexpr std::time_t kLockSeconds = 15 * 60;
inline constexpr std::time_t kSessionIdleSeconds = 30 * 24 * 3600;
inline constexpr std::time_t kSessionMaxSeconds = 180 * 24 * 3600;

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
    bool must_change_password = false;  // početna lozinka – mora je promijeniti pri prvoj prijavi
    std::time_t default_password_until = 0;
    std::time_t created = 0, last_login = 0, locked_until = 0;
};

struct UserInput {  // novi korisnik ili izmjena (prazna lozinka: novi = početna 12345678, izmjena = ne mijenja se)
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

struct LoginResult {
    // TotpRequired: lozinka točna, treba kod iz aplikacije; TotpSetup: treba postaviti aplikaciju (QR kod u totp_uri);
    // TotpInvalid: kod ne vrijedi (broji se u zaključavanje)
    // PasswordChange: lozinka je početna – treba nova (polje new_password); PasswordInvalid: nova ne zadovoljava pravila
    // (problem); PasswordExpired: početna lozinka je istekla (7 dana) – administrator je postavlja ponovno
    enum class Status { Ok, BadCredentials, Locked, Disabled, TotpRequired, TotpSetup, TotpInvalid, PasswordChange,
                        PasswordInvalid, PasswordExpired } status = Status::BadCredentials;
    std::string problem;  // PasswordInvalid: poruka za korisnika
    std::string token;          // samo pri uspjehu – klijent ga šalje kao "Authorization: Bearer <token>"
    std::optional<UserInfo> user;
    std::time_t locked_until = 0;
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
    int64_t create(const UserInput& in, std::time_t now);                 // baca UserError
    void update(int64_t id, const UserInput& in, std::time_t now);        // baca UserError
    void set_disabled(int64_t id, bool disabled, std::time_t now);        // baca UserError (zadnji administrator)
    void remove(int64_t id);                                              // baca UserError (zadnji administrator)
    std::vector<UserInfo> list();
    std::optional<UserInfo> get(int64_t id);

    LoginResult login(const std::string& email, std::string password, const std::string& device, std::time_t now,
                      const std::string& totp = {},           // kod iz aplikacije autentifikatora ili kod za oporavak
                      std::string new_password = {});         // nova lozinka umjesto početne (prva prijava)
    void reset_to_default_password(int64_t id, std::time_t now);  // administrator: ponovno početna lozinka (7 dana)
    void reset_totp(int64_t id, std::time_t now);     // izgubljen mobitel: ponovno postavljanje pri sljedećoj prijavi
    std::optional<UserInfo> session_user(const std::string& token, std::time_t now);  // produžuje prijavu
    void logout(const std::string& token);
    void change_password(int64_t id, const std::string& old_password, const std::string& new_password, std::time_t now);
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
    void set_password_hash(int64_t id, const std::string& password, std::time_t now, bool must_change = false);
    bool verify_password(const Row& r, const std::string& password) const;
    void revoke_sessions(int64_t id);
    bool second_factor(const Row& r, const std::string& code, std::time_t now, LoginResult& res);
    void count_failure(const Row& r, std::time_t now, LoginResult& res, LoginResult::Status status);
    void migrate();
    int admins_enabled(std::optional<int64_t> except);

    std::recursive_mutex mu_;  // API, prozor poslužitelja i radna nit dijele spremište
    sqlite3* db_ = nullptr;
    UserKeys keys_;
    uint32_t iterations_;
};

}  // namespace sm

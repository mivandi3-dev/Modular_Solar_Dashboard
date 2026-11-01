#include "users.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <semaphore>
#include <set>
#include <stdexcept>

#include "i18n.hpp"
#include "secret.hpp"
#include "totp.hpp"

#include <nlohmann/json.hpp>

namespace sm {

using json = nlohmann::json;

namespace {

constexpr const char* kSchema =
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, role TEXT NOT NULL, email_tag BLOB NOT NULL UNIQUE,"
    " first_enc BLOB NOT NULL, last_enc BLOB NOT NULL, email_enc BLOB NOT NULL, pw_salt BLOB, pw_hash BLOB,"
    " pw_iter INTEGER, disabled INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,"
    " locked_until INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL,"
    " last_login INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS sessions (token_hash BLOB PRIMARY KEY, user_id INTEGER NOT NULL, device_enc BLOB,"
    " created INTEGER NOT NULL, last_used INTEGER NOT NULL);"
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);"
    // 4.0 (R-14a): neuspjesi i zaključavanje po paru (račun, izvor)
    "CREATE TABLE IF NOT EXISTS login_failures (user_id INTEGER NOT NULL, source TEXT NOT NULL,"
    " failed INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0, last_attempt INTEGER NOT NULL DEFAULT 0,"
    " PRIMARY KEY (user_id, source));";

constexpr size_t kSaltBytes = 16, kHashBytes = 32, kTokenBytes = 32;
constexpr std::time_t kTouchSeconds = 60;  // last_used se ne zapisuje češće (manje pisanja)
constexpr size_t kMaxNameLength = 80, kMaxEmailLength = 254, kMaxPasswordLength = 256;

class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &st_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("SQLite: ") + sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(st_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& bind(int i, const std::string& v) { sqlite3_bind_text(st_, i, v.c_str(), -1, SQLITE_TRANSIENT); return *this; }
    Stmt& bind(int i, int64_t v) { sqlite3_bind_int64(st_, i, v); return *this; }
    Stmt& bind(int i, const Bytes& v) {
        sqlite3_bind_blob(st_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
        return *this;
    }
    bool step() {
        const int rc = sqlite3_step(st_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw std::runtime_error(std::string("SQLite: ") + sqlite3_errmsg(sqlite3_db_handle(st_)));
    }
    int64_t i64(int c) { return sqlite3_column_int64(st_, c); }
    std::string text(int c) {
        const auto* t = sqlite3_column_text(st_, c);
        return t ? reinterpret_cast<const char*>(t) : "";
    }
    Bytes blob(int c) {
        const auto* p = static_cast<const uint8_t*>(sqlite3_column_blob(st_, c));
        return p ? Bytes(p, p + sqlite3_column_bytes(st_, c)) : Bytes{};
    }

private:
    sqlite3_stmt* st_ = nullptr;
};

void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "?";
        sqlite3_free(err);
        throw std::runtime_error("SQLite: " + msg);
    }
}

std::string normalize_email(const std::string& email) {
    std::string e = trim(email);
    std::transform(e.begin(), e.end(), e.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return e;
}

}  // namespace

// ---------------------------------------------------------------- pomoćno
std::string role_name(Role r) { return r == Role::Admin ? "admin" : "user"; }

std::optional<Role> parse_role(const std::string& s) {
    if (s == "admin") return Role::Admin;
    if (s == "user") return Role::User;
    return std::nullopt;
}

UserError::UserError(std::map<std::string, std::string> f)
    : std::runtime_error(f.empty() ? "user" : f.begin()->second), fields(std::move(f)) {}

bool valid_email(const std::string& email) {
    const std::string e = trim(email);
    if (e.size() < 6 || e.size() > kMaxEmailLength) return false;
    const size_t at = e.find('@');
    if (at == 0 || at == std::string::npos || e.find('@', at + 1) != std::string::npos) return false;
    const size_t dot = e.find('.', at);
    if (dot == std::string::npos || dot == at + 1 || dot + 1 >= e.size() || e.back() == '.') return false;
    return std::none_of(e.begin(), e.end(), [](unsigned char c) { return c <= ' ' || c == ',' || c == ';' || c == '<' || c == '>'; });
}

std::optional<std::string> password_problem(const std::string& password, const std::string& email) {
    if (password.size() < kMinPasswordLength) return tr("Lozinka mora imati najmanje {n} znakova.", {{"n", std::to_string(kMinPasswordLength)}});
    if (password.size() > kMaxPasswordLength) return tr("Lozinka je preduga.");
    int classes = 0;
    classes += std::any_of(password.begin(), password.end(), [](unsigned char c) { return std::islower(c); });
    classes += std::any_of(password.begin(), password.end(), [](unsigned char c) { return std::isupper(c); });
    classes += std::any_of(password.begin(), password.end(), [](unsigned char c) { return std::isdigit(c); });
    classes += std::any_of(password.begin(), password.end(), [](unsigned char c) { return !std::isalnum(c) || c >= 0x80; });
    if (classes < 3 && password.size() < 16) {
        return tr("Lozinka mora imati barem tri od četiri vrste znakova (mala i velika slova, brojke, ostali znakovi) ili barem 16 znakova.");
    }
    const std::string e = normalize_email(email);
    std::string lower = password;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const std::string local = e.substr(0, e.find('@'));
    if (!local.empty() && local.size() >= 4 && lower.find(local) != std::string::npos) return tr("Lozinka ne smije sadržavati e-poštu.");
    return std::nullopt;
}

UserKeys load_or_create_user_keys(const fs::path& key_file) {
    if (const auto stored = read_file(key_file)) {
        std::string raw = unprotect_secret(trim(*stored));
        if (raw.size() == 2 * kAesKeyBytes) {
            UserKeys k{Bytes(raw.begin(), raw.begin() + kAesKeyBytes), Bytes(raw.begin() + kAesKeyBytes, raw.end())};
            wipe(raw);
            return k;
        }
        // ključ postoji, ali se ne može otvoriti (drugo računalo, oštećen) – NE stvarati novi: postojeći podaci bi
        // postali nečitljivi, a administrator mora znati zašto
        throw std::runtime_error("users.key se ne može otvoriti na ovom računalu");
    }
    UserKeys k{random_bytes(kAesKeyBytes), random_bytes(kAesKeyBytes)};
    std::string raw(k.aes.begin(), k.aes.end());
    raw.append(k.hmac.begin(), k.hmac.end());
    fs::create_directories(key_file.parent_path());
    write_file_atomic(key_file, protect_secret(raw) + "\r\n");
    wipe(raw);
    return k;
}

namespace {
std::string normalize_activation_code(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '-' || c == ' ') continue;
        out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return out;
}
}  // namespace

// ---------------------------------------------------------------- spremište
struct UserStore::Row {
    int64_t id = 0;
    Role role = Role::User;
    Bytes first_enc, last_enc, email_enc, salt, hash;
    int64_t iter = 0;
    bool disabled = false;
    int failed = 0;
    std::time_t locked_until = 0, created = 0, last_login = 0;
    bool totp_required = false;
    Bytes totp_secret_enc, totp_pending_enc;
    int64_t totp_last_step = 0;
    std::string recovery;  // JSON: SHA-256 (hex) neiskorištenih kodova za oporavak
    bool must_change = false;
    std::time_t default_set_at = 0;
};

#define USER_COLUMNS "id, role, first_enc, last_enc, email_enc, pw_salt, pw_hash, pw_iter, disabled, failed, locked_until, created, last_login," \
                     " totp_required, totp_secret_enc, totp_pending_enc, totp_last_step, recovery, must_change, default_set_at"

namespace {
template <class R>
R read_row(Stmt& q) {
    R r;
    r.id = q.i64(0);
    r.role = parse_role(q.text(1)).value_or(Role::User);
    r.first_enc = q.blob(2);
    r.last_enc = q.blob(3);
    r.email_enc = q.blob(4);
    r.salt = q.blob(5);
    r.hash = q.blob(6);
    r.iter = q.i64(7);
    r.disabled = q.i64(8) != 0;
    r.failed = static_cast<int>(q.i64(9));
    r.locked_until = q.i64(10);
    r.created = q.i64(11);
    r.last_login = q.i64(12);
    r.totp_required = q.i64(13) != 0;
    r.totp_secret_enc = q.blob(14);
    r.totp_pending_enc = q.blob(15);
    r.totp_last_step = q.i64(16);
    r.recovery = q.text(17);
    r.must_change = q.i64(18) != 0;
    r.default_set_at = q.i64(19);
    return r;
}
}  // namespace

UserStore::UserStore(const fs::path& db_path, UserKeys keys, uint32_t iterations) : keys_(std::move(keys)), iterations_(iterations) {
    if (keys_.aes.size() != kAesKeyBytes || keys_.hmac.size() != kAesKeyBytes) throw std::invalid_argument("ključevi korisnika");
    fs::create_directories(db_path.parent_path());
    if (sqlite3_open(narrow(db_path.wstring()).c_str(), &db_) != SQLITE_OK) {
        const std::string msg = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("SQLite: " + msg);
    }
    sqlite3_busy_timeout(db_, 5000);  // poslužitelj (servis) i prozor poslužitelja dijele bazu
    // 4.0: baza 3.x (tablica users bez schema_version) se NE dira – ni PRAGMA ni ALTER (zaštita razvojnih podataka)
    const auto has_table = [this](const char* name) {
        Stmt q(db_, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?");
        q.bind(1, std::string(name));
        return q.step();
    };
    if (has_table("users") && !has_table("schema_version")) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error(tr("Baza korisnika je iz starije razvojne verzije (3.x) i 4.0 je ne mijenja. "
                                    "Premjestite je iz mape podataka i ponovno pokrenite poslužitelj (izradit će se nova)."));
    }
    exec(db_, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;");
    exec(db_, kSchema);
    migrate();
    exec(db_, "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)");
    Stmt v(db_, "SELECT COUNT(*) FROM schema_version");
    if (v.step() && v.i64(0) == 0) {
        Stmt ins(db_, "INSERT INTO schema_version (version) VALUES (?)");
        ins.bind(1, static_cast<int64_t>(kUsersSchemaVersion));
        ins.step();
    } else {  // 1 → 2 (R-14a): tablica i stupci su dodani u kSchema/migrate(), stari brojač računa se poništava
        Stmt old(db_, "SELECT MAX(version) FROM schema_version");
        if (old.step() && old.i64(0) < kUsersSchemaVersion) {
            exec(db_, "UPDATE users SET failed = 0, locked_until = 0");
            Stmt up(db_, "UPDATE schema_version SET version = ?");
            up.bind(1, static_cast<int64_t>(kUsersSchemaVersion));
            up.step();
            log_info("Korisnici: baza nadograđena na shemu " + std::to_string(kUsersSchemaVersion) + " (zaključavanje po izvoru)");
        }
    }
}

// 3.1: stupci dvofaktorske prijave (baza iz 3.0 se nadogradi na mjestu)
void UserStore::migrate() {
    std::set<std::string> have;
    {
        Stmt q(db_, "PRAGMA table_info(users)");
        while (q.step()) have.insert(q.text(1));
    }
    const std::pair<const char*, const char*> columns[] = {
        {"totp_required", "INTEGER NOT NULL DEFAULT 0"}, {"totp_secret_enc", "BLOB"}, {"totp_pending_enc", "BLOB"},
        {"totp_last_step", "INTEGER NOT NULL DEFAULT 0"}, {"recovery", "TEXT"},
        {"must_change", "INTEGER NOT NULL DEFAULT 0"}, {"default_set_at", "INTEGER NOT NULL DEFAULT 0"},
        // 4.0 (R-14a): neuspjesi računa sa svih izvora u razdoblju od 24 h (usporavanje i upozorenje)
        {"acct_window", "INTEGER NOT NULL DEFAULT 0"}, {"acct_failed", "INTEGER NOT NULL DEFAULT 0"},
        {"acct_alerted", "INTEGER NOT NULL DEFAULT 0"},
        // 4.0: zaboravljena lozinka (PBKDF2 koda, rok, vrijeme zadnjeg slanja, pogrešni pokušaji)
        {"reset_salt", "BLOB"}, {"reset_hash", "BLOB"}, {"reset_until", "INTEGER NOT NULL DEFAULT 0"},
        {"reset_sent", "INTEGER NOT NULL DEFAULT 0"}, {"reset_tries", "INTEGER NOT NULL DEFAULT 0"},
        // 5.0.1 (audit C-04): dnevni limit kodova po računu
        {"reset_day", "INTEGER NOT NULL DEFAULT 0"}, {"reset_day_count", "INTEGER NOT NULL DEFAULT 0"},
        // 5.0.2 (audit C-12): drugi korak po računu i ukupni ritam pokušaja
        {"totp_failed", "INTEGER NOT NULL DEFAULT 0"}, {"totp_locked_until", "INTEGER NOT NULL DEFAULT 0"},
        {"totp_locks", "INTEGER NOT NULL DEFAULT 0"}, {"acct_last_attempt", "INTEGER NOT NULL DEFAULT 0"}};
    for (const auto& [name, type] : columns) {
        if (!have.count(name)) exec(db_, ("ALTER TABLE users ADD COLUMN " + std::string(name) + " " + type).c_str());
    }
}

UserStore::~UserStore() {
    if (db_) sqlite3_close(db_);
    wipe(keys_.aes);
    wipe(keys_.hmac);
}

Bytes UserStore::email_tag(const std::string& email) const { return hmac_sha256(keys_.hmac, "email:" + normalize_email(email)); }

// 5.0.1 (audit C-07): kod za oporavak (~40 bita) kao HMAC s tajnim ključem iz users.key – sama kopija baze ne omogućuje
// iscrpnu pretragu (prije: nesoljeni SHA-256)
std::string UserStore::recovery_tag(const std::string& normalized) const {
    return "h1:" + to_hex(hmac_sha256(keys_.hmac, "recovery:" + normalized));
}

Bytes UserStore::seal(const std::string& field, const std::string& value) const {
    return aes_gcm_encrypt(keys_.aes, value, "user." + field);
}

std::string UserStore::open(const std::string& field, const Bytes& sealed) const {
    return aes_gcm_decrypt(keys_.aes, sealed, "user." + field).value_or("");
}

UserInfo UserStore::info(const Row& r) {
    UserInfo u;
    u.id = r.id;
    u.role = r.role;
    u.first_name = open("first_name", r.first_enc);
    u.last_name = open("last_name", r.last_enc);
    u.email = open("email", r.email_enc);
    u.disabled = r.disabled;
    u.created = r.created;
    u.last_login = r.last_login;
    u.locked_until = r.locked_until;
    {  // R-14a: najkasnije zaključavanje bilo kojeg izvora (prikaz administratoru)
        Stmt q(db_, "SELECT MAX(locked_until) FROM login_failures WHERE user_id = ?");
        q.bind(1, r.id);
        if (q.step()) u.locked_until = std::max<std::time_t>(u.locked_until, q.i64(0));
    }
    u.totp_required = r.totp_required;
    u.totp_enabled = r.totp_required && !r.totp_secret_enc.empty();
    const json codes = json::parse(r.recovery.empty() ? "[]" : r.recovery, nullptr, false);
    u.recovery_left = codes.is_array() ? static_cast<int>(codes.size()) : 0;
    u.activation_pending = r.must_change;
    u.activation_until = r.must_change ? r.default_set_at + kActivationSeconds : 0;
    return u;
}

std::optional<UserStore::Row> UserStore::row_by_id(int64_t id) {
    Stmt q(db_, "SELECT " USER_COLUMNS " FROM users WHERE id = ?");
    q.bind(1, id);
    if (!q.step()) return std::nullopt;
    return read_row<Row>(q);
}

std::optional<UserStore::Row> UserStore::row_by_email(const std::string& email) {
    Stmt q(db_, "SELECT " USER_COLUMNS " FROM users WHERE email_tag = ?");
    q.bind(1, email_tag(email));
    if (!q.step()) return std::nullopt;
    return read_row<Row>(q);
}

int UserStore::admins_enabled(std::optional<int64_t> except) {
    Stmt q(db_, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?");
    q.bind(1, except.value_or(-1));
    q.step();
    return static_cast<int>(q.i64(0));
}

bool UserStore::has_admin() {
    std::lock_guard lock(mu_); return admins_enabled(std::nullopt) > 0; }

void UserStore::validate(const UserInput& in, bool require_password, std::optional<int64_t> self) {
    std::map<std::string, std::string> err;
    const std::string first = trim(in.first_name), last = trim(in.last_name);
    if (first.empty()) err["first_name"] = tr("Upišite ime.");
    else if (first.size() > kMaxNameLength) err["first_name"] = tr("Ime je predugo.");
    if (last.empty()) err["last_name"] = tr("Upišite prezime.");
    else if (last.size() > kMaxNameLength) err["last_name"] = tr("Prezime je predugo.");
    if (!valid_email(in.email)) {
        err["email"] = tr("Upišite ispravnu adresu e-pošte.");
    } else if (const auto other = row_by_email(in.email); other && (!self || other->id != *self)) {
        err["email"] = tr("Korisnik s tom e-poštom već postoji.");
    }
    if (require_password || !in.password.empty()) {
        if (const auto p = password_problem(in.password, in.email)) err["password"] = *p;
    }
    if (!err.empty()) throw UserError(std::move(err));
}

void UserStore::set_password_hash(int64_t id, const std::string& password, std::time_t now, bool activation) {
    const bool must_change = activation;  // stupci must_change/default_set_at: aktivacija na čekanju i vrijeme izdavanja koda
    Bytes salt = random_bytes(kSaltBytes);
    Bytes hash = pbkdf2_sha256(password, salt, iterations_, kHashBytes);
    // svaka nova lozinka ili aktivacijski kod poništava i neiskorišteni kod za zaboravljenu lozinku
    Stmt q(db_, "UPDATE users SET pw_salt = ?, pw_hash = ?, pw_iter = ?, failed = 0, locked_until = 0, updated = ?, must_change = ?,"
                " default_set_at = ?, reset_salt = NULL, reset_hash = NULL, reset_until = 0, reset_tries = 0 WHERE id = ?");
    q.bind(1, salt).bind(2, hash).bind(3, static_cast<int64_t>(iterations_)).bind(4, static_cast<int64_t>(now))
        .bind(5, static_cast<int64_t>(must_change ? 1 : 0)).bind(6, static_cast<int64_t>(must_change ? now : 0)).bind(7, id);
    clear_failures(id);  // nova lozinka ili kod: sva zaključavanja tog računa prestaju
    q.step();
    wipe(hash);
    revoke_sessions(id);  // nova lozinka = sve postojeće prijave prestaju vrijediti
}

namespace {
// 5.0.2 (audit C-03): PBKDF2 (600 000 ponavljanja) se ne računa pod zajedničkom bravom korisnika – inače poplava
// neprijavljenih zahtjeva zamrzava sve prijavljene korisnike. Najviše kPbkdf2Parallel izračuna istodobno.
std::counting_semaphore<kPbkdf2Parallel>& pbkdf2_gate() {
    static std::counting_semaphore<kPbkdf2Parallel> gate(kPbkdf2Parallel);
    return gate;
}

template <class F>
auto unlocked_pbkdf2(std::unique_lock<std::recursive_mutex>& lock, F&& work) {
    lock.unlock();
    pbkdf2_gate().acquire();
    struct Release {
        std::unique_lock<std::recursive_mutex>& l;
        ~Release() {
            pbkdf2_gate().release();
            l.lock();
        }
    } release{lock};
    return work();
}
}  // namespace

bool UserStore::verify_password(const Row& r, const std::string& password) const {
    if (r.salt.empty() || r.hash.empty() || r.iter <= 0) return false;
    Bytes h = pbkdf2_sha256(password, r.salt, static_cast<uint32_t>(r.iter), r.hash.size());
    const bool same = equal_ct(h, r.hash);
    wipe(h);
    return same;
}

void UserStore::revoke_sessions(int64_t id) {
    Stmt q(db_, "DELETE FROM sessions WHERE user_id = ?");
    q.bind(1, id);
    q.step();
}

int64_t UserStore::create(const UserInput& in, std::time_t now, std::string* activation_code) {
    std::lock_guard lock(mu_);
    const bool initial = in.password.empty();  // bez lozinke: jednokratni aktivacijski kod (SMA-03)
    validate(in, !initial, std::nullopt);
    exec(db_, "BEGIN IMMEDIATE");
    try {
        Stmt q(db_, "INSERT INTO users (role, email_tag, first_enc, last_enc, email_enc, created, updated, totp_required)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        q.bind(1, role_name(in.role)).bind(2, email_tag(in.email)).bind(3, seal("first_name", trim(in.first_name)))
            .bind(4, seal("last_name", trim(in.last_name))).bind(5, seal("email", trim(in.email)))
            .bind(6, static_cast<int64_t>(now)).bind(7, static_cast<int64_t>(now)).bind(8, static_cast<int64_t>(in.totp_required ? 1 : 0));
        q.step();
        const int64_t id = sqlite3_last_insert_rowid(db_);
        if (initial) {
            std::string code = new_activation_code(id, now);
            if (activation_code) *activation_code = code;
            wipe(code);
        } else {
            set_password_hash(id, in.password, now, false);
        }
        exec(db_, "COMMIT");
        return id;
    } catch (...) {
        exec(db_, "ROLLBACK");
        throw;
    }
}

void UserStore::update(int64_t id, const UserInput& in, std::time_t now) {
    std::lock_guard lock(mu_);
    const auto row = row_by_id(id);
    if (!row) throw UserError({{"general", tr("Korisnik ne postoji.")}});
    validate(in, false, id);
    if (row->role == Role::Admin && in.role != Role::Admin && !row->disabled && admins_enabled(id) == 0) {
        throw UserError({{"role", tr("Mora ostati barem jedan aktivni administrator.")}});
    }
    exec(db_, "BEGIN IMMEDIATE");
    try {
        Stmt q(db_, "UPDATE users SET role = ?, email_tag = ?, first_enc = ?, last_enc = ?, email_enc = ?, updated = ? WHERE id = ?");
        q.bind(1, role_name(in.role)).bind(2, email_tag(in.email)).bind(3, seal("first_name", trim(in.first_name)))
            .bind(4, seal("last_name", trim(in.last_name))).bind(5, seal("email", trim(in.email)))
            .bind(6, static_cast<int64_t>(now)).bind(7, id);
        q.step();
        if (!in.password.empty()) set_password_hash(id, in.password, now);
        if (row->role != in.role) revoke_sessions(id);  // nova uloga vrijedi od sljedeće prijave
        if (in.totp_required != row->totp_required) {
            // uključeno: postavljanje pri sljedećoj prijavi (postojeće prijave se poništavaju); isključeno: tajna se briše
            Stmt z(db_, "UPDATE users SET totp_required = ?, totp_secret_enc = NULL, totp_pending_enc = NULL, totp_last_step = 0,"
                        " recovery = NULL WHERE id = ?");
            z.bind(1, static_cast<int64_t>(in.totp_required ? 1 : 0)).bind(2, id);
            z.step();
            if (in.totp_required) revoke_sessions(id);
        }
        exec(db_, "COMMIT");
    } catch (...) {
        exec(db_, "ROLLBACK");
        throw;
    }
}

void UserStore::set_disabled(int64_t id, bool disabled, std::time_t now) {
    std::lock_guard lock(mu_);
    const auto row = row_by_id(id);
    if (!row) throw UserError({{"general", tr("Korisnik ne postoji.")}});
    if (disabled && row->role == Role::Admin && admins_enabled(id) == 0) {
        throw UserError({{"general", tr("Mora ostati barem jedan aktivni administrator.")}});
    }
    Stmt q(db_, "UPDATE users SET disabled = ?, failed = 0, locked_until = 0, updated = ? WHERE id = ?");
    q.bind(1, static_cast<int64_t>(disabled ? 1 : 0)).bind(2, static_cast<int64_t>(now)).bind(3, id);
    q.step();
    clear_failures(id);  // blokiranje/odblokiranje otključava račun (ublaženje SMA-14)
    if (disabled) revoke_sessions(id);
}

void UserStore::remove(int64_t id) {
    std::lock_guard lock(mu_);
    const auto row = row_by_id(id);
    if (!row) return;
    if (row->role == Role::Admin && !row->disabled && admins_enabled(id) == 0) {
        throw UserError({{"general", tr("Mora ostati barem jedan aktivni administrator.")}});
    }
    revoke_sessions(id);
    clear_failures(id);
    Stmt q(db_, "DELETE FROM users WHERE id = ?");
    q.bind(1, id);
    q.step();
}

std::vector<UserInfo> UserStore::list() {
    std::lock_guard lock(mu_);
    std::vector<UserInfo> out;
    Stmt q(db_, "SELECT " USER_COLUMNS " FROM users ORDER BY id");
    while (q.step()) out.push_back(info(read_row<Row>(q)));
    std::sort(out.begin(), out.end(), [](const UserInfo& a, const UserInfo& b) {
        return a.last_name + " " + a.first_name < b.last_name + " " + b.first_name;
    });
    return out;
}

std::optional<UserInfo> UserStore::get(int64_t id) {
    std::lock_guard lock(mu_);
    const auto row = row_by_id(id);
    return row ? std::optional(info(*row)) : std::nullopt;
}

LoginResult UserStore::login(const std::string& email, std::string password, const std::string& device, std::time_t now,
                             const std::string& totp, std::string new_password, const std::string& source) {
    std::unique_lock lock(mu_);
    LoginResult res;
    const std::string src_key = source.empty() ? std::string(kLoginSourceLocal) : source.substr(0, 64);
    auto row = password.size() <= kMaxPasswordLength ? row_by_email(email) : std::nullopt;
    if (!row) {
        // nepoznata e-pošta: isti rad kao provjera lozinke, da se po vremenu ne može doznati postoji li račun
        unlocked_pbkdf2(lock, [&] {
            Bytes dummy = pbkdf2_sha256(password, Bytes(kSaltBytes, 0), iterations_, kHashBytes);
            wipe(dummy);
            return 0;
        });
        wipe(password);
        return res;
    }
    // aktivacijski kod se uspoređuje bez crtica i razmaka, velikim slovima; PBKDF2 izvan brave (C-03)
    const Row snapshot = *row;
    bool good = unlocked_pbkdf2(lock, [&] {
        return verify_password(snapshot, snapshot.must_change ? normalize_activation_code(password) : password);
    });
    wipe(password);
    source_ = src_key;  // brava je u međuvremenu bila otpuštena – izvor se postavlja tek sad
    row = row_by_id(snapshot.id);  // lozinka se u međuvremenu mogla promijeniti – vrijedi samo provjera istog zapisa
    if (!row || row->salt != snapshot.salt || row->hash != snapshot.hash || row->must_change != snapshot.must_change) good = false;
    if (!row) return res;
    // R-14a: zaključan je samo ovaj izvor za ovaj račun; uz pogrešnu lozinku isto kao nepostojeći račun (SMA-13)
    const SourceState src = source_state(row->id, source_);
    if (src.locked_until > now) {
        res.status = good ? LoginResult::Status::Locked : LoginResult::Status::BadCredentials;
        return res;
    }
    // R-14a: raspodijeljeni napad na račun – udaljeni izvor smije najviše jedan pokušaj u minuti (lokalni prozor izuzet)
    if (source_ != kLoginSourceLocal && account_throttled(row->id, now)) {
        // 5.0.2 (audit C-12): uz to i ukupno, sa svih izvora zajedno, najviše jedan pokušaj u kAccountGlobalSeconds –
        // broj adresa (IPv6 /64) više ne umnožava broj pokušaja
        int64_t last_any = 0;
        {
            Stmt q(db_, "SELECT acct_last_attempt FROM users WHERE id = ?");
            q.bind(1, row->id);
            if (q.step()) last_any = q.i64(0);
        }
        const bool too_fast = now - src.last_attempt < kThrottleSeconds || now - last_any < kAccountGlobalSeconds;
        Stmt t(db_, "UPDATE users SET acct_last_attempt = ? WHERE id = ?");
        t.bind(1, static_cast<int64_t>(now)).bind(2, row->id);
        t.step();
        if (too_fast) {
            touch_source(row->id, source_, now);
            res.status = good ? LoginResult::Status::Locked : LoginResult::Status::BadCredentials;
            return res;
        }
    }
    if (!good) {
        count_failure(*row, now, res, LoginResult::Status::BadCredentials);
        return res;
    }
    if (row->disabled) {
        res.status = LoginResult::Status::Disabled;
        return res;
    }
    std::optional<Row> current = row;
    if (row->must_change) {  // aktivacijski kod: prije svega ostalog vlastita lozinka
        if (now - row->default_set_at > kActivationSeconds) {  // istekao kod: kao pogrešna lozinka (ne otkriva račun)
            wipe(new_password);
            count_failure(*row, now, res, LoginResult::Status::BadCredentials);
            return res;
        }
        if (new_password.empty()) {
            res.status = LoginResult::Status::ActivationRequired;
            return res;
        }
        const std::string email_plain = open("email", row->email_enc);
        std::optional<std::string> problem = password_problem(new_password, email_plain);
        if (problem) {
            wipe(new_password);
            res.status = LoginResult::Status::PasswordInvalid;
            res.problem = *problem;
            return res;
        }
        set_password_hash(row->id, new_password, now, false);
        wipe(new_password);
        log_info("Korisnici: korisnik #" + std::to_string(row->id) + " je aktivirao račun (vlastita lozinka)");
        current = row_by_id(row->id);
    }
    if (current->totp_required && !second_factor(*current, totp, now, res)) return res;
    Bytes raw = random_bytes(kTokenBytes);
    res.token = base64url(raw);
    wipe(raw);
    Stmt s(db_, "INSERT INTO sessions (token_hash, user_id, device_enc, created, last_used) VALUES (?, ?, ?, ?, ?)");
    s.bind(1, sha256(res.token)).bind(2, row->id).bind(3, seal("device", device.substr(0, 120)))
        .bind(4, static_cast<int64_t>(now)).bind(5, static_cast<int64_t>(now));
    s.step();
    Stmt u(db_, "UPDATE users SET failed = 0, locked_until = 0, last_login = ? WHERE id = ?");
    u.bind(1, static_cast<int64_t>(now)).bind(2, row->id);
    u.step();
    // uspjeh s ovog izvora: brojač i zaključavanje na 0, vrijeme pokušaja ostaje (usporavanje vrijedi i za uspješne pokušaje)
    Stmt f(db_, "INSERT INTO login_failures (user_id, source, failed, locked_until, last_attempt) VALUES (?, ?, 0, 0, ?)"
                " ON CONFLICT(user_id, source) DO UPDATE SET failed = 0, locked_until = 0, last_attempt = excluded.last_attempt");
    f.bind(1, row->id).bind(2, source_).bind(3, static_cast<int64_t>(now));
    f.step();
    res.status = LoginResult::Status::Ok;
    res.user = info(*row_by_id(row->id));  // nakon postavljanja dvofaktorske prijave podaci su novi
    res.user->last_login = now;
    return res;
}

UserStore::SourceState UserStore::source_state(int64_t id, const std::string& source) {
    SourceState s;
    Stmt q(db_, "SELECT failed, locked_until, last_attempt FROM login_failures WHERE user_id = ? AND source = ?");
    q.bind(1, id).bind(2, source);
    if (q.step()) {
        s.failed = static_cast<int>(q.i64(0));
        s.locked_until = q.i64(1);
        s.last_attempt = q.i64(2);
    }
    return s;
}

void UserStore::touch_source(int64_t id, const std::string& source, std::time_t now) {
    Stmt q(db_, "INSERT INTO login_failures (user_id, source, last_attempt) VALUES (?, ?, ?)"
                " ON CONFLICT(user_id, source) DO UPDATE SET last_attempt = excluded.last_attempt");
    q.bind(1, id).bind(2, source).bind(3, static_cast<int64_t>(now));
    q.step();
}

bool UserStore::account_throttled(int64_t id, std::time_t now) {
    Stmt q(db_, "SELECT acct_window, acct_failed FROM users WHERE id = ?");
    q.bind(1, id);
    return q.step() && now - q.i64(0) <= kAccountWindowSeconds && q.i64(1) > kAccountSoftLimit;
}

void UserStore::clear_failures(int64_t id) {
    Stmt d(db_, "DELETE FROM login_failures WHERE user_id = ?");
    d.bind(1, id);
    d.step();
    Stmt u(db_, "UPDATE users SET acct_window = 0, acct_failed = 0, acct_alerted = 0 WHERE id = ?");
    u.bind(1, id);
    u.step();
}

void UserStore::count_failure(const Row& r, std::time_t now, LoginResult& res, LoginResult::Status status) {
    // R-14a: brojač i zaključavanje po paru (račun, izvor)
    const SourceState st = source_state(r.id, source_);
    const int failed = st.failed + 1;
    const std::time_t until = failed >= kMaxFailedLogins ? now + kLockSeconds : 0;
    Stmt q(db_, "INSERT INTO login_failures (user_id, source, failed, locked_until, last_attempt) VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(user_id, source) DO UPDATE SET failed = excluded.failed, locked_until = excluded.locked_until,"
                " last_attempt = excluded.last_attempt");
    q.bind(1, r.id).bind(2, source_).bind(3, static_cast<int64_t>(until ? 0 : failed)).bind(4, static_cast<int64_t>(until))
        .bind(5, static_cast<int64_t>(now));
    q.step();
    if (until) log_warn("Korisnici: račun #" + std::to_string(r.id) + " zaključan 15 min za izvor " + source_);
    // brojač računa sa svih izvora (razdoblje 24 h): usporavanje udaljenih izvora i jedno upozorenje po razdoblju
    Stmt a(db_, "SELECT acct_window, acct_failed, acct_alerted FROM users WHERE id = ?");
    a.bind(1, r.id);
    int64_t window = 0, count = 0, alerted = 0;
    if (a.step()) {
        window = a.i64(0);
        count = a.i64(1);
        alerted = a.i64(2);
    }
    if (now - window > kAccountWindowSeconds) {
        window = now;
        count = 0;
        alerted = 0;
    }
    ++count;
    const bool alert = count > kAccountSoftLimit && !alerted;
    Stmt w(db_, "UPDATE users SET acct_window = ?, acct_failed = ?, acct_alerted = ? WHERE id = ?");
    w.bind(1, window).bind(2, count).bind(3, static_cast<int64_t>(alerted || alert ? 1 : 0)).bind(4, r.id);
    w.step();
    if (alert) {
        const std::string msg = "Račun #" + std::to_string(r.id) + ": više od " + std::to_string(kAccountSoftLimit) +
                                " neuspjelih prijava u 24 h s više adresa – prijave s mreže su usporene (1 pokušaj u minuti po adresi).";
        log_warn("Korisnici: " + msg);
        if (alert_) {
            try {
                alert_(msg);
            } catch (const std::exception& e) {
                log_error(std::string("Korisnici: upozorenje nije poslano: ") + e.what());
            }
        }
    }
    // uz pogrešnu lozinku zaključavanje se ne javlja (SMA-13, SMA-26); uz točnu lozinku i pogrešan kod (TOTP) smije
    res.status = until && status != LoginResult::Status::BadCredentials ? LoginResult::Status::Locked : status;
}

// Drugi korak prijave; false = res sadrži razlog (treba kod, postavljanje, pogrešan kod ili zaključano)
void UserStore::totp_failure(const Row& r, std::time_t now, LoginResult& res) {
    int64_t failed = 0, locks = 0;
    {
        Stmt q(db_, "SELECT totp_failed, totp_locks FROM users WHERE id = ?");
        q.bind(1, r.id);
        if (q.step()) {
            failed = q.i64(0);
            locks = q.i64(1);
        }
    }
    ++failed;
    if (failed < kTotpMaxFailures) {
        Stmt u(db_, "UPDATE users SET totp_failed = ? WHERE id = ?");
        u.bind(1, failed).bind(2, r.id);
        u.step();
        return;
    }
    const std::time_t lock_for = std::min<std::time_t>(kTotpLockMaxSeconds, kTotpLockSeconds << std::min<int64_t>(locks, 5));
    Stmt u(db_, "UPDATE users SET totp_failed = 0, totp_locks = totp_locks + 1, totp_locked_until = ? WHERE id = ?");
    u.bind(1, static_cast<int64_t>(now + lock_for)).bind(2, r.id);
    u.step();
    res.status = LoginResult::Status::Locked;
    res.totp_locked = true;
    const std::string msg = "Račun #" + std::to_string(r.id) + ": " + std::to_string(kTotpMaxFailures) +
                            " pogrešnih kodova drugog koraka uz točnu lozinku – drugi korak zaključan " +
                            std::to_string(lock_for / 60) + " min. Lozinka računa je vjerojatno poznata napadaču.";
    log_warn("Korisnici: " + msg);
    if (alert_) {
        try {
            alert_(msg);
        } catch (const std::exception& e) {
            log_error(std::string("Korisnici: upozorenje nije poslano: ") + e.what());
        }
    }
}

bool UserStore::totp_locked(const Row& r, std::time_t now) {
    Stmt q(db_, "SELECT totp_locked_until FROM users WHERE id = ?");
    q.bind(1, r.id);
    return q.step() && q.i64(0) > now;
}

void UserStore::totp_success(const Row& r) {
    Stmt u(db_, "UPDATE users SET totp_failed = 0 WHERE id = ?");
    u.bind(1, r.id);
    u.step();
}

bool UserStore::second_factor(const Row& r, const std::string& code, std::time_t now, LoginResult& res) {
    // 5.0.2 (audit C-12): zaključan drugi korak – kod se uopće ne provjerava (ni kod za oporavak)
    if (!trim(code).empty() && totp_locked(r, now)) {
        res.status = LoginResult::Status::Locked;
        return false;
    }
    if (r.totp_secret_enc.empty()) {  // još nije postavljena: tajna čeka potvrdu prvim kodom
        Bytes secret;
        // 5.0.2 (audit C-10): svaki prikaz postavljanja (bez koda) dobiva NOVU tajnu – tko zna lozinku ne može
        // preuzeti tajnu koju je vlasnik već skenirao; potvrda kodom vrijedi samo za zadnju prikazanu tajnu
        if (!r.totp_pending_enc.empty() && !trim(code).empty()) {
            const std::string s = open("totp_pending", r.totp_pending_enc);
            secret.assign(s.begin(), s.end());
        }
        if (secret.size() != kTotpSecretBytes) {
            secret = random_bytes(kTotpSecretBytes);
            Stmt q(db_, "UPDATE users SET totp_pending_enc = ? WHERE id = ?");
            q.bind(1, seal("totp_pending", std::string(secret.begin(), secret.end()))).bind(2, r.id);
            q.step();
        }
        res.totp_secret = base32(secret);
        res.totp_uri = otpauth_uri("Solarni monitor", open("email", r.email_enc), secret);
        if (trim(code).empty()) {
            res.status = LoginResult::Status::TotpSetup;
            return false;
        }
        const auto step = totp_verify(secret, code, now, 0);
        if (!step) {
            count_failure(r, now, res, LoginResult::Status::TotpInvalid);
            totp_failure(r, now, res);
            return false;
        }
        totp_success(r);
        res.totp_enrolled = true;
        res.recovery_codes = make_recovery_codes();
        json hashes = json::array();
        for (const auto& rc : res.recovery_codes) hashes.push_back(recovery_tag(normalize_recovery_code(rc)));
        Stmt q(db_, "UPDATE users SET totp_secret_enc = ?, totp_pending_enc = NULL, totp_last_step = ?, recovery = ? WHERE id = ?");
        q.bind(1, seal("totp_secret", std::string(secret.begin(), secret.end()))).bind(2, *step).bind(3, hashes.dump()).bind(4, r.id);
        q.step();
        res.totp_secret.clear();  // postavljeno – tajna se više nikad ne prikazuje
        res.totp_uri.clear();
        wipe(secret);
        return true;
    }
    if (trim(code).empty()) {
        res.status = LoginResult::Status::TotpRequired;
        return false;
    }
    const std::string s = open("totp_secret", r.totp_secret_enc);
    Bytes secret(s.begin(), s.end());
    const auto step = totp_verify(secret, code, now, r.totp_last_step);
    wipe(secret);
    if (step) {
        Stmt q(db_, "UPDATE users SET totp_last_step = ? WHERE id = ?");
        q.bind(1, *step).bind(2, r.id);
        q.step();
        totp_success(r);
        return true;
    }
    // kod za oporavak (jednokratan)
    const std::string norm = normalize_recovery_code(code);
    json codes = json::parse(r.recovery.empty() ? "[]" : r.recovery, nullptr, false);
    if (norm.size() == 8 && codes.is_array()) {
        const std::string tagged = recovery_tag(norm), legacy = to_hex(sha256(norm));  // 5.0.1: HMAC; prije: SHA-256
        for (auto it = codes.begin(); it != codes.end(); ++it) {
            if (!it->is_string()) continue;
            const std::string stored = it->get<std::string>();
            const std::string& h = stored.rfind("h1:", 0) == 0 ? tagged : legacy;
            if (equal_ct(Bytes(h.begin(), h.end()), Bytes(stored.begin(), stored.end()))) {
                codes.erase(it);
                Stmt q(db_, "UPDATE users SET recovery = ? WHERE id = ?");
                q.bind(1, codes.dump()).bind(2, r.id);
                q.step();
                log_warn("Korisnici: prijava kodom za oporavak (korisnik #" + std::to_string(r.id) + ", preostalo " + std::to_string(codes.size()) + ")");
                totp_success(r);
                return true;
            }
        }
    }
    count_failure(r, now, res, LoginResult::Status::TotpInvalid);
    totp_failure(r, now, res);
    return false;
}

std::string UserStore::new_activation_code(int64_t id, std::time_t now) {
    // 8 slučajnih bajtova → base32; prvih 12 znakova = 60 bita. Prikaz XXXX-XXXX-XXXX.
    Bytes raw = random_bytes(8);
    std::string code = base32(raw).substr(0, kActivationCodeChars);
    wipe(raw);
    set_password_hash(id, code, now, true);  // u bazi samo PBKDF2; poništava i sve prijave
    std::string shown = code.substr(0, 4) + "-" + code.substr(4, 4) + "-" + code.substr(8, 4);
    wipe(code);
    return shown;
}

std::string UserStore::issue_activation_code(int64_t id, std::time_t now) {
    std::lock_guard lock(mu_);
    if (!row_by_id(id)) throw UserError({{"general", tr("Korisnik ne postoji.")}});
    return new_activation_code(id, now);
}

ResetRequest UserStore::request_password_reset(const std::string& email, std::time_t now) {
    std::unique_lock lock(mu_);
    ResetRequest out;
    const auto dummy_work = [&] {
        unlocked_pbkdf2(lock, [&] {
            Bytes dummy = pbkdf2_sha256("XXXXXXXX", Bytes(kSaltBytes, 0), iterations_, kHashBytes);
            wipe(dummy);
            return 0;
        });
    };
    const auto row = row_by_email(email);
    if (!row || row->disabled) {
        // isti rad kao za postojeći račun (PBKDF2), da se po vremenu ne može doznati postoji li račun
        dummy_work();
        return out;
    }
    {
        Stmt q(db_, "SELECT reset_sent, reset_day, reset_day_count FROM users WHERE id = ?");
        q.bind(1, row->id);
        if (q.step()) {
            const bool too_soon = now - q.i64(0) < kResetResendSeconds;
            const bool same_day = now - q.i64(1) < 24 * 3600;
            if (too_soon || (same_day && q.i64(2) >= kResetPerDay)) {
                // bez novog koda i bez e-poruke, ali isti rad (PBKDF2) kao slanje – vrijeme ne otkriva račun (audit C-01)
                dummy_work();
                return out;
            }
        }
    }
    Bytes raw = random_bytes(5);  // 40 bita → točno 8 znakova base32
    std::string code = base32(raw).substr(0, kResetCodeChars);
    wipe(raw);
    Bytes salt = random_bytes(kSaltBytes);
    Bytes hash = unlocked_pbkdf2(lock, [&] { return pbkdf2_sha256(code, salt, iterations_, kHashBytes); });
    Stmt q(db_, "UPDATE users SET reset_salt = ?, reset_hash = ?, reset_until = ?, reset_sent = ?, reset_tries = 0,"
                " reset_day_count = CASE WHEN ? - reset_day < 86400 THEN reset_day_count + 1 ELSE 1 END,"
                " reset_day = CASE WHEN ? - reset_day < 86400 THEN reset_day ELSE ? END WHERE id = ?");
    q.bind(1, salt).bind(2, hash).bind(3, static_cast<int64_t>(now + kResetSeconds)).bind(4, static_cast<int64_t>(now))
        .bind(5, static_cast<int64_t>(now)).bind(6, static_cast<int64_t>(now)).bind(7, static_cast<int64_t>(now)).bind(8, row->id);
    q.step();
    wipe(hash);
    out.send = true;
    out.email = open("email", row->email_enc);
    out.first_name = open("first_name", row->first_enc);
    out.code = code.substr(0, 4) + "-" + code.substr(4, 4);
    out.valid_until = now + kResetSeconds;
    wipe(code);
    log_info("Korisnici: zatražen kod za zaboravljenu lozinku (korisnik #" + std::to_string(row->id) + ")");
    return out;
}

ResetResult UserStore::reset_password(const std::string& email, const std::string& code, std::string new_password, std::time_t now) {
    std::unique_lock lock(mu_);
    ResetResult res;
    const std::string entered = normalize_activation_code(code);
    const auto row = entered.size() == kResetCodeChars && new_password.size() <= kMaxPasswordLength ? row_by_email(email) : std::nullopt;
    if (!row || row->disabled) {
        unlocked_pbkdf2(lock, [&] {
            Bytes dummy = pbkdf2_sha256(entered, Bytes(kSaltBytes, 0), iterations_, kHashBytes);
            wipe(dummy);
            return 0;
        });
        wipe(new_password);
        return res;
    }
    Bytes salt, hash;
    std::time_t until = 0;
    int tries = 0;
    {
        Stmt q(db_, "SELECT reset_salt, reset_hash, reset_until, reset_tries FROM users WHERE id = ?");
        q.bind(1, row->id);
        if (q.step()) {
            salt = q.blob(0);
            hash = q.blob(1);
            until = q.i64(2);
            tries = static_cast<int>(q.i64(3));
        }
    }
    bool good = false;
    {  // PBKDF2 uvijek – i kad račun nema kod na čekanju, inače vrijeme odgovora otkriva postoji li račun (audit C-01)
        const bool pending = !salt.empty() && !hash.empty();
        Bytes h = unlocked_pbkdf2(lock, [&] {  // izvan brave (C-03)
            return pbkdf2_sha256(entered, pending ? salt : Bytes(kSaltBytes, 0), iterations_, pending ? hash.size() : kHashBytes);
        });
        good = pending && equal_ct(h, hash);
        wipe(h);
        // kod se u međuvremenu mogao iskoristiti ili zamijeniti – vrijedi samo ako je u bazi još isti
        Stmt q(db_, "SELECT reset_hash, reset_tries FROM users WHERE id = ?");
        q.bind(1, row->id);
        if (!q.step() || q.blob(0) != hash) good = false;
        else tries = static_cast<int>(q.i64(1));
    }
    if (!good || now > until || tries >= kResetMaxTries) {
        wipe(new_password);
        if (!hash.empty()) {  // pogrešan kod troši pokušaj; peti pogrešan poništava kod
            const bool spent = tries + 1 >= kResetMaxTries;
            Stmt q(db_, spent ? "UPDATE users SET reset_salt = NULL, reset_hash = NULL, reset_until = 0, reset_tries = 0 WHERE id = ?"
                              : "UPDATE users SET reset_tries = reset_tries + 1 WHERE id = ?");
            q.bind(1, row->id);
            q.step();
        }
        return res;
    }
    const std::string email_plain = open("email", row->email_enc);
    if (auto problem = password_problem(new_password, email_plain)) {  // kod ostaje važeći – korisnik bira drugu lozinku
        wipe(new_password);
        res.status = ResetResult::Status::PasswordInvalid;
        res.problem = *problem;
        return res;
    }
    set_password_hash(row->id, new_password, now, false);  // poništava kod, zaključavanja i sve prijave
    wipe(new_password);
    log_info("Korisnici: korisnik #" + std::to_string(row->id) + " je postavio novu lozinku kodom iz e-pošte");
    res.status = ResetResult::Status::Ok;
    res.email = email_plain;
    res.first_name = open("first_name", row->first_enc);
    return res;
}

void UserStore::revoke_all_sessions(int64_t id) {
    std::lock_guard lock(mu_);
    revoke_sessions(id);
}

void UserStore::reset_totp(int64_t id, std::time_t now) {
    std::lock_guard lock(mu_);
    Stmt q(db_, "UPDATE users SET totp_secret_enc = NULL, totp_pending_enc = NULL, totp_last_step = 0, recovery = NULL, updated = ? WHERE id = ?");
    q.bind(1, static_cast<int64_t>(now)).bind(2, id);
    q.step();
    revoke_sessions(id);
}

std::optional<UserInfo> UserStore::session_user(const std::string& token, std::time_t now) {
    std::lock_guard lock(mu_);
    if (token.size() < 40 || token.size() > 64) return std::nullopt;
    const Bytes th = sha256(token);
    Stmt q(db_, "SELECT user_id, created, last_used FROM sessions WHERE token_hash = ?");
    q.bind(1, th);
    if (!q.step()) return std::nullopt;
    const int64_t uid = q.i64(0);
    const std::time_t created = q.i64(1), last_used = q.i64(2);
    if (now - last_used > kSessionIdleSeconds || now - created > kSessionMaxSeconds) {
        logout(token);
        return std::nullopt;
    }
    const auto row = row_by_id(uid);
    if (!row || row->disabled) return std::nullopt;
    if (now - last_used >= kTouchSeconds) {
        Stmt t(db_, "UPDATE sessions SET last_used = ? WHERE token_hash = ?");
        t.bind(1, static_cast<int64_t>(now)).bind(2, th);
        t.step();
    }
    return info(*row);
}

void UserStore::logout(const std::string& token) {
    std::lock_guard lock(mu_);
    Stmt q(db_, "DELETE FROM sessions WHERE token_hash = ?");
    q.bind(1, sha256(token));
    q.step();
}

void UserStore::change_password(int64_t id, const std::string& old_password, const std::string& new_password, std::time_t now) {
    std::lock_guard lock(mu_);
    const auto row = row_by_id(id);
    if (!row) throw UserError({{"general", tr("Korisnik ne postoji.")}});
    if (!verify_password(*row, old_password)) throw UserError({{"old_password", tr("Trenutna lozinka nije točna.")}});
    if (const auto p = password_problem(new_password, open("email", row->email_enc))) throw UserError({{"password", *p}});
    set_password_hash(id, new_password, now);
}

int UserStore::active_sessions(int64_t id, std::time_t now) {
    std::lock_guard lock(mu_);
    Stmt q(db_, "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND last_used > ? AND created > ?");
    q.bind(1, id).bind(2, static_cast<int64_t>(now - kSessionIdleSeconds)).bind(3, static_cast<int64_t>(now - kSessionMaxSeconds));
    q.step();
    return static_cast<int>(q.i64(0));
}

}  // namespace sm

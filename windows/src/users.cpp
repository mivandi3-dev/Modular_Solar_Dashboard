#include "users.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
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
    "CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);";

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
    exec(db_, "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;");
    exec(db_, kSchema);
    migrate();
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
        {"must_change", "INTEGER NOT NULL DEFAULT 0"}, {"default_set_at", "INTEGER NOT NULL DEFAULT 0"}};
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
    u.totp_required = r.totp_required;
    u.totp_enabled = r.totp_required && !r.totp_secret_enc.empty();
    const json codes = json::parse(r.recovery.empty() ? "[]" : r.recovery, nullptr, false);
    u.recovery_left = codes.is_array() ? static_cast<int>(codes.size()) : 0;
    u.must_change_password = r.must_change;
    u.default_password_until = r.must_change ? r.default_set_at + kDefaultPasswordSeconds : 0;
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

void UserStore::set_password_hash(int64_t id, const std::string& password, std::time_t now, bool must_change) {
    Bytes salt = random_bytes(kSaltBytes);
    Bytes hash = pbkdf2_sha256(password, salt, iterations_, kHashBytes);
    Stmt q(db_, "UPDATE users SET pw_salt = ?, pw_hash = ?, pw_iter = ?, failed = 0, locked_until = 0, updated = ?, must_change = ?,"
                " default_set_at = ? WHERE id = ?");
    q.bind(1, salt).bind(2, hash).bind(3, static_cast<int64_t>(iterations_)).bind(4, static_cast<int64_t>(now))
        .bind(5, static_cast<int64_t>(must_change ? 1 : 0)).bind(6, static_cast<int64_t>(must_change ? now : 0)).bind(7, id);
    q.step();
    wipe(hash);
    revoke_sessions(id);  // nova lozinka = sve postojeće prijave prestaju vrijediti
}

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

int64_t UserStore::create(const UserInput& in, std::time_t now) {
    std::lock_guard lock(mu_);
    const bool initial = in.password.empty();  // bez lozinke: početna 12345678, mijenja se pri prvoj prijavi
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
        set_password_hash(id, initial ? std::string(kDefaultPassword) : in.password, now, initial);
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
                             const std::string& totp, std::string new_password) {
    std::lock_guard lock(mu_);
    LoginResult res;
    const auto row = password.size() <= kMaxPasswordLength ? row_by_email(email) : std::nullopt;
    if (!row) {
        // nepoznata e-pošta: isti rad kao provjera lozinke, da se po vremenu ne može doznati postoji li račun
        Bytes dummy = pbkdf2_sha256(password, Bytes(kSaltBytes, 0), iterations_, kHashBytes);
        wipe(dummy);
        wipe(password);
        return res;
    }
    if (row->locked_until > now) {
        wipe(password);
        res.status = LoginResult::Status::Locked;
        res.locked_until = row->locked_until;
        return res;
    }
    const bool good = verify_password(*row, password);
    wipe(password);
    if (!good) {
        count_failure(*row, now, res, LoginResult::Status::BadCredentials);
        return res;
    }
    if (row->disabled) {
        res.status = LoginResult::Status::Disabled;
        return res;
    }
    std::optional<Row> current = row;
    if (row->must_change) {  // početna lozinka: prije svega ostalog nova lozinka
        if (now - row->default_set_at > kDefaultPasswordSeconds) {
            wipe(new_password);
            res.status = LoginResult::Status::PasswordExpired;
            return res;
        }
        if (new_password.empty()) {
            res.status = LoginResult::Status::PasswordChange;
            return res;
        }
        const std::string email_plain = open("email", row->email_enc);
        std::optional<std::string> problem = password_problem(new_password, email_plain);
        if (!problem && new_password == kDefaultPassword) problem = tr("Nova lozinka mora se razlikovati od početne.");
        if (problem) {
            wipe(new_password);
            res.status = LoginResult::Status::PasswordInvalid;
            res.problem = *problem;
            return res;
        }
        set_password_hash(row->id, new_password, now, false);
        wipe(new_password);
        log_info("Korisnici: korisnik #" + std::to_string(row->id) + " je promijenio početnu lozinku");
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
    res.status = LoginResult::Status::Ok;
    res.user = info(*row_by_id(row->id));  // nakon postavljanja dvofaktorske prijave podaci su novi
    res.user->last_login = now;
    return res;
}

void UserStore::count_failure(const Row& r, std::time_t now, LoginResult& res, LoginResult::Status status) {
    const int failed = r.failed + 1;
    const std::time_t until = failed >= kMaxFailedLogins ? now + kLockSeconds : 0;
    Stmt q(db_, "UPDATE users SET failed = ?, locked_until = ? WHERE id = ?");
    q.bind(1, static_cast<int64_t>(until ? 0 : failed)).bind(2, static_cast<int64_t>(until)).bind(3, r.id);
    q.step();
    res.status = until ? LoginResult::Status::Locked : status;
    res.locked_until = until;
}

// Drugi korak prijave; false = res sadrži razlog (treba kod, postavljanje, pogrešan kod ili zaključano)
bool UserStore::second_factor(const Row& r, const std::string& code, std::time_t now, LoginResult& res) {
    if (r.totp_secret_enc.empty()) {  // još nije postavljena: tajna čeka potvrdu prvim kodom
        Bytes secret;
        if (!r.totp_pending_enc.empty()) {
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
            return false;
        }
        res.recovery_codes = make_recovery_codes();
        json hashes = json::array();
        for (const auto& rc : res.recovery_codes) hashes.push_back(to_hex(sha256(normalize_recovery_code(rc))));
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
        return true;
    }
    // kod za oporavak (jednokratan)
    const std::string norm = normalize_recovery_code(code);
    json codes = json::parse(r.recovery.empty() ? "[]" : r.recovery, nullptr, false);
    if (norm.size() == 8 && codes.is_array()) {
        const std::string h = to_hex(sha256(norm));
        for (auto it = codes.begin(); it != codes.end(); ++it) {
            if (!it->is_string()) continue;
            const std::string stored = it->get<std::string>();
            if (equal_ct(Bytes(h.begin(), h.end()), Bytes(stored.begin(), stored.end()))) {
                codes.erase(it);
                Stmt q(db_, "UPDATE users SET recovery = ? WHERE id = ?");
                q.bind(1, codes.dump()).bind(2, r.id);
                q.step();
                log_warn("Korisnici: prijava kodom za oporavak (korisnik #" + std::to_string(r.id) + ", preostalo " + std::to_string(codes.size()) + ")");
                return true;
            }
        }
    }
    count_failure(r, now, res, LoginResult::Status::TotpInvalid);
    return false;
}

void UserStore::reset_to_default_password(int64_t id, std::time_t now) {
    std::lock_guard lock(mu_);
    set_password_hash(id, kDefaultPassword, now, true);  // poništava i sve prijave
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

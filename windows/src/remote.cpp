#include "remote.hpp"

#include <set>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "tls.hpp"
#include "util.hpp"

namespace sm {

namespace {

constexpr int kRecvTimeoutMs = 5000;
// SMA-07: ograničenja istodobnosti i ukupni rok po vezi
constexpr int kWorkers = 8;
constexpr size_t kMaxQueue = 32;
constexpr int kMaxConnectionsPerIp = 4;
constexpr auto kConnectionDeadline = std::chrono::seconds(15);
constexpr size_t kMaxHeaderBytes = 8 * 1024;
constexpr int kMaxHeaders = 100;
constexpr size_t kMaxRequestBytes = 16 * 1024;
constexpr long kAcceptPollUs = 500'000;

const char* status_text(int code) {
    switch (code) {
    case 200: return "OK";
    case 302: return "Found";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 403: return "Forbidden";
    case 405: return "Method Not Allowed";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 423: return "Locked";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 503: return "Service Unavailable";
    default: return code >= 500 ? "Internal Server Error" : "Error";
    }
}

void send_all(SOCKET s, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(s, data.data() + sent, static_cast<int>(std::min<size_t>(data.size() - sent, 1 << 20)), 0);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
    }
}

}  // namespace

// Veza s klijentom: obična utičnica ili TLS (isti kod za zahtjev i odgovor)
struct HttpServer::Conn {
    virtual ~Conn() = default;
    virtual int recv(char* buf, int size) = 0;
    virtual void send(const std::string& data) = 0;
};

namespace {

struct PlainConn : HttpServer::Conn {
    SOCKET s;
    explicit PlainConn(SOCKET sock) : s(sock) {}
    int recv(char* buf, int size) override { return ::recv(s, buf, size, 0); }
    void send(const std::string& data) override { send_all(s, data); }
};

struct SecureConn : HttpServer::Conn {
    TlsConnection& tls;
    explicit SecureConn(TlsConnection& t) : tls(t) {}
    int recv(char* buf, int size) override { return tls.recv(buf, size); }
    void send(const std::string& data) override { tls.send(data); }
};

constexpr char kTlsHandshake = 0x16;  // prvi bajt TLS zapisa ClientHello

void respond(HttpServer::Conn& c, const HttpResponse& r, bool head) {
    std::string out = "HTTP/1.1 " + std::to_string(r.code) + " " + status_text(r.code) + "\r\nContent-Type: " + r.type +
                      "\r\nContent-Length: " + std::to_string(r.body.size()) +
                      "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer"
                      "\r\nX-Frame-Options: DENY\r\nConnection: close\r\n" + r.extra_headers + "\r\n";
    if (!head) out += r.body;
    c.send(out);
}

bool safe_segment(const std::string& path) {
    if (path.find("..") != std::string::npos || path.find('\\') != std::string::npos || path.find(':') != std::string::npos) {
        return false;
    }
    for (unsigned char c : path) if (c < 0x20 || c == '%') return false;  // bez kodiranih znakova (%2e%2e…)
    return true;
}

bool inside(const fs::path& base, const fs::path& file) {
    std::error_code ec;
    const fs::path b = fs::weakly_canonical(base, ec), f = fs::weakly_canonical(file, ec);
    if (ec) return false;
    const auto rel = f.lexically_relative(b);
    return !rel.empty() && rel.native()[0] != L'.';
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

}  // namespace

// ---------------------------------------------------------------- zahtjev i odgovor
std::string HttpRequest::header(const std::string& name) const {
    const auto it = headers.find(lower(name));
    return it == headers.end() ? std::string{} : it->second;
}

std::string HttpRequest::param(const std::string& name) const {
    size_t pos = 0;
    while (pos <= query.size()) {
        const size_t amp = query.find('&', pos);
        const std::string part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        if (part.rfind(name + "=", 0) == 0) return part.substr(name.size() + 1);
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return {};
}

HttpResponse HttpResponse::json_body(int code, const nlohmann::json& j) { return {code, "application/json; charset=utf-8", j.dump()}; }
HttpResponse HttpResponse::text(int code, const std::string& body) { return {code, "text/plain; charset=utf-8", body}; }

std::string content_type(const std::wstring& path) {
    static const std::map<std::wstring, std::string> kTypes = {
        {L".html", "text/html; charset=utf-8"}, {L".js", "text/javascript; charset=utf-8"},
        {L".css", "text/css; charset=utf-8"},   {L".json", "application/json; charset=utf-8"},
        {L".png", "image/png"},                 {L".jpg", "image/jpeg"}, {L".jpeg", "image/jpeg"},
        {L".webp", "image/webp"},               {L".svg", "image/svg+xml"}, {L".ttf", "font/ttf"},
        {L".ico", "image/x-icon"}};
    std::wstring ext = fs::path(path).extension().wstring();
    for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));
    const auto it = kTypes.find(ext);
    return it == kTypes.end() ? "application/octet-stream" : it->second;
}

// ---------------------------------------------------------------- poslužitelj
bool HttpServer::start(int port, bool lan) {
    stop();
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return false;
    BOOL exclusive = TRUE;
    setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof exclusive);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(lan ? INADDR_ANY : INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<u_short>(port));
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 || listen(listener, 16) != 0) {
        log_warn("HTTP poslužitelj: port " + std::to_string(port) + " nije dostupan (" + std::to_string(WSAGetLastError()) + ")");
        closesocket(listener);
        return false;
    }
    port_ = port;
    lan_ = lan;
    stop_ = false;
    for (int i = 0; i < kWorkers; ++i) workers_.emplace_back([this] { worker(); });
    watchdog_ = std::thread([this] { watchdog(); });
    thread_ = std::thread([this, listener] { run(static_cast<uintptr_t>(listener)); });
    log_info("HTTP poslužitelj sluša na " + std::string(lan ? "svim mrežama" : "127.0.0.1") + ", port " + std::to_string(port));
    return true;
}

void HttpServer::set_tls(std::shared_ptr<TlsCredentials> creds) { tls_ = std::move(creds); }

void HttpServer::stop() {
    stop_ = true;
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    for (auto& w : workers_) if (w.joinable()) w.join();
    workers_.clear();
    if (watchdog_.joinable()) watchdog_.join();
    std::lock_guard lock(mu_);
    for (const auto& p : queue_) closesocket(static_cast<SOCKET>(p.socket));  // neobrađene veze pri zaustavljanju
    queue_.clear();
    per_ip_.clear();
    port_ = 0;
}

void HttpServer::worker() {
    for (;;) {
        Pending job;
        {
            std::unique_lock lock(mu_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (stop_) return;
            job = std::move(queue_.front());
            queue_.pop_front();
            deadlines_[job.socket] = std::chrono::steady_clock::now() + kConnectionDeadline;
        }
        const SOCKET client = static_cast<SOCKET>(job.socket);
        try {
            serve(job.socket, job.peer);
        } catch (const std::exception& e) {
            log_warn(std::string("HTTP poslužitelj: ") + e.what());
        }
        // uredno zatvaranje: odgovor (npr. 431) mora stići i kad klijent još šalje – inače RST briše odgovor
        shutdown(client, SD_SEND);
        char sink[4096];
        for (int i = 0; i < 64; ++i) {  // pročitaj ostatak bez isteka recv-a (istek ostavlja utičnicu u neodređenom stanju)
            fd_set rd;
            FD_ZERO(&rd);
            FD_SET(client, &rd);
            timeval wait{0, 100'000};
            if (select(0, &rd, nullptr, nullptr, &wait) <= 0) break;
            if (::recv(client, sink, sizeof sink, 0) <= 0) break;
        }
        std::lock_guard lock(mu_);  // nadzorna nit ne smije dirati utičnicu nakon zatvaranja
        deadlines_.erase(job.socket);
        closesocket(client);
        if (--per_ip_[job.peer] <= 0) per_ip_.erase(job.peer);
    }
}

// Veza koja traje dulje od ukupnog roka (spori klijent, nedovršeno TLS rukovanje) se prekida:
// recv/send u radnoj niti tada odmah vrate grešku i nit je slobodna za druge klijente.
void HttpServer::watchdog() {
    while (!stop_) {
        Sleep(200);
        std::lock_guard lock(mu_);
        const auto now = std::chrono::steady_clock::now();
        for (auto& [sock, deadline] : deadlines_) {
            if (now > deadline) {
                shutdown(static_cast<SOCKET>(sock), SD_BOTH);
                deadline = std::chrono::steady_clock::time_point::max();  // jednom je dovoljno
            }
        }
    }
}

void HttpServer::run(uintptr_t listener_handle) {
    const SOCKET listener = static_cast<SOCKET>(listener_handle);
    while (!stop_) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(listener, &set);
        timeval tv{0, kAcceptPollUs};
        if (select(0, &set, nullptr, nullptr, &tv) <= 0) continue;
        sockaddr_in from{};
        int from_len = sizeof from;
        const SOCKET client = accept(listener, reinterpret_cast<sockaddr*>(&from), &from_len);
        if (client == INVALID_SOCKET) continue;
        char ip[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
        DWORD timeout = kRecvTimeoutMs;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof timeout);
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof timeout);
        bool accepted = false;
        {
            std::lock_guard lock(mu_);
            if (queue_.size() < kMaxQueue && per_ip_[ip] < kMaxConnectionsPerIp) {
                ++per_ip_[ip];
                queue_.push_back({static_cast<uintptr_t>(client), ip});
                accepted = true;
            } else if (per_ip_[ip] == 0) {
                per_ip_.erase(ip);
            }
        }
        if (accepted) {
            cv_.notify_one();
        } else {  // previše veza: odbijanje bez obrade (SMA-07)
            closesocket(client);
        }
    }
    closesocket(listener);
}

// S TLS-om (Solarni poslužitelj): šifrirana veza ili obični HTTP samo s 127.0.0.1 (cloudflared na istom računalu)
void HttpServer::serve(uintptr_t client_handle, const std::string& peer) {
    const SOCKET client = static_cast<SOCKET>(client_handle);
    if (!tls_) {
        PlainConn c(client);
        handle(c, peer);
        return;
    }
    char first = 0;
    if (::recv(client, &first, 1, MSG_PEEK) != 1) return;
    if (first == kTlsHandshake) {
        TlsConnection tls(client_handle, *tls_);
        if (!tls.handshake()) return;
        SecureConn c(tls);
        handle(c, peer);
        tls.shutdown();
        return;
    }
    PlainConn c(client);
    if (peer != "127.0.0.1") {
        // zaglavlja se pročitaju (i odbace) da klijent dobije odgovor 400, a ne prekinutu vezu
        std::string head;
        char buf[2048];
        while (head.find("\r\n\r\n") == std::string::npos && head.size() < kMaxRequestBytes) {
            const int n = c.recv(buf, sizeof buf);
            if (n <= 0) return;
            head.append(buf, static_cast<size_t>(n));
        }
        respond(c, HttpResponse::text(400, "HTTPS je obavezan / HTTPS required"), false);
        return;
    }
    handle(c, peer);
}

void HttpServer::handle(Conn& client, const std::string& peer) {
    std::string raw;
    char buf[4096];
    while (raw.find("\r\n\r\n") == std::string::npos && raw.size() < kMaxHeaderBytes) {
        const int n = client.recv(buf, sizeof buf);
        if (n <= 0) return;
        raw.append(buf, static_cast<size_t>(n));
    }
    const size_t header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos || header_end > kMaxHeaderBytes) {
        respond(client, HttpResponse::text(431, "431"), false);
        return;
    }
    int header_lines = 0;
    for (size_t at = raw.find("\r\n"); at != std::string::npos && at < header_end; at = raw.find("\r\n", at + 2)) ++header_lines;
    if (header_lines > kMaxHeaders) {
        respond(client, HttpResponse::text(431, "431"), false);
        return;
    }
    HttpRequest req;
    req.peer = peer;
    size_t pos = raw.find("\r\n");
    const std::string line = raw.substr(0, pos);
    const auto sp1 = line.find(' '), sp2 = line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
        respond(client, HttpResponse::text(400, "400"), false);
        return;
    }
    req.method = line.substr(0, sp1);
    req.target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const auto q = req.target.find('?');
    req.path = req.target.substr(0, std::min(q, req.target.find('#')));
    if (q != std::string::npos) req.query = req.target.substr(q + 1, req.target.find('#', q) - q - 1);
    const size_t head_end = raw.find("\r\n\r\n");
    while (pos != std::string::npos && pos < head_end) {
        const size_t next = raw.find("\r\n", pos + 2);
        const std::string h = raw.substr(pos + 2, next - pos - 2);
        if (const auto colon = h.find(':'); colon != std::string::npos) {
            const std::string name = lower(trim(h.substr(0, colon)));
            // dvostruki Content-Length ili Host = dvosmislen zahtjev (smuggling) → odbijeno (SMA-16)
            if ((name == "content-length" || name == "host") && req.headers.count(name)) {
                respond(client, HttpResponse::text(400, "400"), false);
                return;
            }
            req.headers[name] = trim(h.substr(colon + 1));
        }
        pos = next;
    }
    if (req.method != "GET" && req.method != "HEAD" && req.method != "POST") {
        HttpResponse r = HttpResponse::text(405, "405");
        r.extra_headers = "Allow: GET, HEAD, POST\r\n";
        respond(client, r, false);
        return;
    }
    if (req.method == "POST") {
        const std::string len_text = req.header("Content-Length");
        const long long len = len_text.empty() ? -1 : std::atoll(len_text.c_str());
        if (len < 0 || static_cast<size_t>(len) > kMaxRequestBytes || !req.header("Transfer-Encoding").empty()) {
            respond(client, HttpResponse::text(len < 0 ? 411 : 413, "Bad length"), false);
            return;
        }
        req.body = raw.substr(head_end + 4);
        while (req.body.size() < static_cast<size_t>(len)) {
            const int n = client.recv(buf, sizeof buf);
            if (n <= 0) return;
            req.body.append(buf, static_cast<size_t>(n));
        }
        req.body.resize(static_cast<size_t>(len));
    }
    respond(client, handler_(req), req.method == "HEAD");
}

// ---------------------------------------------------------------- pregled iz mreže (4.0: SMA-08, SMA-27)
namespace {

// Točan popis javnih datoteka (bez spajanja korisničkog unosa u put): ime u URL-u → datoteka u mapi web
const std::set<std::string>& web_allowlist() {
    static const std::set<std::string> kFiles = {
        "index.html", "bridge.js", "i18n.js", "themes.js", "colors.js", "components.js", "charts.js", "widgets.js",
        "dashboard.js", "pages.js", "dashboard-dark.css", "dashboard-light.css", "devices.css", "catalog.json",
        "vendor/plotly-basic.min.js", "vendor/PlusJakartaSans.ttf", "i18n/hr.json", "i18n/en.json", "i18n/de.json",
        "i18n/es.json", "i18n/fr.json", "i18n/it.json", "i18n/ja.json", "i18n/ko.json", "i18n/tr.json", "i18n/zh.json"};
    return kFiles;
}

// Pogrešni ključevi po adresi: 10 u 10 minuta → 429 na 10 minuta
struct KeyFailures {
    int count = 0;
    std::time_t window_start = 0, blocked_until = 0;
};
std::mutex g_view_mutex;
std::map<std::string, KeyFailures> g_view_failures;

bool view_blocked(const std::string& ip, std::time_t t) {
    std::lock_guard lock(g_view_mutex);
    const auto it = g_view_failures.find(ip);
    return it != g_view_failures.end() && it->second.blocked_until > t;
}

void view_failure(const std::string& ip, std::time_t t) {
    std::lock_guard lock(g_view_mutex);
    if (g_view_failures.size() > 10'000) {
        for (auto it = g_view_failures.begin(); it != g_view_failures.end();) {
            it = it->second.blocked_until <= t ? g_view_failures.erase(it) : std::next(it);
        }
    }
    KeyFailures& f = g_view_failures[ip];
    if (t - f.window_start > 600) f = KeyFailures{0, t, 0};
    if (++f.count >= 10) f.blocked_until = t + 600;
}

bool key_matches(const std::string& given, const std::string& expected) {
    if (expected.empty() || given.size() != expected.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < given.size(); ++i) diff |= static_cast<unsigned char>(given[i] ^ expected[i]);
    return diff == 0;
}

// Slika iz JSON-a dashboarda (adresu je izradio program, ne klijent) → datoteka; samo data.solari i app.solari/assets
std::optional<fs::path> image_file_from_url(const std::string& url) {
    std::string rel;
    fs::path base;
    if (url.rfind("https://data.solari/", 0) == 0) {
        rel = url.substr(20);
        base = images_dir();
    } else if (url.rfind("https://app.solari/assets/", 0) == 0) {
        rel = url.substr(26);
        base = exe_dir() / L"assets";
    } else {
        return std::nullopt;
    }
    rel = rel.substr(0, rel.find_first_of("?#"));
    if (rel.empty() || !safe_segment("/" + rel)) return std::nullopt;
    const fs::path file = base / widen(rel);
    std::error_code ec;
    if (!inside(base, file) || !fs::is_regular_file(file, ec)) return std::nullopt;
    return file;
}

HttpResponse view_unauthorized() {
    return HttpResponse::json_body(401, {{"error", "view_key_required"}, {"message", "X-Solari-View-Key"}});
}

}  // namespace

std::optional<std::wstring> resolve_remote_path(const std::string& url_path) {
    // samo /web/<ime s popisa>; /data/*, /assets/* i sve ostalo – nedostupno (SMA-27)
    const std::string path = url_path.substr(0, url_path.find_first_of("?#"));
    if (path.rfind("/web/", 0) != 0) return std::nullopt;
    const std::string name = path.substr(5);
    if (!web_allowlist().count(name)) return std::nullopt;
    std::wstring rel = widen(name);
    for (auto& c : rel) if (c == L'/') c = L'\\';
    const fs::path file = exe_dir() / L"web" / rel;
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) return std::nullopt;
    return file.wstring();
}

json public_dashboard(json d) {
    // SMA-08: bez tehničkih postavki (adresa uređaja, adrese na sabirnici); mjerač samo kao da/ne
    if (d.contains("settings") && d["settings"].is_object()) {
        json& s = d["settings"];
        const bool meter = s.value("meter_unit_id", 0) != 0;
        s.erase("modbus_host");
        s["meter_unit_id"] = meter ? 1 : 0;
    }
    return d;
}

HttpServer::Handler remote_view_handler(std::function<nlohmann::json()> data, std::function<std::string()> key) {
    return [data = std::move(data), key = std::move(key)](const HttpRequest& req) {
        if (req.method != "GET" && req.method != "HEAD") return HttpResponse::text(405, "405");
        if (req.path == "/" || req.path == "/index.html") {
            HttpResponse r = HttpResponse::text(302, "");
            r.extra_headers = "Location: /web/index.html\r\n";
            return r;
        }
        if (req.path == "/api/dashboard" || req.path.rfind("/api/image/", 0) == 0) {
            const std::time_t t = now();
            if (view_blocked(req.peer, t)) return HttpResponse::json_body(429, {{"error", "too_many_attempts"}});
            if (!key_matches(req.header("X-Solari-View-Key"), key())) {  // ključ samo u zaglavlju, nikad u URL-u
                view_failure(req.peer, t);
                return view_unauthorized();
            }
            const json d = data();
            if (req.path == "/api/dashboard") return HttpResponse::json_body(200, public_dashboard(d));
            const std::string kind = req.path.substr(11);
            if (kind != "hero" && kind != "drawing" && kind != "logo") return HttpResponse::text(404, "404");
            const std::string url = d.contains("images") ? d["images"].value(kind, "") : "";
            const auto file = image_file_from_url(url);
            const auto body = file ? read_file(*file) : std::nullopt;
            if (!body) return HttpResponse::text(404, "404");
            return HttpResponse{200, content_type(file->wstring()), *body};
        }
        const auto file = resolve_remote_path(req.target);
        const auto body = file ? read_file(*file) : std::nullopt;
        if (!body) return HttpResponse::text(404, "404");
        return HttpResponse{200, content_type(*file), *body};
    };
}

}  // namespace sm

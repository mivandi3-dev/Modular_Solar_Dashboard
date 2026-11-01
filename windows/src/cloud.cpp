#include "cloud.hpp"

#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <memory>

#include "dashboard.hpp"
#include "images.hpp"
#include "i18n.hpp"
#include "crypto.hpp"
#include "secret.hpp"
#include "tls.hpp"

namespace sm {

namespace {

constexpr size_t kMaxBodyBytes = 25 * 1024 * 1024;
const char* const kImageKinds[] = {"hero", "drawing", "logo"};

struct Handle {
    HINTERNET h = nullptr;
    explicit Handle(HINTERNET v) : h(v) {}
    ~Handle() { if (h) WinHttpCloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

[[noreturn]] void fail_connect(const std::string& url, DWORD err) {
    if (err == ERROR_WINHTTP_TIMEOUT) throw CloudError(tr("Poslužitelj {url} ne odgovara.", {{"url", url}}));
    if (err == ERROR_WINHTTP_SECURE_FAILURE) throw CloudError(tr("Sigurna veza (HTTPS) s poslužiteljem {url} nije uspjela.", {{"url", url}}));
    throw CloudError(tr("Nije moguće spojiti se na poslužitelj {url}.", {{"url", url}}) + " (WinHTTP " + std::to_string(err) + ")");
}

std::string header(HINTERNET req, DWORD what) {
    wchar_t buf[256];
    DWORD size = sizeof buf;
    if (!WinHttpQueryHeaders(req, what, WINHTTP_HEADER_NAME_BY_INDEX, buf, &size, WINHTTP_NO_HEADER_INDEX)) return {};
    return narrow(std::wstring(buf, size / sizeof(wchar_t)));
}

std::string token_of(const Settings& s) { return unprotect_secret(s.cloud_token_enc); }

// Provjera certifikata prije slanja zahtjeva (WinHTTP poziva prije prvog bajta zahtjeva)
struct PinCheck {
    std::string expected, seen;
    bool mismatch = false;
};

void CALLBACK on_sending(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID, DWORD) {
    if (status != WINHTTP_CALLBACK_STATUS_SENDING_REQUEST || !ctx) return;
    auto* pin = reinterpret_cast<PinCheck*>(ctx);
    PCCERT_CONTEXT cert = nullptr;
    DWORD size = sizeof cert;
    if (WinHttpQueryOption(h, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &size) && cert) {
        const Bytes d = sha256(std::string(reinterpret_cast<const char*>(cert->pbCertEncoded), cert->cbCertEncoded));
        pin->seen = format_fingerprint(std::string(d.begin(), d.end()));
        CertFreeCertificateContext(cert);
    }
    if (!pin->expected.empty() && pin->seen != pin->expected) {
        pin->mismatch = true;
        WinHttpCloseHandle(h);  // zahtjev se prekida prije slanja zaglavlja i tijela
    }
}

std::string image_ext(const std::string& type) {
    if (type.find("png") != std::string::npos) return ".png";
    if (type.find("webp") != std::string::npos) return ".webp";
    return ".jpg";
}

// "/api/v1/images/hero?v=123" → slika u data\images\cloud\hero-123.<ext> (preuzima se samo nova verzija)
std::string cached_image(const Settings& s, const std::string& kind, const std::string& api_url) {
    std::string version;
    if (const auto q = api_url.find("v="); q != std::string::npos) {
        for (char c : api_url.substr(q + 2)) if (std::isdigit(static_cast<unsigned char>(c))) version += c; else break;
    }
    const fs::path dir = images_dir() / L"cloud";
    std::error_code ec;
    if (!ui_write_allowed(dir)) throw CloudError("Mapa slika je spojnica ili simbolička veza.");  // NEW-05
    fs::create_directories(dir, ec);
    const std::wstring prefix = widen(kind + "-" + version);
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (e.path().stem().wstring() == prefix) return "https://data.solari/cloud/" + narrow(e.path().filename().wstring()) + "?v=" + version;
    }
    HttpCall call;
    call.path = "/api/v1/images/" + kind;
    call.token = token_of(s);
    call.pin = s.cloud_cert_pin;
    const HttpResult r = http_call(s.cloud_url, call);
    wipe(call.token);
    if (r.status != 200) throw CloudError(tr("Poslužitelj je vratio grešku {code}.", {{"code", std::to_string(r.status)}}));
    const fs::path file = dir / (prefix + widen(image_ext(r.content_type)));
    for (const auto& e : fs::directory_iterator(dir, ec)) {  // stare verzije iste slike
        if (e.path().stem().wstring().rfind(widen(kind + "-"), 0) == 0) fs::remove(e.path(), ec);
    }
    write_file_atomic(file, r.body);
    return "https://data.solari/cloud/" + narrow(file.filename().wstring()) + "?v=" + version;
}

}  // namespace

bool pinned_host(const std::string& base_url) {
    if (base_url.rfind("https://", 0) != 0) return false;
    std::string host = base_url.substr(8);
    host = host.substr(0, host.find_first_of(":/"));
    if (host.empty() || host.front() == '[' || host == "localhost") return true;
    if (std::all_of(host.begin(), host.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)) || c == '.'; })) return true;
    if (host.find('.') == std::string::npos) return true;
    for (const char* suffix : {".local", ".lan", ".home", ".internal"}) {
        const std::string sfx = suffix;
        if (host.size() > sfx.size() && host.compare(host.size() - sfx.size(), sfx.size(), sfx) == 0) return true;
    }
    return false;
}

HttpResult http_call(const std::string& base_url, const HttpCall& call) {
    const std::wstring url = widen(base_url + call.path);
    URL_COMPONENTS parts{sizeof parts};
    wchar_t host[256] = L"", object[2048] = L"";
    parts.lpszHostName = host;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = object;
    parts.dwUrlPathLength = 1024;
    parts.lpszExtraInfo = object + 1024;
    parts.dwExtraInfoLength = 1024;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) throw CloudError(tr("Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr"));
    const bool https = parts.nScheme == INTERNET_SCHEME_HTTPS;
    const bool pinned = pinned_host(base_url);
    const std::wstring target = std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength) +
                                std::wstring(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    // tajne idu samo šifrirano (ili na 127.0.0.1)
    if (!https && (!call.token.empty() || !call.body.empty()) && std::wstring(host) != L"127.0.0.1" && std::wstring(host) != L"localhost") {
        throw CloudError(tr("Poslužitelj u mreži mora imati adresu https://."));
    }

    Handle session(WinHttpOpen(widen(std::string("SolarniMonitor/") + SOLARI_VERSION).c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) fail_connect(base_url, GetLastError());
    WinHttpSetTimeouts(session.h, call.timeout_ms, call.timeout_ms, call.timeout_ms, call.timeout_ms);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(session.h, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof protocols);
    Handle conn(WinHttpConnect(session.h, host, parts.nPort, 0));
    if (!conn) fail_connect(base_url, GetLastError());
    Handle req(WinHttpOpenRequest(conn.h, widen(call.method).c_str(), target.c_str(), nullptr, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0));
    if (!req) fail_connect(base_url, GetLastError());
    // SMA-10: preusmjeravanja se nikad ne slijede (zaglavlje Authorization ne smije otići drugom poslužitelju)
    DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(req.h, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof redirects);
    PinCheck pin{call.pin, {}, false};
    if (https && pinned) {
        // vlastiti certifikat poslužitelja: izdavač i ime se ne provjeravaju, nego otisak (prije slanja zahtjeva)
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(req.h, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof flags);
        DWORD_PTR ctx = reinterpret_cast<DWORD_PTR>(&pin);
        WinHttpSetOption(req.h, WINHTTP_OPTION_CONTEXT_VALUE, &ctx, sizeof ctx);
        WinHttpSetStatusCallback(req.h, on_sending, WINHTTP_CALLBACK_FLAG_SEND_REQUEST, 0);
        if (call.pin.empty() && (!call.token.empty() || !call.body.empty())) {
            throw CloudError(tr("Prijavite se na poslužitelj (e-pošta i lozinka)."));  // tajne nikad bez poznatog otiska
        }
    }
    std::wstring headers = L"Accept: application/json, image/*\r\n";
    if (!call.token.empty()) headers += L"Authorization: Bearer " + widen(call.token) + L"\r\n";
    if (!call.body.empty()) headers += L"Content-Type: application/json\r\n";
    const BOOL sent = WinHttpSendRequest(req.h, headers.c_str(), static_cast<DWORD>(headers.size()),
                                         call.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(call.body.data()),
                                         static_cast<DWORD>(call.body.size()), static_cast<DWORD>(call.body.size()), 0) &&
                      WinHttpReceiveResponse(req.h, nullptr);
    SecureZeroMemory(headers.data(), headers.size() * sizeof(wchar_t));
    if (pin.mismatch) {
        req.h = nullptr;  // zatvorio ju je povratni poziv
        log_warn("Solarni poslužitelj: otisak certifikata " + pin.seen + " ne odgovara zapamćenom " + call.pin);
        throw CloudError(tr("Certifikat poslužitelja se promijenio – veza je prekinuta prije slanja podataka. Ako ste "
                            "ponovno instalirali poslužitelj, prijavite se ponovno; inače netko u mreži možda presreće promet."));
    }
    if (!sent) fail_connect(base_url, GetLastError());
    HttpResult out;
    out.cert_fingerprint = pin.seen;
    out.status = std::atoi(header(req.h, WINHTTP_QUERY_STATUS_CODE).c_str());
    out.content_type = header(req.h, WINHTTP_QUERY_CONTENT_TYPE);
    for (DWORD avail = 0; WinHttpQueryDataAvailable(req.h, &avail) && avail > 0;) {
        std::string chunk(avail, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(req.h, chunk.data(), avail, &read) || read == 0) break;
        out.body.append(chunk.data(), read);
        if (out.body.size() > kMaxBodyBytes) throw CloudError(tr("Poslužitelj je vratio grešku {code}.", {{"code", "413"}}));
    }
    if (out.status == 429) throw CloudError(tr("Previše pogrešnih pokušaja – pokušajte ponovno za nekoliko minuta."));
    if (out.status >= 300 && out.status < 400) {
        throw CloudError(tr("Poslužitelj preusmjerava na drugu adresu – provjerite adresu poslužitelja (preusmjeravanja se ne slijede)."));
    }
    return out;
}

namespace {
json parse_server_json(const HttpResult& r) {
    try {
        return json::parse(r.body);
    } catch (const json::exception&) {
        throw CloudError(tr("Odgovor nije od Solarnog poslužitelja – provjerite adresu."));
    }
}
}  // namespace

CloudLogin cloud_login(const std::string& base_url, const std::string& email, std::string password, const std::string& known_pin,
                       const std::string& totp, std::string new_password, const std::string& entered_code) {
    HttpCall ping;
    ping.path = "/api/v1/ping";
    ping.pin = known_pin;  // ista adresa kao prije: certifikat se ne smije promijeniti
    const HttpResult p = http_call(base_url, ping);
    const json info = p.status == 200 ? parse_server_json(p) : json::object();
    if (info.value("api", 0) < 4) {
        throw CloudError(p.status == 200 ? tr("Poslužitelj nije verzije 4.0 – instalirajte Solarni poslužitelj 4.0.")
                                         : tr("Poslužitelj je vratio grešku {code}.", {{"code", std::to_string(p.status)}}));
    }
    if (!info.value("setup", false)) throw CloudError(tr("Poslužitelj još nema administratora – otvorite Solarni poslužitelj i izradite ga."));

    // SMA-04: prvi kontakt s poslužiteljem u lokalnoj mreži – otisak se potvrđuje kodom s prozora poslužitelja
    // (TOFU ne postoji); bez točnog koda lozinka se ne šalje
    if (pinned_host(base_url) && known_pin.empty() && !pairing_code_matches(entered_code, p.cert_fingerprint)) {
        wipe(password);
        wipe(new_password);
        throw CloudPairingNeeded(entered_code.empty()
            ? tr("Upišite kod za uparivanje s prozora Solarnog poslužitelja (Postavke → Poslužitelj).")
            : tr("Kod za uparivanje ne odgovara certifikatu poslužitelja – provjerite kod i adresu (moguće presretanje veze)."));
    }

    HttpCall login;
    login.method = "POST";
    login.path = "/api/v1/login";
    login.pin = pinned_host(base_url) ? p.cert_fingerprint : "";
    login.body = json{{"email", trim(email)}, {"password", password}, {"device", "Solarni monitor (Windows)"}, {"totp", trim(totp)},
                      {"new_password", new_password}}.dump();
    wipe(new_password);
    wipe(password);
    HttpResult r;
    try {
        r = http_call(base_url, login);
    } catch (...) {
        wipe(login.body);
        throw;
    }
    wipe(login.body);
    const json j = parse_server_json(r);
    const std::string error = j.value("error", "");
    if (error == "activation_required") throw CloudPasswordChange(tr("Aktivacijski kod je točan – postavite svoju lozinku."));
    if (error == "password_invalid") throw CloudPasswordChange(j.value("message", tr("Nova lozinka ne zadovoljava pravila.")));
    if (r.status == 401 && error.rfind("totp_", 0) == 0) {
        json info = {{"step", error == "totp_setup" || j.contains("uri") ? "setup" : "code"}, {"invalid", error == "totp_invalid"}};
        if (j.contains("uri")) info.update({{"secret", j.value("secret", "")}, {"uri", j.value("uri", "")}});
        throw CloudTotpNeeded(error == "totp_invalid" ? tr("Kod nije točan ili je već iskorišten.")
                              : info["step"] == "setup" ? tr("Skenirajte QR kod aplikacijom autentifikatorom i upišite prikazani kod.")
                                                        : tr("Upišite kod iz aplikacije autentifikatora."),
                              info);
    }
    if (r.status == 401) throw CloudError(tr("Pogrešna e-pošta ili lozinka."));
    if (r.status == 423) throw CloudError(tr("Previše pogrešnih lozinki – račun je privremeno zaključan (15 minuta)."));
    if (r.status == 403) throw CloudError(tr("Račun je blokiran – obratite se administratoru poslužitelja."));
    if (r.status != 200 || !j.contains("token")) throw CloudError(tr("Poslužitelj je vratio grešku {code}.", {{"code", std::to_string(r.status)}}));
    const json& u = j.value("user", json::object());
    CloudLogin out;
    out.token = j["token"].get<std::string>();
    out.pin = login.pin;
    if (j.contains("recovery_codes") && j["recovery_codes"].is_array()) {
        for (const auto& rc : j["recovery_codes"]) if (rc.is_string()) out.recovery_codes.push_back(rc.get<std::string>());
    }
    out.account = {{"email", u.value("email", "")}, {"name", trim(u.value("first_name", "") + " " + u.value("last_name", ""))},
                   {"role", u.value("role", "user")}};
    return out;
}

void cloud_logout(const Settings& s) {
    if (s.cloud_url.empty() || s.cloud_token_enc.empty()) return;
    try {
        HttpCall call;
        call.method = "POST";
        call.path = "/api/v1/logout";
        call.token = token_of(s);
        call.body = "{}";
        call.pin = s.cloud_cert_pin;
        call.timeout_ms = 5'000;
        http_call(s.cloud_url, call);
        wipe(call.token);
    } catch (const std::exception& e) {
        log_warn(std::string("Odjava s poslužitelja: ") + e.what());
    }
}

json cloud_json(const Settings& s, const std::string& path) {
    if (s.cloud_url.empty()) throw CloudError(tr("Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr"));
    if (s.cloud_token_enc.empty()) throw CloudError(tr("Prijavite se na poslužitelj (e-pošta i lozinka)."));
    HttpCall call;
    call.path = path;
    call.token = token_of(s);
    call.pin = s.cloud_cert_pin;
    const HttpResult r = http_call(s.cloud_url, call);
    wipe(call.token);
    if (r.status == 401) throw CloudError(tr("Prijava je istekla ili je poništena – prijavite se ponovno u postavkama (Mreža → Solarni poslužitelj)."));
    if (r.status != 200) throw CloudError(tr("Poslužitelj je vratio grešku {code}.", {{"code", std::to_string(r.status)}}));
    return parse_server_json(r);
}

json cloud_dashboard(const Settings& s, const Catalog& catalog) {
    json d = cloud_json(s, "/api/v1/dashboard");
    // Raspored widgeta i prikaz (tema, jezik, noćni način) su lokalni; podaci, naslov i slike s poslužitelja.
    d.update(pages_json(load_pages(catalog, layout_file())));
    if (!d.contains("settings") || !d["settings"].is_object()) d["settings"] = json::object();
    apply_local_display(d["settings"], s);
    json images = json::object();
    for (const char* kind : kImageKinds) {
        const std::string api_url = d.contains("images") ? d["images"].value(kind, std::string{}) : std::string{};
        try {
            images[kind] = cached_image(s, kind, api_url);
        } catch (const std::exception& e) {
            log_warn(std::string("Slika s poslužitelja (") + kind + "): " + e.what());
            images[kind] = image_url(kind);
        }
    }
    d["images"] = images;
    d["version"] = SOLARI_VERSION;
    return d;
}

}  // namespace sm

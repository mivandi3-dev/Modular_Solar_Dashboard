// Mali HTTP poslužitelj (Winsock) i dva rukovatelja:
//   * pregled iz mreže (Postavke → Sustav): dashboard samo za čitanje u pregledniku
//       GET /                 → /web/index.html (bez editora i prečaca)
//       GET /web/…, /assets/… → datoteke iz mape programa;  GET /data/<slika> → vlastite slike
//       GET /api/dashboard    → podaci (isti JSON kao get_dashboard u aplikaciji)
//   * API poslužitelja (src/api.cpp) – prijava korisnika i oznaka prijave (Bearer)
// Zahtjevi se obrađuju jedan po jedan (nekoliko klijenata osvježava se svakih 10 s).
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "net.hpp"

namespace sm {

class TlsCredentials;

struct HttpRequest {
    std::string method, target, path, query;
    std::map<std::string, std::string> headers;  // nazivi malim slovima
    std::string peer;                             // IP adresa klijenta
    std::string body;                             // POST (najviše 16 KB)
    std::string header(const std::string& name) const;
    std::string param(const std::string& name) const;  // iz query stringa
};

struct HttpResponse {
    int code = 200;
    std::string type = "application/json; charset=utf-8";
    std::string body;
    std::string extra_headers;  // "Naziv: vrijednost\r\n"…
    static HttpResponse json_body(int code, const nlohmann::json& j);
    static HttpResponse text(int code, const std::string& body);
};

class HttpServer {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;
    explicit HttpServer(Handler handler) : handler_(std::move(handler)) {}
    ~HttpServer() { stop(); }
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    // lan=false: samo 127.0.0.1 (npr. cloudflared na istom računalu); false ako je port zauzet (zapisano u log)
    bool start(int port, bool lan);
    // HTTPS (Solarni poslužitelj): prije start(); obični HTTP tada prima samo s 127.0.0.1
    void set_tls(std::shared_ptr<TlsCredentials> creds);
    bool tls() const { return tls_ != nullptr; }
    struct Conn;
    void stop();
    int port() const { return port_; }
    bool lan() const { return lan_; }

private:
    void run(uintptr_t listener);
    void serve(uintptr_t client, const std::string& peer);
    void handle(Conn& client, const std::string& peer);

    NetInit net_;  // Winsock dok poslužitelj postoji
    Handler handler_;
    std::shared_ptr<TlsCredentials> tls_;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    int port_ = 0;
    bool lan_ = false;
};

// Pregled iz mreže: datoteke programa i slika te /api/dashboard (bez ključa – samo lokalna mreža).
HttpServer::Handler remote_view_handler(std::function<nlohmann::json()> data);

// Putanja zahtjeva → datoteka na disku (nullopt = nije dopušteno ili ne postoji). Testira se zasebno.
std::optional<std::wstring> resolve_remote_path(const std::string& url_path);

std::string content_type(const std::wstring& path);

}  // namespace sm

// HTTPS za Solarni poslužitelj u lokalnoj mreži (3.0): Windows SChannel, TLS 1.2 i 1.3, bez vanjskih biblioteka.
//
// Certifikat: poslužitelj ga sam izradi pri prvom pokretanju (RSA 3072, SHA-256, vrijedi 10 godina) u spremištu
// certifikata računala (LocalMachine\My; bez administratorskih prava CurrentUser\My). Privatni ključ ostaje u
// Windowsu i ne može se izvesti. Klijenti ne vjeruju izdavaču nego otisku (SHA-256 cijelog certifikata): zapamte
// ga pri prvom spajanju i poslije odbijaju svaki drugi – otisak je prikazan i u prozoru poslužitelja.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace sm {

inline constexpr wchar_t kServerCertName[] = L"Solarni posluzitelj (Solari)";

struct ServerCert {
    std::string fingerprint;  // "AB:CD:…" (SHA-256, 32 bajta)
    std::string not_after;    // "2036-10-30"
    bool machine = false;     // LocalMachine (servis) ili CurrentUser
};

// Postojeći valjani certifikat s privatnim ključem ili novi. name: samo za testove (zasebni certifikat).
ServerCert ensure_server_certificate(const std::wstring& name = kServerCertName);
std::optional<ServerCert> find_server_certificate(const std::wstring& name = kServerCertName);  // bez izrade (prozor poslužitelja)
void remove_server_certificate(const std::wstring& name);  // testovi
std::string format_fingerprint(const std::string& raw_sha256);  // 32 bajta → "AB:CD:…"

// Vjerodajnice SChannela za poslužitelj (jedne za sve veze)
class TlsCredentials {
public:
    explicit TlsCredentials(const std::wstring& name = kServerCertName);  // baca ako certifikata nema
    ~TlsCredentials();
    TlsCredentials(const TlsCredentials&) = delete;
    TlsCredentials& operator=(const TlsCredentials&) = delete;
    void* handle() const { return cred_.get(); }
    const ServerCert& cert() const { return cert_; }

private:
    std::unique_ptr<uint8_t[]> cred_;  // CredHandle
    ServerCert cert_;
};

// Jedna TLS veza na prihvaćenoj utičnici (poslužiteljska strana)
class TlsConnection {
public:
    TlsConnection(uintptr_t socket, const TlsCredentials& creds);
    ~TlsConnection();
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;

    bool handshake();                    // false = klijent nije završio TLS (zapisano u log samo kod neobičnih grešaka)
    int recv(char* out, int size);       // dešifrirani bajtovi; 0 = kraj, <0 = greška
    bool send(const std::string& data);  // šifrira u zapise najveće dopuštene duljine
    void shutdown();                     // close_notify

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sm

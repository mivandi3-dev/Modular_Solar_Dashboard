// Klijent Solarnog poslužitelja (SolarniServer.exe) preko Cloudflare tunela ili lokalne mreže.
// 3.0: korisnik se prijavi e-poštom i lozinkom; sprema se samo oznaka prijave (DPAPI) i šalje kao
// "Authorization: Bearer". Slike (logotip, zaglavlje, crtež) spremaju se u data\images\cloud.
//
// Poslužitelj u lokalnoj mreži ima vlastiti certifikat: klijent pamti njegov otisak (SHA-256) pri prvoj prijavi
// i provjerava ga PRIJE slanja lozinke ili oznake (WinHTTP: SENDING_REQUEST) – drugom poslužitelju ništa ne šalje.
// Javne adrese (Cloudflare) provjeravaju se uobičajeno, preko izdavača certifikata.
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "config.hpp"
#include "layout.hpp"

namespace sm {

class CloudError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Lozinka je točna, ali račun ima dvofaktorsku prijavu: treba kod (step "code") ili postavljanje (step "setup",
// s tajnom i adresom otpauth:// za QR kod). Prijava se ponavlja s istom lozinkom i kodom.
class CloudTotpNeeded : public CloudError {
public:
    CloudTotpNeeded(const std::string& message, json info) : CloudError(message), info_(std::move(info)) {}
    const json& info() const { return info_; }

private:
    json info_;
};

// Lozinka je početna (12345678): treba poslati novu (new_password) – prijava se ponavlja s njom
class CloudPasswordChange : public CloudError {
    using CloudError::CloudError;
};

struct HttpResult {
    int status = 0;
    std::string body, content_type;
    std::string cert_fingerprint;  // otisak certifikata poslužitelja (samo HTTPS u lokalnoj mreži)
};

struct HttpCall {
    std::string method = "GET", path, token, body;
    std::string pin;  // očekivani otisak ("" = prihvati i zapiši – samo za /ping bez tajni)
    int timeout_ms = 15'000;
};

bool pinned_host(const std::string& base_url);  // https na IP adresu, localhost, ime bez točke, .local/.lan/.home
HttpResult http_call(const std::string& base_url, const HttpCall& call);  // baca CloudError s porukom za korisnika

struct CloudLogin {
    std::string token, pin;
    json account;                             // {"email","name","role"}
    std::vector<std::string> recovery_codes;  // samo odmah nakon postavljanja dvofaktorske prijave
};
// Prijava: /ping (otisak), zatim /login samo poslužitelju s istim otiskom. known_pin: otisak od prije (ista adresa).
CloudLogin cloud_login(const std::string& base_url, const std::string& email, std::string password, const std::string& known_pin,
                       const std::string& totp = {}, std::string new_password = {});
void cloud_logout(const Settings& s);  // poništava oznaku na poslužitelju (ne baca)

// JSON s poslužitelja prema postavkama klijenta (cloud_url, cloud_token_enc, cloud_cert_pin)
json cloud_json(const Settings& s, const std::string& path);

// Dashboard s poslužitelja: lokalni raspored i prikaz, slike iz predmemorije (https://data.solari/cloud/…).
json cloud_dashboard(const Settings& s, const Catalog& catalog);

}  // namespace sm

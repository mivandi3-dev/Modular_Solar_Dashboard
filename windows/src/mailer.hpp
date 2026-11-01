// Slanje e-pošte preko servisa Resend (4.0): REST API https://api.resend.com, poziv kroz curl.exe.
//   * jednokratni aktivacijski kod novog korisnika – pošiljatelj registration@solardashboard.bid, predložak na engleskom
//   * obavijesti i greške elektrane – pošiljatelj modular@solardashboard.bid, predložak na jeziku iz postavki
// API ključ: Postavke → Obavijesti, šifriran DPAPI-jem računala (secrets\secrets.json), nikad u naredbenom retku ni u
// zapisniku – ide u privremenu curl -K datoteku (samo vlasnik), koja se briše odmah nakon poziva.
#pragma once

#include <string>
#include <vector>

#include "config.hpp"
#include "util.hpp"

namespace sm {

inline constexpr const char* kResendEmailsUrl = "https://api.resend.com/emails";
inline constexpr const char* kResendBatchUrl = "https://api.resend.com/emails/batch";
inline constexpr const char* kMailFromRegistration = "Solar Dashboard <registration@solardashboard.bid>";
inline constexpr const char* kMailFromAlerts = "Solar Dashboard <modular@solardashboard.bid>";
inline constexpr size_t kResendBatchMax = 100;  // ograničenje servisa po zahtjevu

struct MailContent {
    std::string subject, html, text;
};

// API ključ servisa: "re_" + [A-Za-z0-9_-], 10–200 znakova (ne može ubaciti curl opciju ni zaglavlje)
bool valid_resend_key(const std::string& key);

std::string html_escape(const std::string& s);

// Predložak jednokratnog aktivacijskog koda (uvijek na engleskom; kod velikim slovima u sredini poruke)
MailContent activation_mail(const std::string& code, const std::string& first_name, const std::string& email,
                            const std::string& plant_name, std::time_t valid_until);
// Predložak koda za zaboravljenu lozinku (engleski; kod velik u sredini, rok 30 min)
MailContent password_reset_mail(const std::string& code, const std::string& first_name, const std::string& email,
                                const std::string& plant_name, std::time_t valid_until);
// Potvrda da je lozinka promijenjena (engleski, bez koda) – audit C-09
MailContent password_changed_mail(const std::string& first_name, const std::string& email, const std::string& plant_name, std::time_t when);
// Predložak obavijesti/greške na trenutnom jeziku (set_language): naslov, tekst poruke, podnožje
MailContent alert_mail(const std::string& subject, const std::string& body, const std::string& plant_name);

// Tijelo zahtjeva: jedna poruka (više primatelja u "to") ili skup poruka (svaki primatelj zasebno, ne vide jedni druge)
json resend_message(const std::string& from, const std::vector<std::string>& to, const MailContent& m);
json resend_batch(const std::string& from, const std::vector<std::string>& recipients, const MailContent& m);
// curl -K konfiguracija (URL, zaglavlja s ključem, tijelo iz datoteke, odgovor u datoteku)
std::string resend_curl_config(const std::string& url, const std::string& api_key, const std::string& idempotency_key,
                               const std::wstring& body_file, const std::wstring& response_file);
// Poruka greške iz odgovora servisa ({"statusCode":422,"message":"…"}) – za korisnika
std::string resend_error_text(int http_status, const std::string& response);

// Pošalji (baca MailError). batch = true → svaki primatelj dobiva zasebnu poruku.
void resend_send(const Settings& s, const std::string& api_key, const std::string& from,
                 const std::vector<std::string>& recipients, const MailContent& m, bool batch);

// Ključ iz postavki (DPAPI); "" ako nije postavljen ili se ne može dešifrirati
std::string resend_key(const Settings& s);
// Pošalji jednokratni kod novom korisniku (ili novi kod postojećem). Vraća poruku za administratora; baca MailError.
std::string send_activation_mail(const Settings& s, const std::string& email, const std::string& first_name,
                                 const std::string& code, std::time_t valid_until);
void send_password_changed_mail(const Settings& s, const std::string& email, const std::string& first_name);
// Kod za zaboravljenu lozinku (pošiljatelj registration@…); baca MailError
void send_password_reset_mail(const Settings& s, const std::string& email, const std::string& first_name, const std::string& code,
                              std::time_t valid_until);

}  // namespace sm

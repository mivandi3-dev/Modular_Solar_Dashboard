// Slanje e-pošte preko servisa Resend (src/mailer.cpp): ključ, curl konfiguracija, predlošci, primatelji – bez mreže.
#include <doctest/doctest.h>

#include <cstdlib>

#include "alerts.hpp"
#include "config.hpp"
#include "i18n.hpp"
#include "crypto.hpp"
#include "mailer.hpp"
#include "secret.hpp"
#include "users.hpp"
#include "util.hpp"

using namespace sm;

TEST_CASE("Resend: ključ samo u očekivanom obliku (ne može ubaciti curl opciju ni zaglavlje)") {
    CHECK(valid_resend_key("re_123456789_abcDEF-xyz"));
    for (const std::string& bad : std::vector<std::string>{"", "re_", "re_short", "sk_1234567890ab", "re_123456789\nheader = x", "re_123456789 abc",
                                  "re_1234567890\"", "re_1234567890\\x", std::string("re_") + std::string(300, 'a')}) {
        CAPTURE(bad);
        CHECK_FALSE(valid_resend_key(bad));
    }
}

TEST_CASE("Resend: curl konfiguracija – ključ u zaglavlju, tijelo i odgovor u datotekama") {
    const std::string cfg = resend_curl_config(kResendEmailsUrl, "re_ABCDEFGHIJ_123", "abc123", L"C:\\t\\body.json", L"C:\\t\\out.txt");
    CHECK(cfg.find("url = \"https://api.resend.com/emails\"\n") != std::string::npos);
    CHECK(cfg.find("header = \"Authorization: Bearer re_ABCDEFGHIJ_123\"\n") != std::string::npos);
    CHECK(cfg.find("header = \"Idempotency-Key: abc123\"\n") != std::string::npos);
    CHECK(cfg.find("data-binary = \"@C:\\\\t\\\\body.json\"\n") != std::string::npos);
    CHECK(cfg.find("output = \"C:\\\\t\\\\out.txt\"\n") != std::string::npos);
    CHECK_THROWS_AS(resend_curl_config(kResendEmailsUrl, "re_ABCDEFGHIJ\nurl = http://evil", "", L"b", L"o"), MailError);
    CHECK_THROWS_AS(resend_curl_config(kResendEmailsUrl, "re_ABCDEFGHIJ", "x\ny", L"b", L"o"), MailError);
}

TEST_CASE("Resend: jednokratni kod – engleski predložak, kod velik u sredini, rok valjanosti, escapiranje") {
    const std::time_t until = 1'800'000'000;  // 15 Jan 2027, 08:00 UTC
    const auto m = activation_mail("ABCD-EFGH-JKLM", "<b>Ana</b>", "ana@example.com", "Elektrana <x>", until);
    CHECK(m.subject == "Your Solar Dashboard registration code");
    CHECK(m.html.find("ABCD-EFGH-JKLM") != std::string::npos);
    CHECK(m.html.find("font-size:40px") != std::string::npos);
    CHECK(m.html.find("align=\"center\"") != std::string::npos);
    CHECK(m.html.find("Please register before the code expires: 15 Jan 2027, 08:00 UTC") != std::string::npos);
    CHECK(m.html.find("<b>Ana</b>") == std::string::npos);
    CHECK(m.html.find("&lt;b&gt;Ana&lt;/b&gt;") != std::string::npos);
    CHECK(m.html.find("Elektrana &lt;x&gt;") != std::string::npos);
    CHECK(m.html.find("lang=\"en\"") != std::string::npos);
    CHECK(m.text.find("ABCD-EFGH-JKLM") != std::string::npos);
    CHECK(m.text.find("15 Jan 2027, 08:00 UTC") != std::string::npos);
}

TEST_CASE("Resend: obavijest na jeziku aplikacije, tekst uređaja se escapira") {
    set_language("en");
    const auto en = alert_mail("Device offline", "Line 1\nLine <2>\n\nNext", "Plant");
    CHECK(en.html.find("lang=\"en\"") != std::string::npos);
    CHECK(en.html.find("Line 1<br>Line &lt;2&gt;</p>") != std::string::npos);
    CHECK(en.html.find("<h1") != std::string::npos);
    set_language("hr");
    const auto hr = alert_mail("Uređaj ne odgovara", "x", "Elektrana");
    CHECK(hr.html.find("lang=\"hr\"") != std::string::npos);
    CHECK(hr.html.find("Ovo je automatska poruka Solarnog monitora (Elektrana)") != std::string::npos);
    CHECK(en.html.find("Ovo je automatska poruka") == std::string::npos);  // podnožje je prevedeno
}

TEST_CASE("Resend: obavijest – svaki primatelj zasebno (ne vide adrese drugih)") {
    const MailContent m{"S", "<p>h</p>", "t"};
    const json b = resend_batch(kMailFromAlerts, {"a@x.hr", "b@y.hr"}, m);
    REQUIRE(b.is_array());
    REQUIRE(b.size() == 2);
    CHECK(b[0]["from"] == "Solar Dashboard <modular@solardashboard.bid>");
    CHECK(b[0]["to"] == json::array({"a@x.hr"}));
    CHECK(b[1]["to"] == json::array({"b@y.hr"}));
    CHECK(b[1]["html"] == "<p>h</p>");
    const json one = resend_message(kMailFromRegistration, {"n@z.hr"}, m);
    CHECK(one["from"] == "Solar Dashboard <registration@solardashboard.bid>");
}

TEST_CASE("Primatelji: adrese iz postavki + korisnici, bez ponavljanja i neispravnih adresa") {
    const auto r = merge_recipients({"Ana@Firma.hr", "odrzavanje@firma.hr"}, {"ana@firma.hr", "nije adresa", " ivo@firma.hr "});
    CHECK(r == std::vector<std::string>{"Ana@Firma.hr", "odrzavanje@firma.hr", "ivo@firma.hr"});
    CHECK(merge_recipients({}, {}).empty());
}

TEST_CASE("Resend: poruke grešaka servisa") {
    set_language("hr");
    CHECK(resend_error_text(401, R"({"statusCode":401,"message":"API key is invalid"})").find("API key is invalid") != std::string::npos);
    CHECK(resend_error_text(422, R"({"message":"The solardashboard.bid domain is not verified."})").find("not verified") != std::string::npos);
    CHECK(resend_error_text(500, "nije json").find("500") != std::string::npos);
}

TEST_CASE("Resend: bez ključa nema slanja (bez mreže), ključ je tajna postavki") {
    Settings s;
    s.mail_provider = "resend";
    s.alert_emails = "ana@firma.hr";
    CHECK_FALSE(mail_configured(s));
    CHECK_THROWS_AS(send_mail(s, "x", "y"), MailError);
    CHECK_THROWS_AS(send_activation_mail(s, "ana@firma.hr", "Ana", "ABCD-EFGH-JKLM", 0), MailError);
    s.resend_api_key_enc = "dpapi:nesto";
    CHECK(mail_configured(s));
    const auto& keys = secret_keys();
    CHECK(std::find(keys.begin(), keys.end(), "resend_api_key_enc") != keys.end());
    CHECK_FALSE(strip_secrets(to_json(s)).contains("resend_api_key_enc"));
    const json form = to_form(s);
    CHECK_FALSE(form.contains("resend_api_key_enc"));
    CHECK(form.value("resend_api_key_set", false));
}

TEST_CASE("Postavke: način slanja – stari zapis sa SMTP poslužiteljem ostaje na SMTP-u") {
    CHECK(settings_from_json(json::object()).mail_provider == "resend");
    CHECK(settings_from_json({{"smtp_host", "smtp.firma.hr"}}).mail_provider == "smtp");
    CHECK(settings_from_json({{"smtp_host", "smtp.firma.hr"}, {"mail_provider", "resend"}}).mail_provider == "resend");
    CHECK(settings_from_json({{"mail_provider", "pigeon"}}).mail_provider == "resend");
}

// Stvarno slanje (ručno): SOLARI_RESEND_KEY_FILE=<datoteka s ključem> SOLARI_RESEND_LIVE_TO=<adresa>
//   solari_tests.exe -tc="Resend LIVE*"   – bez varijabli test ne radi ništa (ključ nikad nije u kodu ni u repozitoriju)
TEST_CASE("Resend LIVE: jednokratni kod i obavijest (samo uz varijable okruženja)") {
    const char* to = std::getenv("SOLARI_RESEND_LIVE_TO");
    const char* key_file = std::getenv("SOLARI_RESEND_KEY_FILE");
    if (!to || !*to || !key_file || !*key_file) {
        MESSAGE("preskočeno: SOLARI_RESEND_LIVE_TO / SOLARI_RESEND_KEY_FILE nisu postavljeni");
        return;
    }
    std::string key = trim(read_file(fs::path(widen(key_file))).value_or(std::string{}));
    if (key.rfind("\xEF\xBB\xBF", 0) == 0) key = key.substr(3);
    REQUIRE(valid_resend_key(key));
    Settings s;
    s.plant_name = "Solarna elektrana (test)";
    s.mail_provider = "resend";
    s.alert_emails = to;
    s.resend_api_key_enc = protect_secret(key);
    wipe(key);
    set_mail_extra_recipients(nullptr);
    std::string msg;
    CHECK_NOTHROW(msg = send_activation_mail(s, to, "Test", "ABCD-EFGH-JKLM", now() + kActivationSeconds));
    MESSAGE(msg);
    for (const char* lang : {"hr", "en"}) {
        set_language(lang);
        const auto m = test_message(s, now());
        CHECK_NOTHROW(send_mail(s, m.subject, m.body));
    }
    set_language("hr");
}

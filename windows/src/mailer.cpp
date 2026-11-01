#include "mailer.hpp"

#include <windows.h>

#include <cstdio>

#include "alerts.hpp"
#include "crypto.hpp"
#include "i18n.hpp"
#include "net.hpp"
#include "secret.hpp"
#include "system.hpp"

namespace sm {

namespace {

constexpr unsigned kResendTimeoutMs = 40'000;
constexpr int kResendMaxTimeS = 30;
constexpr size_t kResendKeyMin = 10, kResendKeyMax = 200;

std::string mail_utc_text(std::time_t t) {
    std::tm gm{};
    gmtime_s(&gm, &t);
    char buf[64];
    std::strftime(buf, sizeof buf, "%d %b %Y, %H:%M UTC", &gm);
    return buf;
}

std::string local_text(std::time_t t) {
    const std::tm tm = local_tm(t);
    char buf[64];
    std::strftime(buf, sizeof buf, "%d.%m.%Y. %H:%M", &tm);
    return buf;
}

// Zajednički okvir HTML poruke (tablice i stilovi u retku – ispravno se prikazuje u Outlooku, Gmailu i na mobitelu)
std::string frame(const std::string& lang, const std::string& preheader, const std::string& inner, const std::string& footer) {
    return "<!DOCTYPE html><html lang=\"" + html_escape(lang) + "\"><head><meta charset=\"utf-8\">"
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\">"
           "<title>Solar Dashboard</title></head>"
           "<body style=\"margin:0;padding:0;background:#0b1020;font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#0f172a\">"
           "<div style=\"display:none;max-height:0;overflow:hidden;opacity:0\">" + html_escape(preheader) + "</div>"
           "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"background:#0b1020;padding:32px 12px\"><tr><td align=\"center\">"
           "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"max-width:560px;background:#ffffff;border-radius:18px;overflow:hidden\">"
           "<tr><td style=\"background:linear-gradient(135deg,#0ea5e9,#1d4ed8);background-color:#1d4ed8;padding:22px 28px;color:#ffffff;"
           "font-size:20px;font-weight:700;letter-spacing:.3px\">&#9728;&#65039; Solar Dashboard</td></tr>"
           "<tr><td style=\"padding:28px 28px 8px 28px;font-size:15px;line-height:1.6\">" + inner + "</td></tr>"
           "<tr><td style=\"padding:8px 28px 26px 28px;font-size:12px;line-height:1.5;color:#64748b\">" + footer + "</td></tr>"
           "</table></td></tr></table></body></html>";
}

std::string paragraphs(const std::string& text) {  // prazni red = novi odlomak, novi red = <br>
    std::string out = "<p style=\"margin:0 0 14px 0\">";
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n' && i + 1 < text.size() && text[i + 1] == '\n') {
            out += "</p><p style=\"margin:0 0 14px 0\">";
            while (i + 1 < text.size() && text[i + 1] == '\n') ++i;
        } else if (text[i] == '\n') {
            out += "<br>";
        } else {
            out += html_escape(std::string(1, text[i]));
        }
    }
    return out + "</p>";
}

}  // namespace

bool valid_resend_key(const std::string& key) {
    if (key.size() < kResendKeyMin || key.size() > kResendKeyMax || key.rfind("re_", 0) != 0) return false;
    for (char c : key) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') return false;
    }
    return true;
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

MailContent activation_mail(const std::string& code, const std::string& first_name, const std::string& email,
                            const std::string& plant_name, std::time_t valid_until) {
    const std::string hello = first_name.empty() ? "Hello," : "Hello " + first_name + ",";
    const std::string plant = plant_name.empty() ? "Solar Dashboard" : plant_name;
    const std::string until = mail_utc_text(valid_until);
    MailContent m;
    m.subject = "Your Solar Dashboard registration code";
    const std::string inner =
        "<p style=\"margin:0 0 14px 0\">" + html_escape(hello) + "</p>"
        "<p style=\"margin:0 0 14px 0\">An account has been created for you on <b>" + html_escape(plant) + "</b>. "
        "To complete your registration, sign in with your email address and the one-time code below:</p>"
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin:22px 0\"><tr><td align=\"center\" "
        "style=\"background:#eff6ff;border:2px solid #1d4ed8;border-radius:14px;padding:26px 12px\">"
        "<div style=\"font-size:13px;letter-spacing:2px;text-transform:uppercase;color:#1d4ed8;margin-bottom:10px\">One-time code</div>"
        "<div style=\"font-family:Consolas,Menlo,monospace;font-size:40px;line-height:1.15;font-weight:700;letter-spacing:6px;color:#0f172a\">" +
        html_escape(code) + "</div></td></tr></table>"
        "<p style=\"margin:0 0 14px 0;text-align:center;font-size:16px\"><b>Please register before the code expires: " + html_escape(until) +
        "</b><br><span style=\"color:#64748b;font-size:13px\">The code is valid for 72 hours and can be used only once.</span></p>"
        "<p style=\"margin:0 0 14px 0\"><b>How to register</b><br>1. Open the Solar Dashboard app.<br>"
        "2. Sign in with <b>" + html_escape(email) + "</b> and enter the code as your password.<br>"
        "3. Choose your own password – from then on you sign in with it.</p>"
        "<p style=\"margin:0 0 14px 0\">If the code has expired, ask your administrator to send you a new one.</p>";
    m.html = frame("en", "Your one-time registration code: " + code, inner,
                   "If you did not expect this email, you can safely ignore it – without the code nobody can complete the registration."
                   " Never share this code with anyone.<br>Sent by Solar Dashboard &middot; registration@solardashboard.bid");
    m.text = hello + "\n\nAn account has been created for you on " + plant +
             ". To complete your registration, sign in with your email address and this one-time code:\n\n    " + code +
             "\n\nPlease register before the code expires: " + until +
             " (valid for 72 hours, can be used only once).\n\nHow to register:\n1. Open the Solar Dashboard app.\n2. Sign in with " + email +
             " and enter the code as your password.\n3. Choose your own password.\n\nIf the code has expired, ask your administrator to send "
             "you a new one. If you did not expect this email, ignore it.\n";
    return m;
}

MailContent password_reset_mail(const std::string& code, const std::string& first_name, const std::string& email,
                                const std::string& plant_name, std::time_t valid_until) {
    const std::string hello = first_name.empty() ? "Hello," : "Hello " + first_name + ",";
    const std::string plant = plant_name.empty() ? "Solar Dashboard" : plant_name;
    const std::string until = mail_utc_text(valid_until);
    MailContent m;
    m.subject = "Your Solar Dashboard password reset code";
    const std::string inner =
        "<p style=\"margin:0 0 14px 0\">" + html_escape(hello) + "</p>"
        "<p style=\"margin:0 0 14px 0\">We received a request to reset the password of your account <b>" + html_escape(email) +
        "</b> on <b>" + html_escape(plant) + "</b>. Enter this one-time code in the app to choose a new password:</p>"
        "<table role=\"presentation\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin:22px 0\"><tr><td align=\"center\" "
        "style=\"background:#fff7ed;border:2px solid #ea580c;border-radius:14px;padding:26px 12px\">"
        "<div style=\"font-size:13px;letter-spacing:2px;text-transform:uppercase;color:#c2410c;margin-bottom:10px\">Password reset code</div>"
        "<div style=\"font-family:Consolas,Menlo,monospace;font-size:40px;line-height:1.15;font-weight:700;letter-spacing:6px;color:#0f172a\">" +
        html_escape(code) + "</div></td></tr></table>"
        "<p style=\"margin:0 0 14px 0;text-align:center;font-size:16px\"><b>Use the code before it expires: " + html_escape(until) +
        "</b><br><span style=\"color:#64748b;font-size:13px\">The code is valid for 30 minutes and can be used only once.</span></p>"
        "<p style=\"margin:0 0 14px 0\"><b>How to reset your password</b><br>1. In the Solar Dashboard app, open the sign-in screen and choose "
        "<i>Forgot password</i>.<br>2. Enter your email address, this code and your new password.<br>"
        "3. Sign in with the new password – all previous sign-ins are signed out.</p>"
        "<p style=\"margin:0 0 14px 0\">If you did not request this, ignore this email: your current password stays unchanged.</p>";
    m.html = frame("en", "Your password reset code: " + code, inner,
                   "Never share this code with anyone. Solar Dashboard staff will never ask you for it."
                   "<br>Sent by Solar Dashboard &middot; registration@solardashboard.bid");
    m.text = hello + "\n\nWe received a request to reset the password of your account " + email + " on " + plant +
             ". Enter this one-time code in the app to choose a new password:\n\n    " + code +
             "\n\nUse the code before it expires: " + until + " (valid for 30 minutes, can be used only once).\n\n"
             "In the Solar Dashboard app choose Forgot password, enter your email address, this code and your new password.\n\n"
             "If you did not request this, ignore this email: your current password stays unchanged.\n";
    return m;
}

MailContent password_changed_mail(const std::string& first_name, const std::string& email, const std::string& plant_name, std::time_t when) {
    const std::string hello = first_name.empty() ? "Hello," : "Hello " + first_name + ",";
    const std::string plant = plant_name.empty() ? "Solar Dashboard" : plant_name;
    MailContent m;
    m.subject = "Your Solar Dashboard password was changed";
    const std::string inner =
        "<p style=\"margin:0 0 14px 0\">" + html_escape(hello) + "</p>"
        "<p style=\"margin:0 0 14px 0\">The password of your account <b>" + html_escape(email) + "</b> on <b>" + html_escape(plant) +
        "</b> was changed with a one-time code on " + html_escape(mail_utc_text(when)) + ". All devices were signed out.</p>"
        "<p style=\"margin:0 0 14px 0\"><b>If this was not you,</b> request a new code with <i>Forgot password</i> right away and "
        "contact your administrator – someone may have access to your email.</p>";
    m.html = frame("en", "Your password was changed", inner, "Sent by Solar Dashboard &middot; registration@solardashboard.bid");
    m.text = hello + "\n\nThe password of your account " + email + " on " + plant + " was changed with a one-time code on " +
             mail_utc_text(when) + ". All devices were signed out.\n\nIf this was not you, request a new code with Forgot password "
             "right away and contact your administrator.\n";
    return m;
}

MailContent alert_mail(const std::string& subject, const std::string& body, const std::string& plant_name) {
    MailContent m;
    m.subject = subject;
    const std::string inner = "<h1 style=\"margin:0 0 16px 0;font-size:19px;line-height:1.35;color:#0f172a\">" + html_escape(subject) + "</h1>" +
                              paragraphs(body);
    const std::string footer =
        html_escape(tr("Ovo je automatska poruka Solarnog monitora ({plant}). Primatelje obavijesti mijenjate u Postavke → Obavijesti.",
                       {{"plant", plant_name}})) +
        "<br>Solar Dashboard &middot; modular@solardashboard.bid";
    m.html = frame(language(), subject, inner, footer);
    m.text = body + "\n\n— " + tr("Ovo je automatska poruka Solarnog monitora ({plant}). Primatelje obavijesti mijenjate u Postavke → Obavijesti.",
                                   {{"plant", plant_name}}) + "\n";
    return m;
}

json resend_message(const std::string& from, const std::vector<std::string>& to, const MailContent& m) {
    return {{"from", from}, {"to", to}, {"subject", m.subject}, {"html", m.html}, {"text", m.text}};
}

json resend_batch(const std::string& from, const std::vector<std::string>& recipients, const MailContent& m) {
    json batch = json::array();
    for (const auto& r : recipients) batch.push_back(resend_message(from, {r}, m));
    return batch;
}

std::string resend_curl_config(const std::string& url, const std::string& api_key, const std::string& idempotency_key,
                               const std::wstring& body_file, const std::wstring& response_file) {
    if (!valid_resend_key(api_key)) throw MailError(tr("API ključ servisa Resend nije ispravan (počinje s re_)."));
    std::string c = "url = " + curl_config_value(url) + "\n";
    c += "request = \"POST\"\n";
    c += "header = " + curl_config_value("Authorization: Bearer " + api_key) + "\n";
    c += "header = \"Content-Type: application/json\"\n";
    if (!idempotency_key.empty()) c += "header = " + curl_config_value("Idempotency-Key: " + idempotency_key) + "\n";
    c += "data-binary = " + curl_config_value("@" + narrow(body_file)) + "\n";
    c += "output = " + curl_config_value(narrow(response_file)) + "\n";
    c += "write-out = \"%{http_code}\"\n";
    return c;
}

std::string resend_error_text(int http_status, const std::string& response) {
    const json j = json::parse(response, nullptr, false);
    std::string detail = j.is_object() ? j.value("message", std::string{}) : std::string{};
    if (detail.size() > 300) detail = detail.substr(0, 300);
    switch (http_status) {
    case 401: case 403: return tr("Resend je odbio API ključ ({error}).", {{"error", detail}});
    case 422: return tr("Resend nije prihvatio poruku: {error}", {{"error", detail}});
    case 429: return tr("Resend: previše poruka u kratkom vremenu, pokušajte ponovno za minutu.");
    default: return tr("Resend je javio grešku {status}: {error}", {{"status", std::to_string(http_status)}, {"error", detail}});
    }
}

void resend_send(const Settings& s, const std::string& api_key, const std::string& from,
                 const std::vector<std::string>& recipients, const MailContent& m, bool batch) {
    if (recipients.empty()) throw MailError(tr("Nema adrese primatelja."));
    if (batch && recipients.size() > kResendBatchMax) throw MailError(tr("Previše primatelja."));
    const json body = batch ? resend_batch(from, recipients, m) : resend_message(from, recipients, m);
    Bytes raw = random_bytes(16);
    const std::string idem = to_hex(raw);
    wipe(raw);

    TempFiles files;
    const fs::path body_file = temp_file(L".json"), cfg = temp_file(L".cfg"), out = temp_file(L".out");
    files.paths = {body_file, cfg, out};
    write_private_file(body_file, body.dump());
    write_private_file(out, "");  // odgovor curla ide u vlastitu datoteku (CREATE_NEW, privatni DACL) – audit C-05
    // ključ samo u -K datoteci (vlasnik, SYSTEM, administratori), ne u naredbenom retku koji vide drugi procesi
    write_private_file(cfg, resend_curl_config(batch ? kResendBatchUrl : kResendEmailsUrl, api_key, idem, body_file.wstring(), out.wstring()));

    std::wstring cmd = curl_command() + L" --silent --show-error --proto =https --tlsv1.2 --max-time " + std::to_wstring(kResendMaxTimeS) + L" ";
    if (const auto ip = source_ip(s.internet_interface)) cmd += L"--interface " + widen(*ip) + L" ";
    cmd += L"-K \"" + cfg.wstring() + L"\"";
    const ProcessResult r = run_capture(cmd, kResendTimeoutMs);
    switch (r.exit_code) {
    case 0: break;
    case 6: case 7: throw MailError(tr("Nije moguće spojiti se na api.resend.com ({error}).", {{"error", trim(r.output)}}));
    case 28: throw MailError(tr("Servis Resend ne odgovara."));
    case -1: throw MailError(tr("curl.exe nije dostupan ili nije odgovorio"));
    default: throw MailError(tr("Slanje preko servisa Resend nije uspjelo: {error}", {{"error", trim(r.output)}}));
    }
    const int status = std::atoi(trim(r.output).c_str());
    const std::string response = read_file(out).value_or(std::string{});
    if (status < 200 || status >= 300) throw MailError(resend_error_text(status, response));
    log_info("E-pošta „" + m.subject + "“ poslana preko servisa Resend (" + std::to_string(recipients.size()) + " primatelja)");
}

std::string resend_key(const Settings& s) { return unprotect_secret(s.resend_api_key_enc); }

std::string send_activation_mail(const Settings& s, const std::string& email, const std::string& first_name,
                                 const std::string& code, std::time_t valid_until) {
    std::string key = resend_key(s);
    if (key.empty()) throw MailError(tr("Slanje e-pošte nije podešeno (Postavke → Obavijesti → API ključ servisa Resend)."));
    NetInit net;
    try {
        resend_send(s, key, kMailFromRegistration, {email}, activation_mail(code, first_name, email, s.plant_name, valid_until), false);
    } catch (...) {
        wipe(key);
        throw;
    }
    wipe(key);
    return tr("Jednokratni kod poslan je na {email} (vrijedi do {time}).", {{"email", email}, {"time", local_text(valid_until)}});
}

void send_password_changed_mail(const Settings& s, const std::string& email, const std::string& first_name) {
    std::string key = resend_key(s);
    if (key.empty()) throw MailError(tr("Slanje e-pošte nije podešeno (Postavke → Obavijesti → API ključ servisa Resend)."));
    NetInit net;
    try {
        resend_send(s, key, kMailFromRegistration, {email}, password_changed_mail(first_name, email, s.plant_name, now()), false);
    } catch (...) {
        wipe(key);
        throw;
    }
    wipe(key);
}

void send_password_reset_mail(const Settings& s, const std::string& email, const std::string& first_name, const std::string& code,
                              std::time_t valid_until) {
    std::string key = resend_key(s);
    if (key.empty()) throw MailError(tr("Slanje e-pošte nije podešeno (Postavke → Obavijesti → API ključ servisa Resend)."));
    NetInit net;
    try {
        resend_send(s, key, kMailFromRegistration, {email}, password_reset_mail(code, first_name, email, s.plant_name, valid_until), false);
    } catch (...) {
        wipe(key);
        throw;
    }
    wipe(key);
}

}  // namespace sm

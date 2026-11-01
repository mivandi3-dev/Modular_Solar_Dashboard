#include "webguard.hpp"

#include <algorithm>
#include <cwctype>
#include <set>

namespace sm {

namespace {

std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
}

bool starts_with(const std::wstring& s, const std::wstring& prefix) { return s.rfind(prefix, 0) == 0; }

}  // namespace

bool trusted_app_url(const std::wstring& url) {
    const std::wstring u = lower(url);
    // točno host (ne https://app.solari.zlo.hr/): iza imena mora doći '/'. 4.0 (NEW-05): data.solari (mapa ui\images,
    // u koju smiju pisati svi korisnici) nije pouzdan izvor stranica ni poruka mostu – samo slike
    return starts_with(u, L"https://app.solari/");
}

bool image_host_url(const std::wstring& url) { return starts_with(lower(url), L"https://data.solari/"); }

bool allowed_navigation(const std::wstring& url) { return trusted_app_url(url) || lower(url) == L"about:blank"; }

bool external_browser_url(const std::wstring& url) {
    const std::wstring u = lower(url);
    return starts_with(u, L"https://") && !trusted_app_url(url) && !image_host_url(url) && u.find_first_of(L" \"\r\n\t") == std::wstring::npos;
}

bool allowed_app_resource(const std::wstring& url) {
    const std::wstring u = lower(url);
    const bool data = image_host_url(url);
    if (!starts_with(u, L"https://app.solari/") && !data) return true;  // ostali hostovi nisu predmet ovog filtra
    if (u.find(L"..") != std::wstring::npos || u.find(L"%2e") != std::wstring::npos || u.find(L"%5c") != std::wstring::npos ||
        u.find(L'\\') != std::wstring::npos) {
        return false;
    }
    if (data) {  // NEW-05: iz ui\images samo slike (bez HTML-a, SVG-a, skripti)
        const std::wstring path = u.substr(0, u.find_first_of(L"?#"));
        for (const std::wstring ext : {L".jpg", L".jpeg", L".png", L".webp"}) {
            if (path.size() > ext.size() && path.compare(path.size() - ext.size(), ext.size(), ext) == 0) return true;
        }
        return false;
    }
    return starts_with(u, L"https://app.solari/web/") || starts_with(u, L"https://app.solari/assets/");
}

bool settings_only_method(const std::string& method) {
    static const std::set<std::string> kSettingsOnly = {
        "get_state",       "unlock",           "admin_login",     "setup_admin",       "admin_logout",
        "interfaces",      "test_logger",      "test_internet",   "serial_ports",      "geocode",
        "save",            "test_email",       "cloud_login",     "cloud_logout",      "users_list",
        "cloud_forgot_password", "cloud_reset_password", "admin_forgot_password", "admin_reset_password",
        "user_save",       "user_set_disabled", "user_delete",    "user_reset_totp",   "user_reset_password", "user_logout_all",
        "get_report",      "save_report_csv",  "import_history",  "import_smartlogger", "choose_image",
        "reset_image",     "open_folder",      "close",           "remote_view_new_key"};
    return kSettingsOnly.count(method) > 0;
}

bool main_window_method(const std::string& method) {
    static const std::set<std::string> kMain = {
        "get_dashboard", "get_editor",  "save_layout",  "remove_page", "set_rotation",      "reset_layout",
        "set_display",   "set_sidebar", "toggle_fullscreen", "exit_fullscreen", "open_settings", "reload",
        "quit",          "open_logs",   "window_control", "window_state", "get_i18n"};
    return kMain.count(method) > 0;
}

}  // namespace sm

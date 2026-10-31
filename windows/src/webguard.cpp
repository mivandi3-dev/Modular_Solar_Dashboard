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
    // točno host (ne https://app.solari.zlo.hr/): iza imena mora doći '/'
    return starts_with(u, L"https://app.solari/") || starts_with(u, L"https://data.solari/");
}

bool allowed_navigation(const std::wstring& url) { return trusted_app_url(url) || lower(url) == L"about:blank"; }

bool external_browser_url(const std::wstring& url) {
    const std::wstring u = lower(url);
    return starts_with(u, L"https://") && !trusted_app_url(url) && u.find_first_of(L" \"\r\n\t") == std::wstring::npos;
}

bool settings_only_method(const std::string& method) {
    static const std::set<std::string> kSettingsOnly = {
        "get_state",       "unlock",           "admin_login",     "setup_admin",       "admin_logout",
        "interfaces",      "test_logger",      "test_internet",   "serial_ports",      "geocode",
        "save",            "test_email",       "cloud_login",     "cloud_logout",      "users_list",
        "user_save",       "user_set_disabled", "user_delete",    "user_reset_totp",   "user_reset_password", "user_logout_all",
        "get_report",      "save_report_csv",  "import_history",  "import_smartlogger", "choose_image",
        "reset_image",     "open_folder",      "close"};
    return kSettingsOnly.count(method) > 0;
}

}  // namespace sm

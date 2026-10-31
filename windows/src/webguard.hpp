// Zaštita stranica u WebView2 (4.0, SMA-05/06): koje adrese smiju biti učitane i slati poruke nativnom mostu
// te koje metode mosta smije pozvati samo prozor postavki.
#pragma once

#include <string>

namespace sm {

// https://app.solari/… ili https://data.solari/… (virtualni hostovi aplikacije); sve ostalo nije pouzdano
bool trusted_app_url(const std::wstring& url);
// Može li adresa biti učitana u WebView (pouzdano + about:blank)
bool allowed_navigation(const std::wstring& url);
// Vanjska poveznica koja se smije otvoriti u pregledniku sustava (samo https://)
bool external_browser_url(const std::wstring& url);
// Metode koje smije pozvati samo prozor postavki (PIN / prijava administratora), nikad dashboard
bool settings_only_method(const std::string& method);

}  // namespace sm

// Zaštita stranica u WebView2 (4.0, SMA-05/06): koje adrese smiju biti učitane i slati poruke nativnom mostu
// te koje metode mosta smije pozvati samo prozor postavki.
#pragma once

#include <string>

namespace sm {

// https://app.solari/… (mapa programa); sve ostalo nije pouzdano – ni https://data.solari/ (ui\images, NEW-05)
bool trusted_app_url(const std::wstring& url);
// https://data.solari/… – slike iz ui\images (samo .jpg/.jpeg/.png/.webp, nikad stranice ni poruke mostu)
bool image_host_url(const std::wstring& url);
// Može li adresa biti učitana u WebView (pouzdano + about:blank)
bool allowed_navigation(const std::wstring& url);
// Vanjska poveznica koja se smije otvoriti u pregledniku sustava (samo https://)
bool external_browser_url(const std::wstring& url);
// Zahtjev prema https://app.solari/: dopušteno samo /web/ i /assets/ (ne izvršne datoteke iz mape programa);
// prema https://data.solari/: samo slike
bool allowed_app_resource(const std::wstring& url);
// Metode koje smije pozvati samo prozor postavki (PIN / prijava administratora), nikad dashboard
bool settings_only_method(const std::string& method);
// Metode glavnog prozora (dashboard, uređivač, prozor) – dopuštene i prozoru postavki; svaka metoda mosta je u točno jednom skupu
bool main_window_method(const std::string& method);

}  // namespace sm

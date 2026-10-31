// Aplikacija: glavni prozor s dashboardom, prozor postavki (i čarobnjak), poller u pozadini.
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "config.hpp"
#include "data.hpp"
#include "layout.hpp"
#include "poller.hpp"
#include "remote.hpp"
#include "system.hpp"
#include "users.hpp"
#include "weather.hpp"
#include "webview.hpp"

namespace sm {

enum class WindowKind { Main, Settings };

class App {
public:
    int run();

    // ------------------------------------------------ stanje (smije iz bilo koje niti)
    Settings settings() const;
    const Catalog& catalog() const { return catalog_; }
    DataService& data() { return data_; }
    WeatherService& weather() { return weather_; }
    bool fullscreen() const { return fullscreen_; }
    bool sidebar_open() const { return sidebar_open_; }
    bool wizard() const { return wizard_; }
    std::string settings_panel() const { return settings_panel_; }

    // Solarni poslužitelj 3.0: korisnici (src/users.cpp). Prozor poslužitelja otvara samo prijavljeni administrator
    // (prijava vrijedi dok je prozor otvoren); dok nema nijednog administratora, prozor nudi samo njegovu izradu.
    UserStore& users();  // baca ako se ključ korisnika (data/users.key) ne može otvoriti
    std::optional<UserInfo> admin() const;
    json admin_login(const std::string& email, std::string password, const std::string& totp = {},
                     std::string new_password = {});
    json setup_admin(const UserInput& in);
    void admin_logout();

    // PIN za postavke (vrijedi dok je prozor postavki otvoren)
    bool settings_unlocked() const { return settings_unlocked_; }
    json unlock(const std::string& pin);

    // ------------------------------------------------ samo u GUI niti
    void toggle_fullscreen();
    void set_sidebar(bool open);
    void open_settings(const std::string& panel = {});
    void close_settings();
    void quit();
    void reload_dashboard();
    void apply_settings(const Settings& s);  // spremi i primijeni (u čarobnjaku otvara dashboard)
    void update_settings(const std::function<void(Settings&)>& change);  // samo izmjena i spremanje (prijava na poslužitelj)
    void set_display(bool on);               // noćni način (web/overlay.js): ugasi ili upali zaslon
    // prozor bez okvira (web/window.js): minimize | maximize | close | drag; stanje za kružiće
    void window_control(WindowKind kind, const std::string& action);
    json window_state(WindowKind kind) const;
    int remote_port() const { return remote_ ? remote_->port() : 0; }
    // Solarni poslužitelj (SolarniServer.exe): samo prozor postavki; bilježenje i API rade i bez njega (--service)
    void set_server_role(bool on) { server_role_ = on; }
    bool server_role() const { return server_role_; }
    int api_port() const { return api_ ? api_->port() : 0; }  // API u ovom procesu (kad zadatak sustava ne radi)
    void* settings_hwnd() const;

    // ------------------------------------------------ niti i poruke
    void reply(WindowKind kind, const json& message);  // iz bilo koje niti
    void run_async(std::function<void()> work);         // radna nit (COM inicijaliziran)
    void post_ui(std::function<void()> work);           // izvrši u GUI niti

private:
    void create_main();
    void apply_zoom();
    void on_message(WindowKind kind, const std::string& message);
    void tick();  // svake minute: dnevno osvježavanje stranice
    void update_remote();  // pregled iz mreže prema postavkama
    void update_api();     // poslužitelj: API u ovom procesu ako ga ne vodi zadatak sustava

    mutable std::mutex mutex_;
    Settings settings_;
    Catalog catalog_;
    DataService data_{db_file()};
    WeatherService weather_;
    Poller poller_;
    std::unique_ptr<HttpServer> remote_, api_;
    std::unique_ptr<NamedMutex> service_lock_;
    std::mutex users_mutex_;
    std::unique_ptr<UserStore> users_;
    std::optional<UserInfo> admin_;  // pod mutex_
    std::string admin_token_;
    bool display_on_ = true;
    bool server_role_ = false;
    std::unique_ptr<WebViewWindow> main_, settings_window_;
    std::atomic<bool> fullscreen_{false}, sidebar_open_{true}, wizard_{false}, settings_unlocked_{false};
    std::string settings_panel_;
    int pin_failures_ = 0;
    std::time_t pin_locked_until_ = 0;
    std::atomic<int> workers_{0};
    DWORD ui_thread_ = 0;
    int reloaded_day_ = -1;
};

App& app();  // jedina instanca (main.cpp)

// bridge.cpp: obrada poziva iz JS-a ({id, method, args}) – odgovor ide kao {id, ok, result | error}
void dispatch(App& app, WindowKind kind, const json& call);
json dashboard_json(App& app);  // podaci za dashboard (aplikacija i pregled iz mreže)

}  // namespace sm

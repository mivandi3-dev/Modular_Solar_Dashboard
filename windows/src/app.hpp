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
    // spremi i primijeni (u čarobnjaku otvara dashboard); persist=false: već spremio broker
    void apply_settings(const Settings& s, bool persist = true);
    void update_settings(const std::function<void(Settings&)>& change);  // ne smije se zvati u načinu brokera

    // 4.0 (SMA-02, W4): sučelje bez prava upisa u %ProgramData% – postavke i uvoz idu kroz broker (src/broker.cpp)
    bool broker_mode() const { return broker_mode_; }
    // poziv brokera s PIN-om otključanih postavki; greška kanala → {ok:false, error:"service", message}
    json broker(json request);
    // stanje brokera ({settings, secrets, pin_set…}) → Settings za ovo sučelje (bez SMTP lozinke i hasha PIN-a)
    static Settings settings_from_broker(const json& state);
    void set_settings_from_broker(const json& state);  // samo zamjena u memoriji
    std::string new_remote_view_key();   // pregled iz mreže (SMA-08): novi ključ, sprema se šifriran
    std::string remote_view_key() const;  // samo izmjena i spremanje (prijava na poslužitelj)
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
    json ipc_check_pin(const std::string& pin);
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
    bool broker_mode_ = false;
    std::string broker_pin_;  // pod mutex_; samo dok je prozor postavki otključan
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

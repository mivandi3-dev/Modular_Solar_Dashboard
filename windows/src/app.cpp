#include "app.hpp"

#include <objbase.h>

#include <thread>

#include "api.hpp"
#include "crypto.hpp"
#include "secret.hpp"
#include "tls.hpp"
#include "display.hpp"
#include "system.hpp"
#include "i18n.hpp"
#include "util.hpp"

namespace sm {

namespace {
constexpr UINT kMsgUiTask = WM_APP + 10;    // lParam: std::function<void()>*
constexpr UINT kMsgCleanup = WM_APP + 11;   // zatvoren prozor → oslobodi ga izvan njegovog WndProca
constexpr UINT_PTR kTimerTick = 1;
constexpr int kDailyReloadHour = 3;          // svaki dan u 03:00 stranica se učita iznova (rad 0–24)
constexpr COLORREF kBackground[] = {RGB(0x0B, 0x11, 0x20), RGB(0xEE, 0xF2, 0xF8)};
const std::wstring kMainUrl = L"https://app.solari/web/index.html";
const std::wstring kSettingsUrl = L"https://app.solari/web/settings.html";
}  // namespace

Settings App::settings() const {
    std::lock_guard lock(mutex_);
    return settings_;
}

// ---------------------------------------------------------------- životni ciklus
int App::run() {
    ui_thread_ = GetCurrentThreadId();
    log_open(logs_dir() / L"app.log");
    log_info(std::string("Solarni monitor ") + SOLARI_VERSION + " pokrenut");
    catalog_ = load_catalog(exe_dir() / L"web" / L"catalog.json");
    if (!webview_available()) {
        message_box(widen(tr("Nedostaje Microsoft Edge WebView2 Runtime. Ponovno pokrenite instalaciju Solarnog monitora "
                             "(instalira ga automatski).")), true);
        return 1;
    }
    settings_ = load_settings();
    wizard_ = !is_configured();
    set_language(wizard_ ? system_language() : settings_.language);
    poller_.start();  // čeka postavke ako je ovo prvo pokretanje
    if (server_role_) {
        log_info("Solarni poslužitelj – postavke");
        update_api();
        open_settings();
    } else if (wizard_) {
        log_info("Prvo pokretanje – čarobnjak za postavke");
        open_settings();
    } else {
        create_main();
    }
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == nullptr && msg.message == kMsgUiTask) {
            std::unique_ptr<std::function<void()>> task(reinterpret_cast<std::function<void()>*>(msg.lParam));
            (*task)();
            continue;
        }
        if (msg.hwnd == nullptr && msg.message == kMsgCleanup) {
            if (main_ && !main_->hwnd()) main_.reset();
            if (settings_window_ && !settings_window_->hwnd()) {
                settings_window_.reset();
                admin_logout();  // zatvoren prozor poslužitelja = odjava administratora
            }
            if (!main_ && !settings_window_) PostQuitMessage(0);
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    poller_.stop();
    for (int i = 0; i < 50 && workers_ > 0; ++i) Sleep(100);  // radne niti (npr. provjera veze) završe
    log_info("Aplikacija zatvorena");
    return 0;
}

void App::run_async(std::function<void()> work) {
    ++workers_;
    std::thread([this, work = std::move(work)] {
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        try {
            work();
        } catch (const std::exception& e) {
            log_error(std::string("Radna nit: ") + e.what());
        }
        CoUninitialize();
        --workers_;
    }).detach();
}

void App::post_ui(std::function<void()> work) {
    PostThreadMessageW(ui_thread_, kMsgUiTask, 0, reinterpret_cast<LPARAM>(new std::function<void()>(std::move(work))));
}

void App::reply(WindowKind kind, const json& message) {
    // Odgovor može stići nakon zatvaranja prozora – tada se odbacuje.
    post_ui([this, kind, text = message.dump()] {
        WebViewWindow* w = kind == WindowKind::Main ? main_.get() : settings_window_.get();
        if (w && w->hwnd()) w->post(text);
    });
}

void App::on_message(WindowKind kind, const std::string& message) {
    try {
        dispatch(*this, kind, json::parse(message));
    } catch (const json::exception& e) {
        log_warn(std::string("Neispravna poruka iz sučelja: ") + e.what());
    }
}

// ---------------------------------------------------------------- glavni prozor
void App::create_main() {
    const Settings s = settings();
    const auto screens = list_screens();
    // 1600 × 900 logičkih piksela (na zaslonu sa 150 % to je 2400 × 1350 fizičkih), unutar zaslona
    const double dpi = GetDpiForSystem() / 96.0;
    const int want_w = static_cast<int>(1600 * dpi), want_h = static_cast<int>(900 * dpi);
    RECT bounds{100, 100, 100 + want_w, 100 + want_h};
    if (!screens.empty()) {
        const Screen& sc = screens[static_cast<size_t>(s.monitor) < screens.size() ? s.monitor : 0];
        const int w = std::min(sc.width - 120, want_w), h = std::min(sc.height - 120, want_h);
        bounds = {sc.x + (sc.width - w) / 2, sc.y + (sc.height - h) / 2, sc.x + (sc.width + w) / 2, sc.y + (sc.height + h) / 2};
    }
    WebViewCallbacks cb;
    cb.on_message = [this](const std::string& m) { on_message(WindowKind::Main, m); };
    cb.on_resize = [this] { apply_zoom(); };
    cb.on_ready = [this] { apply_zoom(); };
    cb.on_closed = [this] {
        if (settings_window_) settings_window_->close();
        PostThreadMessageW(ui_thread_, kMsgCleanup, 0, 0);
    };
    main_ = std::make_unique<WebViewWindow>(L"Solarni monitor", bounds, kMainUrl, cb, kBackground[s.theme == "light"]);
    SetTimer(main_->hwnd(), kTimerTick, 60'000, [](HWND, UINT, UINT_PTR, DWORD) { app().tick(); });
    keep_awake(s.keep_awake);
    if (s.start_fullscreen) toggle_fullscreen();
    update_remote();
}

void App::update_remote() {
    const Settings s = settings();
    const int want = s.remote_view ? s.remote_port : 0;
    if (want == remote_port()) return;
    remote_.reset();
    if (!want) return;
    if (s.remote_view_key_enc.empty()) new_remote_view_key();  // 4.0: pregled iz mreže samo uz pristupni ključ
    auto server = std::make_unique<HttpServer>(remote_view_handler([this] { return dashboard_json(*this); },
                                                                   [this] { return unprotect_secret(settings().remote_view_key_enc); }));
    if (server->start(want, true)) remote_ = std::move(server);
}

void App::update_api() {
    if (!service_lock_) service_lock_ = std::make_unique<NamedMutex>(kServerServiceMutex);
    if (!service_lock_->owned()) return;  // API vodi zadatak sustava (--service)
    const Settings s = settings();
    if (api_ && api_->port() == s.server_port && api_->lan() == (s.server_lan && api_->tls())) return;
    UserStore* store = nullptr;
    try {
        store = &users();
    } catch (const std::exception& e) {
        log_error(std::string("Korisnici: ") + e.what() + " – API se ne pokreće");
        return;
    }
    if (!api_) {
        api_ = std::make_unique<HttpServer>(api_handler({&data_, &weather_, &catalog_, store, [this] { return settings(); }}));
        try {
            api_->set_tls(std::make_shared<TlsCredentials>());
        } catch (const std::exception& e) {
            log_error(std::string("HTTPS: ") + e.what() + " – API samo na 127.0.0.1");
        }
    }
    api_->start(s.server_port, s.server_lan && api_->tls());
}

void App::window_control(WindowKind kind, const std::string& action) {
    WebViewWindow* w = kind == WindowKind::Main ? main_.get() : settings_window_.get();
    if (!w) return;
    if (action == "minimize") w->minimize();
    else if (action == "maximize") w->toggle_maximize();
    else if (action == "drag") w->start_drag();
    else if (action == "close") {
        if (kind == WindowKind::Settings) close_settings();
        else w->close();
    }
}

json App::window_state(WindowKind kind) const {
    const WebViewWindow* w = kind == WindowKind::Main ? main_.get() : settings_window_.get();
    return {{"fullscreen", kind == WindowKind::Main && fullscreen_.load()}, {"maximized", w && w->maximized()}};
}

void App::set_display(bool on) {
    display_on_ = on;
    keep_awake(settings().keep_awake, on);
    monitor_power(on);
    log_info(on ? "Noćni način: zaslon upaljen" : "Noćni način: zaslon ugašen");
}

void App::apply_zoom() {
    if (!main_ || !main_->hwnd()) return;
    const Settings s = settings();
    int w = 0, h = 0;
    main_->client_size_px(w, h);
    // Izvan cijelog zaslona dashboard uvijek stane u prozor (uz izbornik widgeta);
    // odabrana razlučivost (Full HD / 2K / 4K) vrijedi preko cijelog zaslona.
    const std::string scale = fullscreen_ ? s.display_scale : "auto";
    const int extra = !fullscreen_ && sidebar_open_ ? kSidebarCssW : 0;
    main_->set_zoom(zoom_factor(scale, w, h, main_->dpi_scale(), extra));
}

void App::toggle_fullscreen() {
    if (!main_) return;
    fullscreen_ = !fullscreen_;
    main_->set_fullscreen(fullscreen_);
    apply_zoom();
    main_->post(json{{"event", "mode"}, {"fullscreen", fullscreen_.load()}}.dump());
}

void App::set_sidebar(bool open) {
    sidebar_open_ = open;
    apply_zoom();
}

void App::reload_dashboard() {
    if (main_) main_->post(json{{"event", "reload"}}.dump());
}

void App::quit() {
    if (settings_window_) settings_window_->close();
    if (main_) main_->close();
}

void App::tick() {
    const std::tm t = local_tm(now());
    if (t.tm_hour == kDailyReloadHour && t.tm_yday != reloaded_day_ && main_) {
        reloaded_day_ = t.tm_yday;
        log_info("Dnevno osvježavanje stranice");
        main_->reload();
    }
}

// ---------------------------------------------------------------- postavke
void* App::settings_hwnd() const { return settings_window_ ? settings_window_->hwnd() : nullptr; }

void App::open_settings(const std::string& panel) {
    if (settings_window_) {
        settings_window_->bring_to_front();
        return;
    }
    settings_panel_ = panel;
    // poslužitelj: uvijek prijava administratora (ili izrada prvog); klijent: PIN ako je postavljen
    admin_logout();
    settings_unlocked_ = !server_role_ && (wizard_ || settings().settings_pin_hash.empty());
    WebViewCallbacks cb;
    cb.on_message = [this](const std::string& m) { on_message(WindowKind::Settings, m); };
    cb.on_closed = [this] { PostThreadMessageW(ui_thread_, kMsgCleanup, 0, 0); };
    const double dpi = GetDpiForSystem() / 96.0;
    const int w = static_cast<int>(1100 * dpi), h = static_cast<int>(800 * dpi);
    RECT work{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    RECT bounds{work.left + (work.right - work.left - w) / 2, work.top + (work.bottom - work.top - h) / 2, 0, 0};
    bounds.right = bounds.left + w;
    bounds.bottom = bounds.top + h;
    const std::wstring title = widen(server_role_ ? tr("Solarni poslužitelj – postavke")
                                     : wizard_    ? tr("Solarni monitor – prvo postavljanje")
                                                  : tr("Solarni monitor – postavke"));
    settings_window_ = std::make_unique<WebViewWindow>(title, bounds, kSettingsUrl, cb, kBackground[0],
                                                       main_ ? main_->hwnd() : nullptr);
    if (fullscreen_) settings_window_->set_topmost(true);  // inače bi bio ispod dashboarda
}

void App::close_settings() {
    if (settings_window_) settings_window_->close();
}

UserStore& App::users() {
    std::lock_guard lock(users_mutex_);
    if (!users_) users_ = std::make_unique<UserStore>(users_db_file(), load_or_create_user_keys(users_key_file()));
    return *users_;
}

std::optional<UserInfo> App::admin() const {
    std::lock_guard lock(mutex_);
    return admin_;
}

json App::admin_login(const std::string& email, std::string password, const std::string& totp, std::string new_password) {
    const LoginResult r = users().login(email, std::move(password), "Solarni poslužitelj (ovo računalo)", now(), totp, std::move(new_password));
    if (r.status == LoginResult::Status::ActivationRequired) {
        return {{"ok", false}, {"password_change", true}, {"message", tr("Aktivacijski kod je točan – postavite svoju lozinku.")}};
    }
    if (r.status == LoginResult::Status::PasswordInvalid) return {{"ok", false}, {"password_change", true}, {"message", r.problem}};
    if (r.status == LoginResult::Status::TotpRequired || r.status == LoginResult::Status::TotpSetup ||
        r.status == LoginResult::Status::TotpInvalid) {
        json t = {{"step", r.status == LoginResult::Status::TotpSetup || !r.totp_uri.empty() ? "setup" : "code"},
                  {"invalid", r.status == LoginResult::Status::TotpInvalid}};
        if (!r.totp_uri.empty()) t.update({{"secret", r.totp_secret}, {"uri", r.totp_uri}});
        return {{"ok", false}, {"totp", t},
                {"message", r.status == LoginResult::Status::TotpInvalid ? tr("Kod nije točan ili je već iskorišten.")
                            : r.status == LoginResult::Status::TotpSetup ? tr("Skenirajte QR kod aplikacijom autentifikatorom i upišite prikazani kod.")
                                                                         : tr("Upišite kod iz aplikacije autentifikatora.")}};
    }
    if (r.status == LoginResult::Status::Locked) {
        return {{"ok", false}, {"message", tr("Račun je privremeno zaključan zbog previše pogrešnih pokušaja.")}};
    }
    if (r.status == LoginResult::Status::Disabled) return {{"ok", false}, {"message", tr("Račun je blokiran.")}};
    if (r.status != LoginResult::Status::Ok) return {{"ok", false}, {"message", tr("Pogrešna e-pošta ili lozinka.")}};
    if (r.user->role != Role::Admin) {
        users().logout(r.token);
        log_warn("Prozor poslužitelja: prijava korisnika bez administratorskih prava (#" + std::to_string(r.user->id) + ")");
        return {{"ok", false}, {"message", tr("Postavke poslužitelja može otvoriti samo administrator.")}};
    }
    {
        std::lock_guard lock(mutex_);
        admin_ = r.user;
        admin_token_ = r.token;
    }
    settings_unlocked_ = true;
    log_info("Prozor poslužitelja: prijavljen administrator #" + std::to_string(r.user->id));
    json ok = {{"ok", true}, {"message", tr("Prijavljeni ste.")}};
    if (!r.recovery_codes.empty()) ok["recovery_codes"] = r.recovery_codes;
    return ok;
}

json App::setup_admin(const UserInput& in) {
    if (users().has_admin()) return {{"ok", false}, {"message", tr("Administrator već postoji – prijavite se.")}};
    UserInput admin = in;
    admin.role = Role::Admin;
    if (admin.password.empty()) {  // prvi administrator uvijek upisuje vlastitu lozinku (nema aktivacijskog koda)
        return {{"ok", false}, {"errors", {{"password", tr("Upišite lozinku.")}}}, {"message", tr("Provjerite označena polja.")}};
    }
    try {
        users().create(admin, now());
    } catch (const UserError& e) {
        return {{"ok", false}, {"errors", e.fields}, {"message", tr("Provjerite označena polja.")}};
    }
    log_info("Izrađen prvi administrator Solarnog poslužitelja");
    return admin_login(admin.email, admin.password);
}

void App::admin_logout() {
    std::string token;
    {
        std::lock_guard lock(mutex_);
        admin_.reset();
        token.swap(admin_token_);
    }
    if (!token.empty() && users_) users_->logout(token);
    if (server_role_) settings_unlocked_ = false;
}

json App::unlock(const std::string& pin) {
    constexpr int kMaxAttempts = 5, kLockoutS = 60;
    const std::time_t t = now();
    if (t < pin_locked_until_) {
        return {{"ok", false}, {"message", tr("Previše pogrešnih pokušaja. Pokušajte za {s} s.", {{"s", std::to_string(pin_locked_until_ - t)}})}};
    }
    if (check_pin(pin, settings().settings_pin_hash)) {
        settings_unlocked_ = true;
        pin_failures_ = 0;
        return {{"ok", true}, {"message", tr("Otključano.")}};
    }
    log_warn("Pogrešan PIN za postavke");
    if (++pin_failures_ >= kMaxAttempts) {
        pin_failures_ = 0;
        pin_locked_until_ = t + kLockoutS;
    }
    return {{"ok", false}, {"message", tr("Pogrešan PIN.")}};
}

std::string App::new_remote_view_key() {
    // 128 bita slučajno (base32, 26 znakova); stari ključ odmah prestaje vrijediti
    Bytes raw = random_bytes(16);
    std::string key = base32(raw);
    wipe(raw);
    update_settings([&](Settings& s) { s.remote_view_key_enc = protect_secret(key); });
    log_info("Pregled iz mreže: izrađen novi pristupni ključ");
    return key;
}

std::string App::remote_view_key() const { return unprotect_secret(settings().remote_view_key_enc); }

void App::update_settings(const std::function<void(Settings&)>& change) {
    std::lock_guard lock(mutex_);
    change(settings_);
    save_settings(settings_);
}

void App::apply_settings(const Settings& s) {
    const Settings old = settings();
    save_settings(s);
    set_language(s.language);
    {
        std::lock_guard lock(mutex_);
        settings_ = s;
    }
    log_info("Postavke spremljene");
    if (server_role_) {
        wizard_ = false;
        update_api();
        return;
    }
    keep_awake(s.keep_awake, display_on_);
    if (!wizard_) update_remote();
    if (wizard_) {
        wizard_ = false;
        create_main();
        return;
    }
    if (main_ && s.monitor != old.monitor) {
        const auto screens = list_screens();
        if (static_cast<size_t>(s.monitor) < screens.size()) {
            const Screen& sc = screens[s.monitor];
            main_->move_to(RECT{sc.x, sc.y, sc.x + sc.width, sc.y + sc.height});
        }
    }
    apply_zoom();
    reload_dashboard();  // tema, naziv, kartice… vrijede odmah
}

}  // namespace sm

#include "webview.hpp"

#include <WebView2.h>
#include <dwmapi.h>
#include <windowsx.h>

#include <atomic>

namespace sm {

namespace {

constexpr UINT kMsgPost = WM_APP + 1;  // lParam: std::string* s JSON-om za JS
constexpr wchar_t kClassName[] = L"SolarniMonitor2Window";

using CreateEnvironmentFn = HRESULT(STDAPICALLTYPE*)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions*,
                                                     ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);
ICoreWebView2Environment* g_env = nullptr;

// Općeniti COM rukovatelj za WebView2 događaje: jedno sučelje s metodom Invoke(args...).
template <typename Iface, const IID* Iid, typename... Args>
class Handler final : public Iface {
public:
    explicit Handler(std::function<HRESULT(Args...)> fn) : fn_(std::move(fn)) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override {
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, *Iid)) {
            *out = static_cast<Iface*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG left = --refs_;
        if (left == 0) delete this;  // COM objekt: životni vijek po brojaču referenci
        return left;
    }
    HRESULT STDMETHODCALLTYPE Invoke(Args... args) override { return fn_(args...); }

private:
    std::function<HRESULT(Args...)> fn_;
    std::atomic<ULONG> refs_{1};
};

using EnvironmentDone = Handler<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
                                &IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler, HRESULT,
                                ICoreWebView2Environment*>;
using ControllerDone = Handler<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
                               &IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler, HRESULT,
                               ICoreWebView2Controller*>;
using MessageReceived = Handler<ICoreWebView2WebMessageReceivedEventHandler, &IID_ICoreWebView2WebMessageReceivedEventHandler,
                                ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs*>;

template <typename T>
struct ComPtr {  // minimalni pametni pokazivač za QueryInterface
    T* p = nullptr;
    ~ComPtr() { if (p) p->Release(); }
    T** put() { return &p; }
    T* operator->() const { return p; }
    explicit operator bool() const { return p != nullptr; }
};

bool ensure_environment() {
    if (g_env) return true;
    HMODULE dll = LoadLibraryW((exe_dir() / L"WebView2Loader.dll").c_str());
    if (!dll) return false;
    auto create = reinterpret_cast<CreateEnvironmentFn>(
        reinterpret_cast<void*>(GetProcAddress(dll, "CreateCoreWebView2EnvironmentWithOptions")));
    if (!create) return false;
    bool done = false;
    auto* handler = new EnvironmentDone([&](HRESULT hr, ICoreWebView2Environment* env) {
        if (SUCCEEDED(hr) && env) {
            env->AddRef();
            g_env = env;
        }
        done = true;
        return S_OK;
    });
    const std::wstring user_data = (home_dir() / L"webview2").wstring();
    const HRESULT hr = create(nullptr, user_data.c_str(), nullptr, handler);
    handler->Release();
    if (FAILED(hr)) return false;
    MSG msg;
    while (!done && GetMessageW(&msg, nullptr, 0, 0)) {  // okruženje se stvara asinkrono
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return g_env != nullptr;
}

void register_class() {
    static bool registered = false;
    if (registered) return;
    WNDCLASSEXW wc{sizeof wc};
    wc.lpfnWndProc = WebViewWindow::wnd_proc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(wc.hInstance, MAKEINTRESOURCEW(1));
    wc.hIconSm = wc.hIcon;
    wc.lpszClassName = kClassName;
    RegisterClassExW(&wc);
    registered = true;
}

}  // namespace

bool webview_available() { return ensure_environment(); }

WebViewWindow::WebViewWindow(const std::wstring& title, RECT b, const std::wstring& url, WebViewCallbacks callbacks,
                             COLORREF background, HWND owner)
    : url_(url), cb_(std::move(callbacks)), background_(background) {
    register_class();
    hwnd_ = CreateWindowExW(0, kClassName, title.c_str(), WS_OVERLAPPEDWINDOW, b.left, b.top, b.right - b.left,
                            b.bottom - b.top, owner, nullptr, GetModuleHandleW(nullptr), this);
    const BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd_, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &dark, sizeof dark);
    // bez okvira: ni naslovne trake (WM_NCCALCSIZE) ni Windows 11 obruba; sjena i zaobljeni kutovi ostaju
    const COLORREF no_border = 0xFFFFFFFE;  // DWMWA_COLOR_NONE
    DwmSetWindowAttribute(hwnd_, 34 /*DWMWA_BORDER_COLOR*/, &no_border, sizeof no_border);
    background_brush_ = CreateSolidBrush(background);
    SetWindowPos(hwnd_, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    ShowWindow(hwnd_, SW_SHOW);
    create_controller();
}

WebViewWindow::~WebViewWindow() {
    if (controller_) {
        controller_->Close();
        controller_->Release();
    }
    if (webview_) webview_->Release();
    if (hwnd_) {
        SetWindowLongPtrW(hwnd_, GWLP_USERDATA, 0);
        DestroyWindow(hwnd_);
    }
    if (background_brush_) DeleteObject(background_brush_);
}

void WebViewWindow::create_controller() {
    if (!ensure_environment()) return;
    auto* handler = new ControllerDone([this](HRESULT hr, ICoreWebView2Controller* controller) {
        if (FAILED(hr) || !controller || !hwnd_) return S_OK;
        controller->AddRef();
        controller_ = controller;
        controller_->get_CoreWebView2(&webview_);

        ComPtr<ICoreWebView2Settings> settings;
        webview_->get_Settings(settings.put());
        const bool debug = _wgetenv(L"SOLARI2_DEBUG") != nullptr;
        settings->put_AreDevToolsEnabled(debug);
        settings->put_AreDefaultContextMenusEnabled(debug);
        settings->put_IsStatusBarEnabled(FALSE);
        settings->put_IsZoomControlEnabled(FALSE);  // zoom određuje aplikacija (Full HD / 2K / 4K)
        ComPtr<ICoreWebView2Settings3> settings3;
        if (SUCCEEDED(settings->QueryInterface(IID_ICoreWebView2Settings3, reinterpret_cast<void**>(settings3.put())))) {
            settings3->put_AreBrowserAcceleratorKeysEnabled(debug);  // F5, Ctrl+F … obrađuje aplikacija
        }
        ComPtr<ICoreWebView2Controller2> controller2;
        if (SUCCEEDED(controller_->QueryInterface(IID_ICoreWebView2Controller2, reinterpret_cast<void**>(controller2.put())))) {
            controller2->put_DefaultBackgroundColor(
                COREWEBVIEW2_COLOR{255, GetRValue(background_), GetGValue(background_), GetBValue(background_)});
        }
        // Lokalne datoteke preko virtualnih hostova (https://app.solari/..., https://data.solari/...)
        ComPtr<ICoreWebView2_3> webview3;
        if (SUCCEEDED(webview_->QueryInterface(IID_ICoreWebView2_3, reinterpret_cast<void**>(webview3.put())))) {
            std::error_code ec;
            fs::create_directories(images_dir(), ec);
            webview3->SetVirtualHostNameToFolderMapping(L"app.solari", exe_dir().c_str(),
                                                        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY_CORS);
            webview3->SetVirtualHostNameToFolderMapping(L"data.solari", images_dir().c_str(),
                                                        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY_CORS);
        }
        EventRegistrationToken token{};
        auto* on_message = new MessageReceived([this](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) {
            LPWSTR text = nullptr;
            if (SUCCEEDED(args->TryGetWebMessageAsString(&text)) && text) {
                const std::string message = narrow(text);
                CoTaskMemFree(text);
                if (cb_.on_message) cb_.on_message(message);
            }
            return S_OK;
        });
        webview_->add_WebMessageReceived(on_message, &token);
        on_message->Release();
        resize_controller();
        if (cb_.on_ready) cb_.on_ready();
        webview_->Navigate(url_.c_str());
        return S_OK;
    });
    g_env->CreateCoreWebView2Controller(hwnd_, handler);
    handler->Release();
}

void WebViewWindow::resize_controller() {
    if (!controller_) return;
    RECT r;
    GetClientRect(hwnd_, &r);
    if (!fullscreen_ && !IsZoomed(hwnd_)) {  // tanak rub oko stranice za promjenu veličine mišem
        const int b = resize_border();
        InflateRect(&r, -b, -b);
    }
    controller_->put_Bounds(r);
}

int WebViewWindow::resize_border() const { return static_cast<int>(kResizeBorderPx * dpi_scale() + 0.5); }

void WebViewWindow::minimize() { ShowWindow(hwnd_, SW_MINIMIZE); }

void WebViewWindow::toggle_maximize() {
    if (fullscreen_) return;
    ShowWindow(hwnd_, IsZoomed(hwnd_) ? SW_RESTORE : SW_MAXIMIZE);
}

bool WebViewWindow::maximized() const { return IsZoomed(hwnd_) != FALSE; }

void WebViewWindow::start_drag() {
    if (fullscreen_) return;
    ReleaseCapture();  // miš drži WebView2 – prepušta se sustavu kao da je povučena naslovna traka
    SendMessageW(hwnd_, WM_NCLBUTTONDOWN, HTCAPTION, 0);
}

void WebViewWindow::post(std::string json) {
    if (hwnd_) PostMessageW(hwnd_, kMsgPost, 0, reinterpret_cast<LPARAM>(new std::string(std::move(json))));
}

void WebViewWindow::navigate(const std::wstring& url) {
    url_ = url;
    if (webview_) webview_->Navigate(url.c_str());
}

void WebViewWindow::reload() {
    if (webview_) webview_->Reload();
}

void WebViewWindow::set_zoom(double zoom) {
    double current = 0;
    if (controller_ && SUCCEEDED(controller_->get_ZoomFactor(&current)) && std::abs(current - zoom) > 1e-3) {
        controller_->put_ZoomFactor(zoom);
    }
}

void WebViewWindow::client_size_px(int& width, int& height) const {
    RECT r{};
    GetClientRect(hwnd_, &r);
    width = r.right - r.left;
    height = r.bottom - r.top;
}

double WebViewWindow::dpi_scale() const { return GetDpiForWindow(hwnd_) / 96.0; }

void WebViewWindow::set_fullscreen(bool on) {
    if (on == fullscreen_) return;
    if (on) {
        GetWindowPlacement(hwnd_, &placement_);
        style_ = GetWindowLongPtrW(hwnd_, GWL_STYLE);
        MONITORINFO mi{sizeof mi};
        GetMonitorInfoW(MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST), &mi);
        SetWindowLongPtrW(hwnd_, GWL_STYLE, (style_ & ~WS_OVERLAPPEDWINDOW) | WS_POPUP);
        const RECT& m = mi.rcMonitor;
        SetWindowPos(hwnd_, HWND_TOP, m.left, m.top, m.right - m.left, m.bottom - m.top, SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
    } else {
        SetWindowLongPtrW(hwnd_, GWL_STYLE, style_);
        SetWindowPlacement(hwnd_, &placement_);
        SetWindowPos(hwnd_, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    }
    fullscreen_ = on;
    resize_controller();
}

void WebViewWindow::move_to(RECT m) {
    const bool was_full = fullscreen_;
    if (was_full) set_fullscreen(false);
    const int w = std::min<int>(1600, m.right - m.left - 80), h = std::min<int>(900, m.bottom - m.top - 80);
    SetWindowPos(hwnd_, nullptr, m.left + 40, m.top + 40, w, h, SWP_NOZORDER);
    if (was_full) set_fullscreen(true);
}

void WebViewWindow::set_topmost(bool on) {
    SetWindowPos(hwnd_, on ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

void WebViewWindow::bring_to_front() {
    if (IsIconic(hwnd_)) ShowWindow(hwnd_, SW_RESTORE);
    SetForegroundWindow(hwnd_);
}

void WebViewWindow::close() {
    if (hwnd_) PostMessageW(hwnd_, WM_CLOSE, 0, 0);
}

LRESULT CALLBACK WebViewWindow::wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        reinterpret_cast<WebViewWindow*>(cs->lpCreateParams)->hwnd_ = hwnd;
    }
    auto* self = reinterpret_cast<WebViewWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    return self ? self->handle(msg, wp, lp) : DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT WebViewWindow::handle(UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case kMsgPost: {
        std::unique_ptr<std::string> json(reinterpret_cast<std::string*>(lp));
        if (webview_) webview_->PostWebMessageAsJson(widen(*json).c_str());
        return 0;
    }
    case WM_SIZE:
        resize_controller();
        if (cb_.on_resize) cb_.on_resize();
        return 0;
    case WM_DPICHANGED: {
        const RECT* r = reinterpret_cast<RECT*>(lp);
        SetWindowPos(hwnd_, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        if (cb_.on_resize) cb_.on_resize();
        return 0;
    }
    case WM_MOVE:
        if (controller_) controller_->NotifyParentWindowPositionChanged();
        return 0;
    case WM_NCCALCSIZE:
        if (wp == TRUE) {
            // cijeli prozor je stranica; maksimiziran prozor Windows povećava za debljinu okvira – vrati ga u zaslon
            if (IsZoomed(hwnd_) && !fullscreen_) {
                auto* p = reinterpret_cast<NCCALCSIZE_PARAMS*>(lp);
                const UINT dpi = GetDpiForWindow(hwnd_);
                const int frame = GetSystemMetricsForDpi(SM_CXFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                InflateRect(&p->rgrc[0], -frame, -frame);
            }
            return 0;
        }
        return DefWindowProcW(hwnd_, msg, wp, lp);
    case WM_NCHITTEST: {
        if (fullscreen_ || IsZoomed(hwnd_)) return HTCLIENT;
        POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
        RECT w;
        GetWindowRect(hwnd_, &w);
        const int b = resize_border() + 2;
        const bool left = pt.x < w.left + b, right = pt.x >= w.right - b, top = pt.y < w.top + b, bottom = pt.y >= w.bottom - b;
        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
        return HTCLIENT;
    }
    case WM_ERASEBKGND: {
        RECT r;
        GetClientRect(hwnd_, &r);
        FillRect(reinterpret_cast<HDC>(wp), &r, background_brush_);
        return 1;
    }
    case WM_GETMINMAXINFO: {
        auto* mm = reinterpret_cast<MINMAXINFO*>(lp);
        mm->ptMinTrackSize = {800, 480};
        return 0;
    }
    case WM_DESTROY: {
        HWND hwnd = hwnd_;
        hwnd_ = nullptr;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (cb_.on_closed) cb_.on_closed();
        return 0;
    }
    default:
        return DefWindowProcW(hwnd_, msg, wp, lp);
    }
}

}  // namespace sm

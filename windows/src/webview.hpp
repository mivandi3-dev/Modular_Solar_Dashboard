// Prozor s WebView2 kontrolom (Win32, bez WRL-a): virtualni hostovi za lokalne datoteke, poruke
// JS ↔ C++, zoom, cijeli zaslon. Svi pozivi na WebView idu u GUI niti; post() smije iz bilo koje niti.
#pragma once

#include <windows.h>

#include <functional>
#include <memory>
#include <string>

#include "util.hpp"

struct ICoreWebView2;
struct ICoreWebView2Controller;
struct ICoreWebView2Environment;

namespace sm {

inline constexpr int kResizeBorderPx = 5;

struct WebViewCallbacks {
    std::function<void(const std::string& message)> on_message;  // JSON iz chrome.webview.postMessage
    std::function<void()> on_ready;                               // kontrola spremna (prije prve navigacije)
    std::function<void()> on_resize;                              // promjena veličine, DPI ili zaslona
    std::function<void()> on_closed;
};

class WebViewWindow {
public:
    WebViewWindow(const std::wstring& title, RECT bounds, const std::wstring& url, WebViewCallbacks callbacks,
                  COLORREF background, HWND owner = nullptr);
    ~WebViewWindow();
    WebViewWindow(const WebViewWindow&) = delete;
    WebViewWindow& operator=(const WebViewWindow&) = delete;

    HWND hwnd() const { return hwnd_; }
    void post(std::string json);  // iz bilo koje niti
    void navigate(const std::wstring& url);
    void reload();
    void set_zoom(double zoom);
    void client_size_px(int& width, int& height) const;
    double dpi_scale() const;
    void set_fullscreen(bool on);
    bool fullscreen() const { return fullscreen_; }
    void move_to(RECT monitor);
    void set_topmost(bool on);
    void bring_to_front();
    void close();
    // Prozor bez okvira (3.1): kružići u stranici (web/window.js) zovu ove radnje
    void minimize();
    void toggle_maximize();
    void start_drag();  // pomicanje prozora povlačenjem trake na vrhu stranice
    bool maximized() const;

    static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

private:
    void create_controller();
    void resize_controller();
    int resize_border() const;  // px rub za promjenu veličine (prozor bez okvira)
    LRESULT handle(UINT msg, WPARAM wp, LPARAM lp);

    HWND hwnd_ = nullptr;
    std::wstring url_;
    WebViewCallbacks cb_;
    COLORREF background_;
    ICoreWebView2Controller* controller_ = nullptr;
    ICoreWebView2* webview_ = nullptr;
    bool fullscreen_ = false;
    HBRUSH background_brush_ = nullptr;  // rub za promjenu veličine u boji pozadine (prozor nema okvira)
    WINDOWPLACEMENT placement_{sizeof(WINDOWPLACEMENT)};
    LONG_PTR style_ = 0;
};

// Pokreće WebView2 okruženje (jednom po procesu). false ako WebView2 Runtime nije instaliran.
bool webview_available();

}  // namespace sm

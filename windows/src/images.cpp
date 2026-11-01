#include "images.hpp"

#include <windows.h>
#include <wincodec.h>

#include <cmath>
#include <cstdio>

#include "i18n.hpp"
#include "util.hpp"

namespace sm {

namespace {

constexpr uintmax_t kMaxFileBytes = 40ull * 1024 * 1024;
constexpr double kRatioTolerance = 0.15;
constexpr UINT kThumbWidth = 360;

struct Spec {
    const char* title;
    double ratio;
    const char* ratio_text;
    UINT min_w, min_h, max_w;
    const char* hint;
    const wchar_t* custom_name;
    const wchar_t* default_name;
};

const Spec& spec(const std::string& kind) {
    static const Spec kHero{
        "Fotografija u zaglavlju", 6.0, "6 : 1", 1920, 320, 3840,
        "Široka fotografija, omjer 6 : 1 – npr. 3840 × 640 px (za 4K) ili najmanje 1920 × 320 px. Lijeva trećina "
        "prekrivena je pozdravom i logom, a desno je prognoza, pa glavni motiv (zgrada) neka bude u sredini. Šira ili "
        "viša slika automatski se obreže po sredini.",
        L"hero.jpg", L"zgrada_iz_zraka.jpg"};
    static const Spec kDrawing{
        "Crtež zgrade (Tok energije)", 16.0 / 9.0, "16 : 9", 960, 540, 2400,
        "Crtež ili fotografija zgrade, omjer 16 : 9 – npr. 1920 × 1080 px. Zgrada u sredini, a pozadina jednolična i "
        "svijetla (aplikacija je sama ukloni) ili PNG s prozirnom pozadinom.",
        L"drawing.png", L"crtez.png"};
    static const Spec kLogo{
        "Logotip tvrtke", 9.0, "široki, npr. 9 : 1", 300, 30, 1840,
        "PNG s prozirnom pozadinom, širok i nizak – npr. 1840 × 200 px (najmanje 920 px širine za oštar prikaz na 4K). "
        "Prikazuje se u kartici zaglavlja širine 356 px i visine najviše 96 px; uži ili viši logotip se smanji da stane, "
        "bez obrezivanja.",
        L"logo.png", L"logo.png"};
    return kind == "hero" ? kHero : kind == "logo" ? kLogo : kDrawing;
}

// RAII za COM sučelja
template <typename T>
struct Com {
    T* p = nullptr;
    ~Com() { if (p) p->Release(); }
    T** put() { return &p; }
    T* operator->() const { return p; }
};

void check(HRESULT hr, const char* what) {
    if (FAILED(hr)) throw std::runtime_error(what);
}

IWICImagingFactory* factory() {
    static IWICImagingFactory* f = [] {
        IWICImagingFactory* p = nullptr;
        check(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&p)),
              "WIC nije dostupan");
        return p;
    }();
    return f;
}

struct Decoded {
    Com<IWICBitmapSource> source;  // 32bpp BGRA
    UINT width = 0, height = 0;
    bool has_alpha = false;
};

Decoded decode(const fs::path& file) {
    Com<IWICBitmapDecoder> decoder;
    if (FAILED(factory()->CreateDecoderFromFilename(file.c_str(), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnLoad,
                                                    decoder.put()))) {
        throw std::runtime_error(tr("Datoteka nije slika (podržano: JPG, PNG, WebP)."));
    }
    Com<IWICBitmapFrameDecode> frame;
    check(decoder->GetFrame(0, frame.put()), "Slika se ne može pročitati.");
    WICPixelFormatGUID fmt{};
    frame->GetPixelFormat(&fmt);
    Com<IWICFormatConverter> conv;
    check(factory()->CreateFormatConverter(conv.put()), "WIC");
    check(conv->Initialize(frame.p, GUID_WICPixelFormat32bppBGRA, WICBitmapDitherTypeNone, nullptr, 0,
                           WICBitmapPaletteTypeCustom), "Format slike nije podržan.");
    Decoded d;
    conv->GetSize(&d.width, &d.height);
    // Ima li slika stvarno prozirnih piksela (ne samo alfa kanal)?
    Com<IWICComponentInfo> info;
    if (SUCCEEDED(factory()->CreateComponentInfo(fmt, info.put()))) {
        Com<IWICPixelFormatInfo2> pf;
        BOOL transparency = FALSE;
        if (SUCCEEDED(info->QueryInterface(IID_PPV_ARGS(pf.put()))) && SUCCEEDED(pf->SupportsTransparency(&transparency)) &&
            transparency) {
            std::vector<uint8_t> row(static_cast<size_t>(d.width) * 4);
            for (UINT y = 0; y < d.height && !d.has_alpha; y += std::max(1u, d.height / 200)) {
                WICRect r{0, static_cast<INT>(y), static_cast<INT>(d.width), 1};
                conv->CopyPixels(&r, d.width * 4, static_cast<UINT>(row.size()), row.data());
                for (size_t x = 3; x < row.size(); x += 4) if (row[x] < 250) { d.has_alpha = true; break; }
            }
        }
    }
    conv->QueryInterface(IID_PPV_ARGS(d.source.put()));
    return d;
}

void encode(IWICBitmapSource* src, UINT w, UINT h, const fs::path& target, bool jpeg) {
    Com<IWICBitmapScaler> scaler;
    check(factory()->CreateBitmapScaler(scaler.put()), "WIC");
    check(scaler->Initialize(src, w, h, WICBitmapInterpolationModeFant), "Smanjivanje slike nije uspjelo.");
    Com<IWICStream> stream;
    check(factory()->CreateStream(stream.put()), "WIC");
    check(stream->InitializeFromFilename(target.c_str(), GENERIC_WRITE), "Slika se ne može spremiti.");
    Com<IWICBitmapEncoder> enc;
    check(factory()->CreateEncoder(jpeg ? GUID_ContainerFormatJpeg : GUID_ContainerFormatPng, nullptr, enc.put()), "WIC");
    check(enc->Initialize(stream.p, WICBitmapEncoderNoCache), "WIC");
    Com<IWICBitmapFrameEncode> frame;
    Com<IPropertyBag2> props;
    check(enc->CreateNewFrame(frame.put(), props.put()), "WIC");
    if (jpeg) {
        PROPBAG2 opt{};
        opt.pstrName = const_cast<LPOLESTR>(L"ImageQuality");
        VARIANT v;
        VariantInit(&v);
        v.vt = VT_R4;
        v.fltVal = 0.92f;
        props->Write(1, &opt, &v);
    }
    check(frame->Initialize(props.p), "WIC");
    check(frame->SetSize(w, h), "WIC");
    WICPixelFormatGUID fmt = jpeg ? GUID_WICPixelFormat24bppBGR : GUID_WICPixelFormat32bppBGRA;
    check(frame->SetPixelFormat(&fmt), "WIC");
    Com<IWICFormatConverter> conv;
    check(factory()->CreateFormatConverter(conv.put()), "WIC");
    check(conv->Initialize(scaler.p, fmt, WICBitmapDitherTypeNone, nullptr, 0, WICBitmapPaletteTypeCustom), "WIC");
    check(frame->WriteSource(conv.p, nullptr), "Slika se ne može spremiti.");
    check(frame->Commit(), "WIC");
    check(enc->Commit(), "WIC");
}

std::string thumbnail(const fs::path& file) {
    try {
        Decoded d = decode(file);
        const UINT w = std::min(kThumbWidth, d.width), h = std::max(1u, static_cast<UINT>(std::lround(double(d.height) * w / d.width)));
        // 5.0.2 (audit C-16): jedinstveno ime koje stvara sustav (ne fiksni %TEMP%\solari_thumb.png)
        wchar_t name[MAX_PATH]{};
        if (!GetTempFileNameW(fs::temp_directory_path().c_str(), L"sth", 0, name)) return "";
        const fs::path tmp = name;
        encode(d.source.p, w, h, tmp, false);
        const auto bytes = read_file(tmp);
        fs::remove(tmp);
        return bytes ? "data:image/png;base64," + base64(std::vector<uint8_t>(bytes->begin(), bytes->end())) : "";
    } catch (const std::exception&) {
        return "";
    }
}

}  // namespace

bool is_image_kind(const std::string& kind) { return kind == "hero" || kind == "drawing" || kind == "logo"; }

fs::path image_path(const std::string& kind) {
    const fs::path custom = images_dir() / spec(kind).custom_name;
    return fs::exists(custom) ? custom : exe_dir() / L"assets" / spec(kind).default_name;
}

std::string image_url(const std::string& kind) {
    const fs::path p = image_path(kind);
    std::error_code ec;
    const auto stamp = fs::last_write_time(p, ec).time_since_epoch().count();
    const bool custom = p.parent_path() == images_dir();
    return std::string(custom ? "https://data.solari/" : "https://app.solari/assets/") + narrow(p.filename().wstring()) +
           "?v=" + std::to_string(static_cast<long long>(stamp));
}

json image_info(const std::string& kind) {
    const Spec& s = spec(kind);
    const fs::path p = image_path(kind);
    json info = {{"kind", kind}, {"title", s.title}, {"hint", s.hint}, {"ratio", s.ratio_text},
                 {"custom", p.parent_path() == images_dir()}, {"path", narrow(p.wstring())},
                 {"width", 0}, {"height", 0}, {"thumb", ""}};
    try {
        const Decoded d = decode(p);
        info["width"] = d.width;
        info["height"] = d.height;
        info["thumb"] = thumbnail(p);
    } catch (const std::exception&) {
        // slika nedostaje – sučelje to javlja
    }
    return info;
}

json replace_image(const std::string& kind, const fs::path& source) {
    const Spec& s = spec(kind);
    if (fs::file_size(source) > kMaxFileBytes) throw std::runtime_error(tr("Slika je veća od {mb} MB.", {{"mb", "40"}}));
    Decoded d = decode(source);
    if (d.width < s.min_w || d.height < s.min_h) {
        throw std::runtime_error(tr("Slika je premala ({w} × {h} px); najmanje {mw} × {mh} px.",
                                    {{"w", std::to_string(d.width)}, {"h", std::to_string(d.height)},
                                     {"mw", std::to_string(s.min_w)}, {"mh", std::to_string(s.min_h)}}));
    }
    UINT w = d.width, h = d.height;
    if (w > s.max_w) {
        h = static_cast<UINT>(std::lround(double(h) * s.max_w / w));
        w = s.max_w;
    }
    if (!ui_write_allowed(images_dir())) throw std::runtime_error("Mapa slika je spojnica ili simbolička veza – slika nije spremljena.");  // NEW-05
    fs::create_directories(images_dir());
    const fs::path target = images_dir() / s.custom_name;
    const fs::path tmp = fs::path(target) += L".tmp";
    encode(d.source.p, w, h, tmp, kind == "hero");  // crtež ostaje PNG (čuva prozirnost)
    fs::rename(tmp, target);

    const double ratio = double(w) / h;
    std::string message = tr("Slika je promijenjena ({w} × {h} px).", {{"w", std::to_string(w)}, {"h", std::to_string(h)}});
    if (kind == "logo") {
        if (ratio < 3) message += " " + tr("Logotip je visok – bit će smanjen na visinu kartice (preporučen je širi logotip).");
    } else if (std::abs(ratio - s.ratio) / s.ratio > kRatioTolerance) {
        char r[16];
        std::snprintf(r, sizeof r, "%.2f", ratio);
        message += " " + tr("Omjer slike je {ratio} : 1, a preporučeno je {wanted}.", {{"ratio", r}, {"wanted", tr(s.ratio_text)}});
        if (kind == "hero") message += " " + tr("Dio slike bit će obrezan.");
    }
    json info = image_info(kind);
    info["message"] = message;
    return info;
}

void reset_image(const std::string& kind) {
    std::error_code ec;
    if (!ui_write_allowed(images_dir())) return;  // NEW-05: ne briše kroz spojnicu
    fs::remove(images_dir() / spec(kind).custom_name, ec);
}

}  // namespace sm

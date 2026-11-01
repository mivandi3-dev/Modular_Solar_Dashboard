package hr.ivandic.solarnimonitor;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.print.PrintAttributes;
import android.print.PrintManager;
import android.util.LruCache;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Solarni monitor za Android: isto web sučelje kao C++ verzija (dashboard, widgeti, stranice, editor, prijevodi)
 * na https://app.solari/web/…, a podatke daje Solarni poslužitelj (Cloudflare tunel ili lokalna mreža).
 * Zahtjevi na https://app.solari/api/v1/… prosljeđuju se poslužitelju s oznakom prijave – oznaka ostaje u Javi.
 */
public class MainActivity extends Activity {
    private static final String HOST = "app.solari";
    private static final String START = "https://" + HOST + "/web/index.html";
    private static final String SETTINGS = "https://" + HOST + "/web/settings-android.html";
    private static final Pattern API_PATH = Pattern.compile("^/api/v1/(info|dashboard|report|images/(hero|drawing|logo))$");
    private static final int REQ_SAVE_CSV = 7;
    private static final int MAX_BODY = 25 * 1024 * 1024;

    private WebView web;
    private Prefs prefs;
    private boolean fullscreen;
    private String pendingCsv;
    private String pendingCsvCallback;
    private final ExecutorService io = Executors.newCachedThreadPool();
    // slike s poslužitelja (URL s oznakom verzije ?v=… → bajtovi), da se velika fotografija ne preuzima stalno
    private final LruCache<String, Cached> images = new LruCache<>(48 * 1024 * 1024) {
        @Override protected int sizeOf(String key, Cached value) { return value.body.length; }
    };

    private record Cached(String type, byte[] body) {}

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        prefs = new Prefs(this);
        WebView.setWebContentsDebuggingEnabled((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
        web = new WebView(this);
        web.setBackgroundColor(0xFF0B1120);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setUseWideViewPort(true);
        ws.setLoadWithOverviewMode(true);
        ws.setSupportZoom(false);
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        ws.setMediaPlaybackRequiresUserGesture(true);
        ws.setTextZoom(100);
        web.addJavascriptInterface(new Bridge(), "SolariAndroid");
        web.setWebChromeClient(new WebChromeClient());
        web.setWebViewClient(new Client());
        web.addOnLayoutChangeListener(this::reloadOnOrientationChange);
        setContentView(web);
        applySystemBarInsets();
        applyKeepOn();
        setFullscreen(prefs.startFullscreen());
        web.loadUrl(prefs.configured() ? START : SETTINGS);
    }

    /**
     * Android 15+ (targetSdk 35+) crta aplikaciju i ispod statusne i navigacijske trake: sadržaj se odmakne za njihovu
     * visinu i za izrez kamere. Preko cijelog zaslona trake su skrivene, pa je odmak 0.
     */
    private void applySystemBarInsets() {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) return;
        web.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets b = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            v.setPadding(b.left, b.top, b.right, b.bottom);
            return WindowInsets.CONSUMED;
        });
    }

    /**
     * Okretanje uređaja: dashboard se učita iznova tek kad WebView dobije novu veličinu (viewport se računa iz
     * stvarne širine i visine – položeno 1920 CSS px, uspravno widgeti jedan ispod drugog).
     */
    private void reloadOnOrientationChange(View v, int l, int t, int r, int b, int ol, int ot, int or, int ob) {
        boolean wasPortrait = (ob - ot) > (or - ol), portrait = (b - t) > (r - l);
        String url = web.getUrl();
        if (or - ol > 0 && wasPortrait != portrait && url != null && url.startsWith(START)) web.post(web::reload);
    }

    @Override
    public void onBackPressed() {
        String url = web.getUrl();
        if (url != null && url.startsWith(SETTINGS) && prefs.configured()) web.loadUrl(START);
        else super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        io.shutdownNow();
        web.destroy();
        super.onDestroy();
    }

    private void applyKeepOn() {
        if (prefs.keepScreenOn()) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    @SuppressWarnings("deprecation")
    private void setFullscreen(boolean on) {
        fullscreen = on;
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.R) {  // Android 8–10
            getWindow().getDecorView().setSystemUiVisibility(on
                    ? View.SYSTEM_UI_FLAG_FULLSCREEN | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                    : View.SYSTEM_UI_FLAG_VISIBLE);
            return;
        }
        WindowInsetsController c = getWindow().getInsetsController();
        if (c == null) return;
        if (on) {
            c.hide(WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars());
            c.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
        } else {
            c.show(WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars());
        }
    }

    // ------------------------------------------------------------------ lokalne datoteke i poslužitelj
    /** Trenutna stranica (5.0.1, audit A-02): osjetljive metode mosta rade samo na stranici postavki. */
    private volatile String currentPage = "";

    private boolean onSettingsPage() {
        return currentPage.startsWith(SETTINGS);
    }

    private final class Client extends WebViewClient {
        @Override
        public void onPageStarted(WebView view, String url, android.graphics.Bitmap favicon) {
            currentPage = url == null ? "" : url;
            super.onPageStarted(view, url, favicon);
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
            return !HOST.equals(req.getUrl().getHost());  // vanjske adrese se ne otvaraju u aplikaciji
        }

        @Override
        public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest req) {
            Uri u = req.getUrl();
            if (!HOST.equals(u.getHost())) return error(403, "forbidden");
            String path = u.getPath() == null ? "" : u.getPath();
            if (path.startsWith("/web/")) return asset(path.substring(5));
            if (!"GET".equals(req.getMethod()) || !API_PATH.matcher(path).matches()) return error(404, "not_found");
            return proxy(path, u.getEncodedQuery());
        }
    }

    /** Demo način: podaci i slike iz aplikacije (web/demo/); vremenske podatke slaže web/demo.js. */
    private WebResourceResponse demoResponse(String path) {
        switch (path) {
            case "/api/v1/info":
                return response(200, "application/json", new ByteArrayInputStream(
                        ("{\"plant\":\"Demo\",\"version\":\"" + version() + "\"}").getBytes(StandardCharsets.UTF_8)));
            case "/api/v1/dashboard": return asset("demo/dashboard.json");
            case "/api/v1/report": return asset("demo/report.json");
            case "/api/v1/images/hero": return asset("demo/hero.jpg");
            case "/api/v1/images/drawing": return asset("demo/drawing.png");
            case "/api/v1/images/logo": return asset("demo/logo.png");
            default: return error(404, "not_found");
        }
    }

    private WebResourceResponse asset(String name) {
        if (name.contains("..")) return error(404, "not_found");
        if (name.equals("bridge.js")) name = "android-bridge.js";
        try {
            InputStream in = getAssets().open("web/" + name);
            if (name.equals("index.html")) {
                String html = new String(readAll(in, MAX_BODY), StandardCharsets.UTF_8)
                        .replace("<meta charset=\"utf-8\">", "<meta charset=\"utf-8\">\n" + viewport())
                        .replace("<script src=\"bridge.js\"></script>", "<script src=\"demo.js\"></script>\n<script src=\"bridge.js\"></script>");
                in = new ByteArrayInputStream(html.getBytes(StandardCharsets.UTF_8));
            }
            return response(200, mime(name), in);
        } catch (IOException e) {
            return error(404, "not_found");
        }
    }

    /**
     * Položeno: dashboard je složen za 1920 × 1080 CSS px – viewport tolike širine (ili šire, da stane i visina).
     * Uspravno: widgeti su jedan ispod drugog (android-bridge.js), pa je viewport uži i stranica se pomiče.
     */
    /*
     * Slike (logo, zaglavlje, crtež) spremaju se na uređaj. Dashboard ih traži s oznakom inačice (?v=vrijeme promjene
     * na poslužitelju), pa se s poslužitelja preuzimaju samo kad se promijene; starija inačica iste slike se briše.
     */
    private File imageFile(String path, String target) {
        String kind = path.substring(path.lastIndexOf('/') + 1);
        return new File(new File(getFilesDir(), "images"), kind + "-" + Integer.toHexString(target.hashCode()));
    }

    private Cached readImage(String path, String target) {
        File f = imageFile(path, target), t = new File(f.getPath() + ".type");
        if (!f.isFile() || !t.isFile()) return null;
        try {
            return new Cached(new String(java.nio.file.Files.readAllBytes(t.toPath()), StandardCharsets.UTF_8),
                    java.nio.file.Files.readAllBytes(f.toPath()));
        } catch (IOException e) {
            return null;
        }
    }

    private void clearImages() {
        images.evictAll();
        File[] files = new File(getFilesDir(), "images").listFiles();
        if (files != null) for (File f : files) //noinspection ResultOfMethodCallIgnored
            f.delete();
    }

    private void writeImage(String path, String target, ServerClient.Fetched img) {
        File f = imageFile(path, target), dir = f.getParentFile();
        if (dir == null || (!dir.isDirectory() && !dir.mkdirs())) return;
        String kind = f.getName().substring(0, f.getName().lastIndexOf('-') + 1);
        File[] old = dir.listFiles((d, n) -> n.startsWith(kind) && !n.startsWith(f.getName()));
        if (old != null) for (File o : old) o.delete();
        try {
            java.nio.file.Files.write(f.toPath(), img.body());
            java.nio.file.Files.write(new File(f.getPath() + ".type").toPath(), img.type().getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            f.delete(); // bez spremanja – slika se preuzme sljedeći put
        }
    }

    private String viewport() {
        return "<meta name=\"viewport\" content=\"width=" + cssWidth() + ", user-scalable=no\">";
    }

    private int cssWidth() {
        int w = web.getWidth(), h = web.getHeight();
        if (w <= 0 || h <= 0) { // prvo učitavanje prije rasporeda – veličina zaslona
            w = Math.max(1, getResources().getDisplayMetrics().widthPixels);
            h = Math.max(1, getResources().getDisplayMetrics().heightPixels);
        }
        // širina ekrana u dp: slova i dodirne površine prirodne veličine (raspored je mobilni – android-bridge.js)
        return Math.max(320, Math.round(w / getResources().getDisplayMetrics().density));
    }

    private WebResourceResponse proxy(String path, String query) {
        if (prefs.demo()) return demoResponse(path);
        String base = prefs.serverUrl();
        if (!prefs.loggedIn()) return error(401, "not_logged_in");
        String target = base + path + (query == null ? "" : "?" + query);
        boolean image = path.startsWith("/api/v1/images/");
        if (image && query != null) {
            Cached c = images.get(target);
            if (c == null) c = readImage(path, target);
            if (c != null) {
                images.put(target, c);
                return response(200, ServerClient.safeType(path, c.type), new ByteArrayInputStream(c.body));
            }
        }
        try {
            ServerClient.Fetched f = ServerClient.request(base, path + (query == null ? "" : "?" + query), "GET", prefs.token(), null, prefs.certPin());
            if (image && f.status() == 200 && query != null) {
                images.put(target, new Cached(f.type(), f.body()));
                writeImage(path, target, f);
            }
            return response(f.status(), ServerClient.safeType(path, f.type()), new ByteArrayInputStream(f.body()));
        } catch (ServerClient.ServerException e) {
            return error(495, e.getMessage());  // npr. promijenjen certifikat – poruka za korisnika
        } catch (IOException e) {
            return error(502, e instanceof SocketTimeoutException ? "timeout" : "unreachable");
        }
    }

    private static byte[] readAll(InputStream in, int max) throws IOException {
        try (in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[16 * 1024];
            for (int n; (n = in.read(buf)) > 0; ) {
                out.write(buf, 0, n);
                if (out.size() > max) throw new IOException("too large");
            }
            return out.toByteArray();
        }
    }

    /** Poništi oznaku na poslužitelju (ne baca – bez mreže oznaka sama istekne). */
    private void logoutQuietly() {
        if (!prefs.loggedIn()) return;
        try {
            ServerClient.request(prefs.serverUrl(), "/api/v1/logout", "POST", prefs.token(), "{}", prefs.certPin());
        } catch (IOException e) {
            // bez veze: oznaka istječe nakon 30 dana nekorištenja
        }
    }

    private static WebResourceResponse response(int status, String contentType, InputStream body) {
        String type = contentType, charset = null;
        int semi = contentType.indexOf(';');
        if (semi >= 0) {
            type = contentType.substring(0, semi).trim();
            int cs = contentType.indexOf("charset=");
            if (cs >= 0) charset = contentType.substring(cs + 8).trim();
        }
        Map<String, String> headers = new HashMap<>();
        headers.put("Cache-Control", "no-store");
        headers.put("X-Content-Type-Options", "nosniff");
        String reason = status < 300 ? "OK" : status == 401 ? "Unauthorized" : status == 404 ? "Not Found" : status == 495 ? "Certificate" : "Error";
        return new WebResourceResponse(type, charset, status, reason, headers, body);
    }

    private static WebResourceResponse error(int status, String code) {
        byte[] body = ("{\"error\":" + JSONObject.quote(code) + "}").getBytes(StandardCharsets.UTF_8);
        return response(status, "application/json; charset=utf-8", new ByteArrayInputStream(body));
    }

    private static String mime(String name) {
        if (name.endsWith(".html")) return "text/html; charset=utf-8";
        if (name.endsWith(".js")) return "text/javascript; charset=utf-8";
        if (name.endsWith(".css")) return "text/css; charset=utf-8";
        if (name.endsWith(".json")) return "application/json; charset=utf-8";
        if (name.endsWith(".png")) return "image/png";
        if (name.endsWith(".jpg") || name.endsWith(".jpeg")) return "image/jpeg";
        if (name.endsWith(".svg")) return "image/svg+xml";
        if (name.endsWith(".ttf")) return "font/ttf";
        return "application/octet-stream";
    }

    private String version() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (PackageManager.NameNotFoundException e) {
            return "";
        }
    }

    private void callback(String id, JSONObject result) {
        String js = "window.__solariCallback && window.__solariCallback(" + JSONObject.quote(id) + ", " + result + ")";
        runOnUiThread(() -> web.evaluateJavascript(js, null));
    }

    private static JSONObject result(boolean ok, String message) {
        JSONObject o = new JSONObject();
        try {
            o.put("ok", ok);
            o.put("message", message);
        } catch (JSONException ignored) {
            // ključevi su fiksni
        }
        return o;
    }

    @Override
    protected void onActivityResult(int request, int code, Intent data) {
        super.onActivityResult(request, code, data);
        if (request != REQ_SAVE_CSV || pendingCsvCallback == null) return;
        String cb = pendingCsvCallback, text = pendingCsv;
        pendingCsvCallback = null;
        pendingCsv = null;
        if (code != RESULT_OK || data == null || data.getData() == null) {
            callback(cb, result(true, ""));
            return;
        }
        try (OutputStream out = getContentResolver().openOutputStream(data.getData())) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            callback(cb, result(true, "Spremljeno."));
        } catch (IOException | NullPointerException e) {
            callback(cb, result(false, "Datoteka nije spremljena."));
        }
    }

    // ------------------------------------------------------------------ most JavaScript → Android
    private final class Bridge {
        @JavascriptInterface
        public String getSettings() {
            try {
                return prefs.toJson(version()).toString();
            } catch (JSONException e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public String saveSettings(String json) {
            if (!onSettingsPage()) return result(false, "Nije dopušteno.").toString();
            try {
                JSONObject res = prefs.save(new JSONObject(json));
                runOnUiThread(MainActivity.this::applyKeepOn);
                return res.toString();
            } catch (JSONException | IllegalStateException e) {
                return result(false, "Postavke nisu spremljene.").toString();
            }
        }

        /** Prijava na poslužitelj (adresa iz obrasca) – lozinka ide samo poslužitelju; odgovor na __solariCallback. */
        @JavascriptInterface
        public void login(String json, String callbackId) {
            if (!onSettingsPage()) { callback(callbackId, result(false, "Nije dopušteno.")); return; }
            io.execute(() -> {
                try {
                    JSONObject f = new JSONObject(json);
                    String url = Prefs.normalize(f.optString("url"));
                    if (url == null || url.isEmpty()) {
                        callback(callbackId, result(false, "Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr"));
                        return;
                    }
                    ServerClient.Login l = ServerClient.login(url, f.optString("email"), f.optString("password"), prefs.knownPin(url),
                                                              f.optString("totp"), f.optString("new_password"), f.optString("pairing_code"));
                    logoutQuietly();  // prethodna prijava ne ostaje aktivna na poslužitelju
                    prefs.setLogin(url, l.token(), l.account(), l.pin());
                    JSONObject ok = result(true, "Prijavljeni ste kao {name}.");
                    ok.put("name", l.account().optString("name"));
                    ok.put("account", l.account());
                    ok.put("pin", l.pin());
                    ok.put("url", url);
                    if (l.recoveryCodes() != null) ok.put("recovery_codes", l.recoveryCodes());
                    callback(callbackId, ok);
                } catch (ServerClient.PairingNeeded e) {
                    JSONObject need = result(false, e.getMessage());
                    try { need.put("pairing", true); } catch (JSONException ignored) { /* ne može se dogoditi */ }
                    callback(callbackId, need);
                } catch (ServerClient.PasswordChange e) {
                    JSONObject need = result(false, e.getMessage());
                    try { need.put("password_change", true); } catch (JSONException ignored) { /* ne može se dogoditi */ }
                    callback(callbackId, need);
                } catch (ServerClient.TotpNeeded e) {
                    JSONObject need = result(false, e.getMessage());
                    try { need.put("totp", e.info); } catch (JSONException ignored) { /* ne može se dogoditi */ }
                    callback(callbackId, need);
                } catch (ServerClient.ServerException e) {
                    callback(callbackId, result(false, e.getMessage()));
                } catch (SocketTimeoutException e) {
                    callback(callbackId, result(false, "Poslužitelj ne odgovara."));
                } catch (IOException e) {
                    callback(callbackId, result(false, "Nije moguće spojiti se na poslužitelj."));
                } catch (JSONException e) {
                    callback(callbackId, result(false, "Odgovor nije od Solarnog poslužitelja – provjerite adresu."));
                }
            });
        }

        /** Zaboravljena lozinka: kod e-poštom (reset = false) ili nova lozinka uz kod (reset = true); odgovor na __solariCallback. */
        private void passwordFlow(String json, String callbackId, boolean reset) {
            if (!onSettingsPage()) { callback(callbackId, result(false, "Nije dopušteno.")); return; }
            io.execute(() -> {
                try {
                    JSONObject f = new JSONObject(json);
                    String url = Prefs.normalize(f.optString("url"));
                    if (url == null || url.isEmpty()) {
                        callback(callbackId, result(false, "Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr"));
                        return;
                    }
                    String message = reset
                            ? ServerClient.resetPassword(url, f.optString("email"), f.optString("code"), f.optString("new_password"),
                                                         prefs.knownPin(url), f.optString("pairing_code"))
                            : ServerClient.forgotPassword(url, f.optString("email"), prefs.knownPin(url), f.optString("pairing_code"));
                    callback(callbackId, result(true, message));
                } catch (ServerClient.PairingNeeded e) {
                    JSONObject need = result(false, e.getMessage());
                    try { need.put("pairing", true); } catch (JSONException ignored) { /* ne može se dogoditi */ }
                    callback(callbackId, need);
                } catch (ServerClient.PasswordChange | ServerClient.ServerException e) {
                    callback(callbackId, result(false, e.getMessage()));
                } catch (SocketTimeoutException e) {
                    callback(callbackId, result(false, "Poslužitelj ne odgovara."));
                } catch (IOException e) {
                    callback(callbackId, result(false, "Nije moguće spojiti se na poslužitelj."));
                } catch (JSONException e) {
                    callback(callbackId, result(false, "Odgovor nije od Solarnog poslužitelja – provjerite adresu."));
                }
            });
        }

        @JavascriptInterface
        public void forgotPassword(String json, String callbackId) { passwordFlow(json, callbackId, false); }

        @JavascriptInterface
        public void resetPassword(String json, String callbackId) { passwordFlow(json, callbackId, true); }

        /** Otvara otpauth:// u aplikaciji autentifikatoru na istom mobitelu (QR kod se ne može skenirati sam sobom). */
        @JavascriptInterface
        public boolean openAuthenticator(String uri) {
            if (!onSettingsPage()) return false;
            if (uri == null || !uri.startsWith("otpauth://totp/")) return false;
            try {
                startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(uri)));
                return true;
            } catch (android.content.ActivityNotFoundException e) {
                return false;
            }
        }

        @JavascriptInterface
        public void logout(String callbackId) {
            if (!onSettingsPage()) { callback(callbackId, result(false, "Nije dopušteno.")); return; }
            io.execute(() -> {
                logoutQuietly();
                prefs.clearLogin();
                clearImages();  // audit A-08: slike prethodnog poslužitelja ne ostaju na uređaju
                callback(callbackId, result(true, "Odjavljeni ste."));
            });
        }

        @JavascriptInterface
        public boolean isFullscreen() { return fullscreen; }

        /** Koliko CSS px stane u jedan dp – gumbi izbornika (android-menu.js) iste su fizičke veličine na svakom uređaju. */
        @JavascriptInterface
        public double cssPerDp() {
            float density = getResources().getDisplayMetrics().density;
            return (double) cssWidth() * density / Math.max(1, web.getWidth());
        }

        @JavascriptInterface
        public boolean setFullscreen(boolean on) {
            runOnUiThread(() -> MainActivity.this.setFullscreen(on));
            fullscreen = on;
            return on;
        }

        /** Noćni način: "ugašen zaslon" je na Androidu najmanja svjetlina uz crni prikaz. */
        @JavascriptInterface
        public void setDisplay(boolean on) {
            runOnUiThread(() -> {
                WindowManager.LayoutParams lp = getWindow().getAttributes();
                lp.screenBrightness = on ? WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE : 0.01f;
                getWindow().setAttributes(lp);
            });
        }

        /** Izvještaj u PDF (Android ispis → Spremi kao PDF). */
        @JavascriptInterface
        public void print(String title) {
            runOnUiThread(() -> {
                PrintManager pm = (PrintManager) getSystemService(PRINT_SERVICE);
                pm.print(title, web.createPrintDocumentAdapter(title),
                        new PrintAttributes.Builder().setMediaSize(PrintAttributes.MediaSize.ISO_A4).build());
            });
        }

        /** CSV za Excel: korisnik bira mjesto spremanja (bez dodatnih dozvola). */
        @JavascriptInterface
        public void saveCsv(String filename, String text, String callbackId) {
            runOnUiThread(() -> {
                pendingCsv = text;
                pendingCsvCallback = callbackId;
                Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                        .setType("text/csv").putExtra(Intent.EXTRA_TITLE, filename);
                startActivityForResult(i, REQ_SAVE_CSV);
            });
        }

        @JavascriptInterface
        public void openDashboard() { runOnUiThread(() -> web.loadUrl(START)); }

        @JavascriptInterface
        public void exit() { runOnUiThread(MainActivity.this::finish); }
    }
}

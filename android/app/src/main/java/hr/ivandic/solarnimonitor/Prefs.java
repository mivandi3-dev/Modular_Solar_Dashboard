package hr.ivandic.solarnimonitor;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Postavke aplikacije. 3.0: umjesto API ključa korisnik se prijavi e-poštom i lozinkom; lozinka se nigdje ne sprema,
 * a oznaka prijave i podaci o računu spremaju se šifrirani ključem iz Android Keystorea (AES-GCM) – ključ za
 * šifriranje nikad ne napušta uređaj, a sigurnosna kopija aplikacije je isključena.
 */
final class Prefs {
    static final String[] LANGUAGES = {"hr", "en", "de", "fr", "it", "es", "tr", "zh", "ja", "ko"};
    private static final String KEY_ALIAS = "solari_api_key";
    private static final Pattern URL = Pattern.compile(
            "^https?://([A-Za-z0-9.-]+|\\[[0-9A-Fa-f:]+\\])(:\\d{1,5})?(/[A-Za-z0-9._~/-]*)?$");
    private static final Pattern TIME = Pattern.compile("^([01]\\d|2[0-3]):[0-5]\\d$");
    // palete boja – isti popis kao PALETTES u web/colors.js ("" = boje same teme)
    static final String[] ICON_THEMES = {"classic", "neon", "iconset"};
    static final String[] PALETTES = {"", "ocean", "forest", "sunset", "midnight", "graphite", "contrast", "paper", "sky", "sand"};

    private final SharedPreferences sp;

    Prefs(Context context) {
        sp = context.getSharedPreferences("solari", Context.MODE_PRIVATE);
    }

    String mode() { return sp.getString("mode", "cloud"); }
    String serverUrl() { return sp.getString("cloud".equals(mode()) ? "cloud_url" : "local_url", ""); }
    String language() { return sp.getString("language", defaultLanguage()); }
    boolean keepScreenOn() { return sp.getBoolean("keep_on", true); }
    boolean startFullscreen() { return sp.getBoolean("start_fullscreen", true); }
    boolean demo() { return "demo".equals(mode()); }  // primjer podataka bez poslužitelja (web/demo.js)
    boolean configured() { return demo() || loggedIn(); }
    /** Prijava vrijedi samo za adresu na koju je izdana. */
    boolean loggedIn() { return !serverUrl().isEmpty() && serverUrl().equals(sp.getString("login_url", "")) && !token().isEmpty(); }
    String certPin() { return loggedIn() ? sp.getString("cert_pin", "") : ""; }
    String loginUrl() { return sp.getString("login_url", ""); }
    String knownPin(String url) { return url.equals(sp.getString("login_url", "")) ? sp.getString("cert_pin", "") : ""; }

    String token() { return decrypt(sp.getString("token_enc", "")); }

    JSONObject account() {
        try {
            return loggedIn() ? new JSONObject(decrypt(sp.getString("account_enc", ""))) : null;
        } catch (JSONException e) {
            return null;
        }
    }

    void setLogin(String url, String token, JSONObject account, String pin) {
        sp.edit().putString("login_url", url).putString("token_enc", encrypt(token)).putString("account_enc", encrypt(account.toString()))
                .putString("cert_pin", pin).remove("api_key_enc").apply();
    }

    void clearLogin() { sp.edit().remove("token_enc").remove("account_enc").apply(); }

    static String defaultLanguage() {
        String sys = Locale.getDefault().getLanguage();
        return Arrays.asList(LANGUAGES).contains(sys) ? sys : "en";
    }

    /** Postavke za stranicu postavki i most (bez ključa – samo je li postavljen). */
    JSONObject toJson(String version) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("mode", mode());
        o.put("cloud_url", sp.getString("cloud_url", ""));
        o.put("local_url", sp.getString("local_url", ""));
        o.put("account", account() == null ? JSONObject.NULL : account());
        o.put("cert_pin", certPin());
        o.put("language", language());
        o.put("theme", sp.getString("theme", "dark"));
        o.put("palette", sp.getString("palette", ""));
        o.put("icon_theme", sp.getString("icon_theme", "classic"));
        o.put("forecast_days", sp.getInt("forecast_days", 5));
        o.put("night_mode", sp.getString("night_mode", "off"));
        o.put("night_from", sp.getString("night_from", "22:00"));
        o.put("night_to", sp.getString("night_to", "06:00"));
        o.put("keep_on", keepScreenOn());
        o.put("start_fullscreen", startFullscreen());
        o.put("version", version);
        return o;
    }

    /** Provjera i spremanje obrasca; vraća {ok, errors:{polje: poruka}} (poruke su hrvatski ključevi za T()). */
    JSONObject save(JSONObject f) throws JSONException {
        JSONObject errors = new JSONObject();
        String requested = f.optString("mode");
        String mode = "local".equals(requested) ? "local" : "demo".equals(requested) ? "demo" : "cloud";
        String cloudUrl = normalize(f.optString("cloud_url"));
        String localUrl = normalize(f.optString("local_url"));
        String active = "cloud".equals(mode) ? cloudUrl : localUrl;
        if (!"demo".equals(mode) && (active == null || active.isEmpty())) errors.put("cloud".equals(mode) ? "cloud_url" : "local_url", "Upišite adresu poslužitelja, npr. https://solar.tvrtka.hr");
        boolean loginFor = active != null && !active.isEmpty() && active.equals(sp.getString("login_url", "")) && !token().isEmpty();
        if (!"demo".equals(mode) && active != null && !active.isEmpty() && !loginFor) errors.put("login", "Prijavite se na poslužitelj (e-pošta i lozinka).");
        String lang = f.optString("language", language());
        if (!Arrays.asList(LANGUAGES).contains(lang)) errors.put("language", "Nepoznat jezik.");
        String night = f.optString("night_mode", "off");
        if (!Arrays.asList("off", "dim", "screen_off").contains(night)) errors.put("night_mode", "Nepoznat noćni način.");
        for (String k : new String[] {"night_from", "night_to"}) {
            if (!TIME.matcher(f.optString(k)).matches()) errors.put(k, "Upišite vrijeme kao SS:MM, npr. 22:00.");
        }
        int days = f.optInt("forecast_days", 5);
        if (days != 2 && days != 3 && days != 5) errors.put("forecast_days", "Izaberite 2, 3 ili 5 dana.");
        String palette = f.optString("palette", "");
        if ("dark".equals(palette) || "light".equals(palette)) palette = "";  // boje same teme
        if (!Arrays.asList(PALETTES).contains(palette)) errors.put("palette", "Nepoznata tema.");
        String iconTheme = f.optString("icon_theme", "classic");  // web/icons.js: classic | neon | iconset
        if (!Arrays.asList(ICON_THEMES).contains(iconTheme)) errors.put("icon_theme", "Nepoznata tema ikona.");
        JSONObject out = new JSONObject();
        if (errors.length() > 0) {
            out.put("ok", false);
            out.put("errors", errors);
            return out;
        }
        SharedPreferences.Editor e = sp.edit()
                .putString("mode", mode)
                .putString("cloud_url", cloudUrl == null ? "" : cloudUrl)
                .putString("local_url", localUrl == null ? "" : localUrl)
                .putString("language", lang)
                .putString("theme", "light".equals(f.optString("theme")) ? "light" : "dark")
                .putString("night_mode", night)
                .putString("night_from", f.optString("night_from"))
                .putString("night_to", f.optString("night_to"))
                .putBoolean("keep_on", f.optBoolean("keep_on", true))
                .putBoolean("start_fullscreen", f.optBoolean("start_fullscreen", true))
                .putString("palette", palette)
                .putString("icon_theme", iconTheme)
                .putInt("forecast_days", days);
        e.remove("api_key_enc").apply();  // API ključ (do 2.x) više se ne koristi
        out.put("ok", true);
        return out;
    }

    /** "https://solar.tvrtka.hr/" → "https://solar.tvrtka.hr"; prazno → ""; neispravno → null. */
    static String normalize(String url) {
        String u = url == null ? "" : url.trim();
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        if (u.isEmpty()) return "";
        if (!URL.matcher(u).matches()) return null;
        // 3.0: poslužitelj u mreži je samo HTTPS (obični http samo na istom uređaju)
        if (u.startsWith("http://") && !ServerClient.isLoopback(u)) u = "https://" + u.substring(7);
        return u;
    }

    private static String decrypt(String enc) {
        if (enc.isEmpty()) return "";
        try {
            byte[] all = Base64.decode(enc, Base64.NO_WRAP);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, secretKey(), new GCMParameterSpec(128, Arrays.copyOfRange(all, 0, 12)));
            return new String(c.doFinal(Arrays.copyOfRange(all, 12, all.length)), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            return "";  // npr. ključ Keystorea je obrisan – korisnik se ponovno prijavi
        }
    }

    private static String encrypt(String text) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, secretKey());
            byte[] iv = c.getIV();
            byte[] data = c.doFinal(text.getBytes(StandardCharsets.UTF_8));
            byte[] all = new byte[iv.length + data.length];
            System.arraycopy(iv, 0, all, 0, iv.length);
            System.arraycopy(data, 0, all, iv.length, data.length);
            return Base64.encodeToString(all, Base64.NO_WRAP);
        } catch (Exception ex) {
            throw new IllegalStateException("Android Keystore", ex);
        }
    }

    private static SecretKey secretKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) return ((KeyStore.SecretKeyEntry) ks.getEntry(KEY_ALIAS, null)).getSecretKey();
        KeyGenerator gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        gen.init(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return gen.generateKey();
    }
}

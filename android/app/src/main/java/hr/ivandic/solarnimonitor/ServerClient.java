package hr.ivandic.solarnimonitor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Veza sa Solarnim poslužiteljem 3.0 (prijava korisnika umjesto API ključa).
 *
 * Poslužitelj u lokalnoj mreži ima vlastiti certifikat: aplikacija pamti njegov otisak (SHA-256) pri prvoj prijavi
 * i provjerava ga u TrustManageru, dakle tijekom TLS rukovanja – prije nego što se pošalje ijedan bajt zahtjeva
 * (lozinka ili oznaka prijave). Javne adrese (Cloudflare tunel) provjeravaju se uobičajeno, preko izdavača.
 */
final class ServerClient {
    static final int TIMEOUT_MS = 15_000;
    static final int MAX_BODY = 25 * 1024 * 1024;

    record Fetched(int status, String type, byte[] body, String certPin) {}

    record Login(String token, String pin, JSONObject account, org.json.JSONArray recoveryCodes) {}

    /** Greška za korisnika (hrvatski ključ za T() u sučelju). */
    static final class ServerException extends IOException {
        ServerException(String message) { super(message); }
    }

    /** Prijava aktivacijskim kodom (4.0) ili nova lozinka ne zadovoljava pravila – treba vlastita lozinka (new_password). */
    static final class PasswordChange extends IOException {
        PasswordChange(String message) { super(message); }
    }

    /** Lozinka je točna, a račun ima dvofaktorsku prijavu: treba kod (step "code") ili postavljanje ("setup" + QR). */
    static final class TotpNeeded extends IOException {
        final JSONObject info;
        TotpNeeded(String message, JSONObject info) { super(message); this.info = info; }
    }

    private ServerClient() {}

    /** https na IP adresu, localhost, ime bez točke ili .local/.lan/.home/.internal → provjera otiska. */
    static boolean pinnedHost(String baseUrl) {
        if (!baseUrl.startsWith("https://")) return false;
        String host = baseUrl.substring(8);
        int end = host.length();
        for (char c : new char[] {':', '/'}) { int i = host.indexOf(c); if (i >= 0) end = Math.min(end, i); }
        host = host.substring(0, end);
        if (host.isEmpty() || host.startsWith("[") || host.equals("localhost") || host.matches("[\\d.]+") || !host.contains(".")) return true;
        for (String s : new String[] {".local", ".lan", ".home", ".internal"}) if (host.endsWith(s)) return true;
        return false;
    }

    /** Provjera otiska tijekom rukovanja; expected="" samo za /ping (bez tajni) – otisak se tada samo zapiše. */
    private static final class PinTrust implements X509TrustManager {
        final String expected;
        String seen = "";
        PinTrust(String expected) { this.expected = expected; }

        @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (chain == null || chain.length == 0) throw new CertificateException("no certificate");
            seen = fingerprint(chain[0].getEncoded());
            if (!expected.isEmpty() && !expected.equals(seen)) throw new CertificateException("pin mismatch");
        }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("client");
        }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static String fingerprint(byte[] der) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(der);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < d.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", d[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    static Fetched request(String base, String path, String method, String token, String body, String pin) throws IOException {
        boolean secret = !token.isEmpty() || body != null;
        boolean pinned = pinnedHost(base);
        if (!base.startsWith("https://") && secret && !isLoopback(base)) throw new ServerException("Poslužitelj u mreži mora imati adresu https://.");
        if (pinned && secret && pin.isEmpty()) throw new ServerException("Prijavite se na poslužitelj (e-pošta i lozinka).");
        HttpURLConnection c = (HttpURLConnection) new URL(base + path).openConnection();
        PinTrust trust = null;
        if (pinned && c instanceof HttpsURLConnection https) {
            try {
                trust = new PinTrust(pin);
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[] {trust}, null);
                https.setSSLSocketFactory(ctx.getSocketFactory());
                https.setHostnameVerifier((h, s) -> true);  // umjesto imena provjerava se otisak (gore)
            } catch (Exception e) {
                throw new IOException("TLS", e);
            }
        }
        try {
            c.setConnectTimeout(TIMEOUT_MS);
            c.setReadTimeout(TIMEOUT_MS);
            c.setInstanceFollowRedirects(false);  // oznaka se ne šalje na drugu adresu
            c.setUseCaches(false);
            c.setRequestMethod(method);
            c.setRequestProperty("Accept", "application/json, image/*");
            if (!token.isEmpty()) c.setRequestProperty("Authorization", "Bearer " + token);
            if (body != null) {
                byte[] b = body.getBytes(StandardCharsets.UTF_8);
                c.setDoOutput(true);
                c.setFixedLengthStreamingMode(b.length);
                c.setRequestProperty("Content-Type", "application/json");
                try (OutputStream out = c.getOutputStream()) { out.write(b); }
            }
            int status = c.getResponseCode();
            InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
            byte[] data = in == null ? new byte[0] : readAll(in, MAX_BODY);
            String type = c.getContentType() == null ? "application/octet-stream" : c.getContentType();
            return new Fetched(status, type, data, trust == null ? "" : trust.seen);
        } catch (javax.net.ssl.SSLException e) {
            if (trust != null && !trust.expected.isEmpty() && !trust.seen.isEmpty() && !trust.expected.equals(trust.seen)) {
                throw new ServerException("Certifikat poslužitelja se promijenio – veza je prekinuta prije slanja podataka. Ako ste ponovno instalirali poslužitelj, prijavite se ponovno; inače netko u mreži možda presreće promet.");
            }
            throw new ServerException("Sigurna veza (HTTPS) s poslužiteljem nije uspjela.");
        } finally {
            c.disconnect();
        }
    }

    static boolean isLoopback(String base) {
        return base.startsWith("http://127.0.0.1") || base.startsWith("http://localhost");
    }

    /** /ping (otisak), zatim /login samo poslužitelju s istim otiskom. knownPin: otisak od prije (ista adresa). */
    static Login login(String base, String email, String password, String knownPin, String totp, String newPassword) throws IOException {
        Fetched p = request(base, "/api/v1/ping", "GET", "", null, knownPin);
        JSONObject info;
        try {
            info = new JSONObject(new String(p.body(), StandardCharsets.UTF_8));
        } catch (JSONException e) {
            throw new ServerException("Odgovor nije od Solarnog poslužitelja – provjerite adresu.");
        }
        if (p.status() != 200 || info.optInt("api", 0) < 3) throw new ServerException("Poslužitelj je stare verzije – instalirajte Solarni poslužitelj 3.0.");
        if (!info.optBoolean("setup", false)) throw new ServerException("Poslužitelj još nema administratora – otvorite Solarni poslužitelj i izradite ga.");
        String pin = pinnedHost(base) ? p.certPin() : "";
        String body;
        try {
            body = new JSONObject().put("email", email.trim()).put("password", password).put("device", "Solarni monitor (Android)")
                    .put("totp", totp == null ? "" : totp.trim()).put("new_password", newPassword == null ? "" : newPassword).toString();
        } catch (JSONException e) {
            throw new IOException(e);
        }
        Fetched r = request(base, "/api/v1/login", "POST", "", body, pin);
        if (r.status() == 401 || r.status() == 400) {
            try {
                JSONObject e = new JSONObject(new String(r.body(), StandardCharsets.UTF_8));
                String err = e.optString("error");
                if ("activation_required".equals(err)) throw new PasswordChange("Aktivacijski kod je točan – postavite svoju lozinku.");
                if ("password_invalid".equals(err)) throw new PasswordChange(e.optString("message", "Nova lozinka ne zadovoljava pravila."));
                /* 4.0: istek aktivacijskog koda javlja se kao pogrešna lozinka */
                if (err.startsWith("totp_")) {
                    boolean setup = "totp_setup".equals(err) || e.has("uri");
                    JSONObject need = new JSONObject().put("step", setup ? "setup" : "code").put("invalid", "totp_invalid".equals(err));
                    if (e.has("uri")) need.put("secret", e.optString("secret")).put("uri", e.optString("uri"));
                    throw new TotpNeeded("totp_invalid".equals(err) ? "Kod nije točan ili je već iskorišten."
                            : setup ? "Skenirajte QR kod aplikacijom autentifikatorom i upišite prikazani kod."
                                    : "Upišite kod iz aplikacije autentifikatora.", need);
                }
            } catch (JSONException ignored) {
                // tijelo nije JSON – obična pogreška prijave
            }
            throw new ServerException("Pogrešna e-pošta ili lozinka.");
        }
        if (r.status() == 423) throw new ServerException("Previše pogrešnih lozinki – račun je privremeno zaključan (15 minuta).");
        if (r.status() == 403) throw new ServerException("Račun je blokiran – obratite se administratoru poslužitelja.");
        if (r.status() == 429) throw new ServerException("Previše pogrešnih pokušaja – pokušajte ponovno za nekoliko minuta.");
        try {
            JSONObject j = new JSONObject(new String(r.body(), StandardCharsets.UTF_8));
            if (r.status() != 200 || !j.has("token")) throw new ServerException("Poslužitelj je vratio grešku {code}.");
            JSONObject u = j.optJSONObject("user");
            JSONObject account = new JSONObject()
                    .put("email", u == null ? "" : u.optString("email"))
                    .put("name", u == null ? "" : (u.optString("first_name") + " " + u.optString("last_name")).trim())
                    .put("role", u == null ? "user" : u.optString("role", "user"));
            return new Login(j.getString("token"), pin, account, j.optJSONArray("recovery_codes"));
        } catch (JSONException e) {
            throw new ServerException("Odgovor nije od Solarnog poslužitelja – provjerite adresu.");
        }
    }

    static byte[] readAll(InputStream in, int max) throws IOException {
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
}

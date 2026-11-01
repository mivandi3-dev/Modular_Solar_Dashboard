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

    /** 4.0 (SMA-04): poslužitelj u lokalnoj mreži još nije uparen – treba kod za uparivanje s prozora poslužitelja. */
    static final class PairingNeeded extends IOException {
        PairingNeeded(String message) { super(message); }
    }

    /** Kod za uparivanje: prvih 60 bita SHA-256 otiska ("AB:CD:…") u base32 → "XXXX-XXXX-XXXX"; "" za neispravan otisak. */
    static String pairingCode(String fingerprint) {
        String[] parts = fingerprint == null ? new String[0] : fingerprint.split(":");
        if (parts.length != 32) return "";
        byte[] first = new byte[8];
        try {
            for (int i = 0; i < 8; i++) first[i] = (byte) Integer.parseInt(parts[i], 16);
        } catch (NumberFormatException e) {
            return "";
        }
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder b32 = new StringBuilder();
        int buffer = 0, bits = 0;
        for (byte x : first) {
            buffer = (buffer << 8) | (x & 0xFF);
            bits += 8;
            while (bits >= 5 && b32.length() < 12) {
                b32.append(alphabet.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        return b32.substring(0, 4) + "-" + b32.substring(4, 8) + "-" + b32.substring(8, 12);
    }

    /** Upisani kod (mala/velika slova, s crticama ili bez) odgovara otisku – usporedba u stalnom vremenu. */
    static boolean pairingMatches(String entered, String fingerprint) {
        String expected = pairingCode(fingerprint).replace("-", "");
        String given = entered == null ? "" : entered.replace("-", "").replace(" ", "").toUpperCase(java.util.Locale.ROOT);
        return !expected.isEmpty() && MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), given.getBytes(StandardCharsets.US_ASCII));
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
        return login(base, email, password, knownPin, totp, newPassword, "");
    }

    static Login login(String base, String email, String password, String knownPin, String totp, String newPassword,
                       String enteredPairingCode) throws IOException {
        Fetched p = request(base, "/api/v1/ping", "GET", "", null, knownPin);
        JSONObject info;
        try {
            info = new JSONObject(new String(p.body(), StandardCharsets.UTF_8));
        } catch (JSONException e) {
            throw new ServerException("Odgovor nije od Solarnog poslužitelja – provjerite adresu.");
        }
        if (p.status() != 200 || info.optInt("api", 0) < 4) throw new ServerException("Poslužitelj nije verzije 4.0 – instalirajte Solarni poslužitelj 4.0.");
        if (!info.optBoolean("setup", false)) throw new ServerException("Poslužitelj još nema administratora – otvorite Solarni poslužitelj i izradite ga.");
        String pin = pinnedHost(base) ? p.certPin() : "";
        // SMA-04: prvi kontakt u lokalnoj mreži – otisak se potvrđuje kodom s prozora poslužitelja; bez toga se lozinka ne šalje
        if (pinnedHost(base) && (knownPin == null || knownPin.isEmpty()) && !pairingMatches(enteredPairingCode, pin)) {
            throw new PairingNeeded(enteredPairingCode == null || enteredPairingCode.trim().isEmpty()
                    ? "Upišite kod za uparivanje s prozora Solarnog poslužitelja (Postavke → Poslužitelj)."
                    : "Kod za uparivanje ne odgovara certifikatu poslužitelja – provjerite kod i adresu (moguće presretanje veze).");
        }
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

    /** /ping (verzija 4) i SMA-04 uparivanje – isto kao prijava; vraća otisak za sljedeći poziv ("" = javni certifikat). */
    static String confirmedPin(String base, String knownPin, String enteredPairingCode) throws IOException {
        Fetched p = request(base, "/api/v1/ping", "GET", "", null, knownPin);
        JSONObject info;
        try {
            info = new JSONObject(new String(p.body(), StandardCharsets.UTF_8));
        } catch (JSONException e) {
            throw new ServerException("Odgovor nije od Solarnog poslužitelja – provjerite adresu.");
        }
        if (p.status() != 200 || info.optInt("api", 0) < 4) throw new ServerException("Poslužitelj nije verzije 4.0 – instalirajte Solarni poslužitelj 4.0.");
        String pin = pinnedHost(base) ? p.certPin() : "";
        if (pinnedHost(base) && (knownPin == null || knownPin.isEmpty()) && !pairingMatches(enteredPairingCode, pin)) {
            throw new PairingNeeded(enteredPairingCode == null || enteredPairingCode.trim().isEmpty()
                    ? "Upišite kod za uparivanje s prozora Solarnog poslužitelja (Postavke → Poslužitelj)."
                    : "Kod za uparivanje ne odgovara certifikatu poslužitelja – provjerite kod i adresu (moguće presretanje veze).");
        }
        return pin;
    }

    private static JSONObject jsonBody(Fetched r) throws ServerException {
        try {
            return new JSONObject(new String(r.body(), StandardCharsets.UTF_8));
        } catch (JSONException e) {
            throw new ServerException("Odgovor nije od Solarnog poslužitelja – provjerite adresu.");
        }
    }

    /** Zaboravljena lozinka (4.0): kod stiže e-poštom; odgovor je isti za svaku adresu (ne otkriva račun). */
    static String forgotPassword(String base, String email, String knownPin, String pairingCode) throws IOException {
        String e = email == null ? "" : email.trim();
        if (!e.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) throw new ServerException("Upišite e-poštu računa.");
        String pin = confirmedPin(base, knownPin, pairingCode);
        String body;
        try {
            body = new JSONObject().put("email", e).toString();
        } catch (JSONException x) {
            throw new IOException(x);
        }
        Fetched r = request(base, "/api/v1/forgot_password", "POST", "", body, pin);
        JSONObject j = jsonBody(r);
        if (r.status() == 429) throw new ServerException("Previše pokušaja – pokušajte ponovno za nekoliko minuta.");
        if (r.status() != 200) throw new ServerException(j.optString("message", "Poslužitelj je vratio grešku."));
        return j.optString("message", "Ako račun s tom adresom postoji, kod je poslan e-poštom. Vrijedi 30 minuta.");
    }

    /** Nova lozinka uz kod iz e-pošte; slaba lozinka → PasswordChange (kod ostaje važeći). */
    static String resetPassword(String base, String email, String code, String newPassword, String knownPin, String pairingCode)
            throws IOException {
        String pin = confirmedPin(base, knownPin, pairingCode);
        String body;
        try {
            body = new JSONObject().put("email", email == null ? "" : email.trim()).put("code", code == null ? "" : code.trim())
                    .put("new_password", newPassword == null ? "" : newPassword).toString();
        } catch (JSONException x) {
            throw new IOException(x);
        }
        Fetched r = request(base, "/api/v1/reset_password", "POST", "", body, pin);
        JSONObject j = jsonBody(r);
        if (r.status() == 200) return j.optString("message", "Nova lozinka je postavljena – prijavite se.");
        if ("password_invalid".equals(j.optString("error"))) throw new PasswordChange(j.optString("message", "Nova lozinka ne zadovoljava pravila."));
        if (r.status() == 429) throw new ServerException("Previše pokušaja – pokušajte ponovno za nekoliko minuta.");
        throw new ServerException(j.optString("message", "Kod nije točan ili je istekao – zatražite novi."));
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

package hr.ivandic.solarnimonitor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.security.keystore.KeyInfo;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

/**
 * 4.0 AT-04 (instrumentirani, na uređaju/emulatoru): oznaka prijave i račun šifrirani ključem iz Android Keystorea
 * (AES-256-GCM, ključ se ne može izvesti), u SharedPreferences nema čitljive oznake, e-pošte ni lozinke; brisanje
 * ključa (npr. promjena zaključavanja zaslona) vodi u ponovnu prijavu, a ne u rušenje; manifest bez sigurnosne kopije.
 */
@RunWith(AndroidJUnit4.class)
public class PrefsKeystoreTest {
    private static final String TOKEN = "tok_ABCdef0123456789-xyz_SAMO_TEST";
    private static final String URL = "https://192.168.1.20:8700";
    private Context ctx;
    private SharedPreferences sp;

    @Before
    public void setUp() throws Exception {
        ctx = InstrumentationRegistry.getInstrumentation().getTargetContext();
        sp = ctx.getSharedPreferences("solari", Context.MODE_PRIVATE);
        sp.edit().clear().commit();
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        ks.deleteEntry("solari_api_key");
    }

    @After
    public void tearDown() {
        sp.edit().clear().commit();
    }

    private void login(Prefs p) throws Exception {
        sp.edit().putString("mode", "local").putString("local_url", URL).commit();
        p.setLogin(URL, TOKEN, new JSONObject().put("email", "ana@primjer.hr").put("name", "Ana"), "AB:CD");
        Thread.sleep(300);  // apply() je asinkron
    }

    @Test
    public void tokenIsEncryptedWithNonExportableKeystoreKey() throws Exception {
        Prefs p = new Prefs(ctx);
        login(p);
        assertTrue(p.loggedIn());
        assertEquals(TOKEN, p.token());
        assertEquals("Ana", p.account().getString("name"));
        for (Map.Entry<String, ?> e : sp.getAll().entrySet()) {
            String v = String.valueOf(e.getValue());
            assertFalse("oznaka u čitljivom obliku: " + e.getKey(), v.contains(TOKEN));
            assertFalse("e-pošta u čitljivom obliku: " + e.getKey(), v.contains("primjer.hr"));
        }
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        assertTrue(ks.containsAlias("solari_api_key"));
        SecretKey key = ((KeyStore.SecretKeyEntry) ks.getEntry("solari_api_key", null)).getSecretKey();
        assertNull("ključ Keystorea se ne smije moći izvesti", key.getEncoded());
        KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore").getKeySpec(key, KeyInfo.class);
        assertEquals(256, info.getKeySize());
        assertFalse(info.isUserAuthenticationRequired());
    }

    @Test
    public void sameTokenEncryptsDifferentlyEachTime() throws Exception {
        Prefs p = new Prefs(ctx);
        login(p);
        String first = sp.getString("token_enc", "");
        login(p);
        String second = sp.getString("token_enc", "");
        assertFalse(first.isEmpty());
        assertFalse("GCM s novim IV-om – isti zapis bi otkrivao istu oznaku", first.equals(second));
    }

    @Test
    public void deletedKeystoreKeyMeansLoginAgainNotCrash() throws Exception {
        Prefs p = new Prefs(ctx);
        login(p);
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        ks.deleteEntry("solari_api_key");
        assertEquals("", p.token());
        assertFalse(p.loggedIn());
        assertNull(p.account());
    }

    @Test
    public void tamperedCiphertextIsRejected() throws Exception {
        Prefs p = new Prefs(ctx);
        login(p);
        String enc = sp.getString("token_enc", "");
        char[] c = enc.toCharArray();
        c[c.length / 2] = c[c.length / 2] == 'A' ? 'B' : 'A';
        sp.edit().putString("token_enc", new String(c)).commit();
        assertEquals("", p.token());
        assertFalse(p.loggedIn());
    }

    @Test
    public void loginIsBoundToItsServerAddress() throws Exception {
        Prefs p = new Prefs(ctx);
        login(p);
        sp.edit().putString("local_url", "https://192.168.1.99:8700").commit();
        assertFalse("prijava vrijedi samo za adresu na koju je izdana", p.loggedIn());
        assertEquals("", p.certPin());
    }

    @Test
    public void pairingCodeMatchesCppAndRustVector() throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest("abc".getBytes("UTF-8"));
        StringBuilder fp = new StringBuilder();
        for (int i = 0; i < h.length; i++) fp.append(i == 0 ? "" : ":").append(String.format("%02X", h[i]));
        assertEquals("XJ4B-NP4P-AHH6", ServerClient.pairingCode(fp.toString()));
        assertTrue(ServerClient.pairingMatches("xj4bnp4pahh6", fp.toString()));
        assertFalse(ServerClient.pairingMatches("XJ4B-NP4P-AHH7", fp.toString()));
    }

    @Test
    public void manifestDisallowsBackup() {
        ApplicationInfo ai = ctx.getApplicationInfo();
        assertEquals("allowBackup mora biti isključen (SMA-21)", 0, ai.flags & ApplicationInfo.FLAG_ALLOW_BACKUP);
        assertNotNull(ai.packageName);
    }
}

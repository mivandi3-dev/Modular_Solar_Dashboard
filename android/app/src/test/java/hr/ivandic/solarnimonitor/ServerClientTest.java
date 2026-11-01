package hr.ivandic.solarnimonitor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 4.0 (SMA-04, AT-01…AT-03): uparivanje kodom i stvarni HTTPS (TLS JDK-a, SSLServerSocket) na 127.0.0.1.
 * Pokretanje: gradlew testDebugUnitTest (JVM, bez uređaja).
 */
public class ServerClientTest {
    private static final String PASSWORD = "solari-test";
    private static File keystoreA, keystoreB;
    private static String fingerprintA;

    /** Testni ključ i samopotpisani certifikat (keytool iz JDK-a) – samo za test, u privremenoj mapi. */
    private static File makeKeystore(String name) throws Exception {
        File dir = Files.createTempDirectory("solari-tls").toFile();
        File ks = new File(dir, name + ".p12");
        String keytool = new File(System.getProperty("java.home"), "bin/keytool").getPath();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "srv", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                "-dname", "CN=solari-test-" + name, "-storetype", "PKCS12", "-keystore", ks.getPath(), "-storepass", PASSWORD,
                "-keypass", PASSWORD).redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assertEquals("keytool", 0, p.waitFor());
        return ks;
    }

    private static SSLContext context(File ks) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(ks)) { store.load(in, PASSWORD.toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, PASSWORD.toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    private static String fingerprint(File ks) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(ks)) { store.load(in, PASSWORD.toCharArray()); }
        return ServerClient.fingerprint(((X509Certificate) store.getCertificate("srv")).getEncoded());
    }

    /**
     * Lažni Solarni poslužitelj 4.0 na stvarnom TLS-u JDK-a (javax.net.ssl.SSLServerSocket): broji zahtjeve /login
     * (dokaz da lozinka nije poslana). com.sun.net.httpserver.HttpsServer nije dostupan pri prevođenju testova
     * Androida (android.jar), pa je ovo ekvivalent s istim TLS stogom.
     */
    private static final class FakeServer implements AutoCloseable {
        final java.net.ServerSocket server;
        final AtomicInteger logins = new AtomicInteger();
        final AtomicInteger resets = new AtomicInteger();  // /forgot_password i /reset_password (e-pošta, kod)
        final AtomicInteger requests = new AtomicInteger();
        final int port;
        private final Thread thread;

        FakeServer(File ks, String... protocols) throws Exception {
            javax.net.ssl.SSLServerSocket s = (javax.net.ssl.SSLServerSocket) context(ks).getServerSocketFactory()
                    .createServerSocket(0, 10, java.net.InetAddress.getByName("127.0.0.1"));
            s.setEnabledProtocols(protocols.length > 0 ? protocols : new String[] {"TLSv1.3", "TLSv1.2"});
            server = s;
            port = s.getLocalPort();
            thread = start();
        }

        FakeServer() throws Exception {  // obični HTTP (provjera da se tajne ne šalju bez TLS-a)
            server = new java.net.ServerSocket(0, 10, java.net.InetAddress.getByName("127.0.0.1"));
            port = server.getLocalPort();
            thread = start();
        }

        private Thread start() {
            Thread t = new Thread(() -> {
                while (!server.isClosed()) {
                    try (java.net.Socket c = server.accept()) {
                        c.setSoTimeout(5000);
                        java.io.BufferedReader in = new java.io.BufferedReader(new java.io.InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
                        String line = in.readLine();
                        if (line == null) continue;
                        requests.incrementAndGet();
                        int length = 0;
                        for (String h; (h = in.readLine()) != null && !h.isEmpty();) {
                            if (h.toLowerCase().startsWith("content-length:")) length = Integer.parseInt(h.substring(15).trim());
                        }
                        for (int i = 0; i < length; i++) in.read();
                        String body;
                        if (line.contains("/api/v1/forgot_password") || line.contains("/api/v1/reset_password")) {
                            resets.incrementAndGet();
                            body = "{\"ok\":true,\"message\":\"poslano\"}";
                        } else if (line.contains("/api/v1/login")) {
                            logins.incrementAndGet();
                            body = "{\"token\":\"oznaka-prijave-0123456789-0123456789-01234\",\"user\":{\"first_name\":\"Ana\","
                                    + "\"last_name\":\"Horvat\",\"email\":\"ana@primjer.hr\",\"role\":\"user\"}}";
                        } else {
                            body = "{\"app\":\"Solarni poslužitelj\",\"api\":4,\"setup\":true}";
                        }
                        byte[] b = body.getBytes(StandardCharsets.UTF_8);
                        OutputStream o = c.getOutputStream();
                        o.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + b.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                        o.write(b);
                        o.flush();
                    } catch (IOException ignored) {
                        // neuspjelo TLS rukovanje (npr. pogrešan protokol) – sljedeća veza
                    }
                }
            });
            t.setDaemon(true);
            t.start();
            return t;
        }

        @Override public void close() throws IOException { server.close(); }
    }

    @BeforeClass public static void setUp() throws Exception {
        keystoreA = makeKeystore("a");
        keystoreB = makeKeystore("b");
        fingerprintA = fingerprint(keystoreA);
    }

    @AfterClass public static void tearDown() {
        keystoreA.delete();
        keystoreB.delete();
    }

    @Test public void pairingCodeMatchesCppVector() {
        String fp = "8D:29:86:91:10:49:64:12:9B:D6:BC:56:6F:F3:F4:D2:2E:6F:28:89:1F:53:8F:AB:B2:EC:DC:0E:2C:1A:79:00";
        assertEquals("RUUY-NEIQ-JFSB", ServerClient.pairingCode(fp));  // isti vektor kao C++ test SMA-04
        assertTrue(ServerClient.pairingMatches("ruuyneiqjfsb", fp));
        assertTrue(ServerClient.pairingMatches(" RUUY NEIQ JFSB ", fp));
        assertFalse(ServerClient.pairingMatches("RUUY-NEIQ-JFSC", fp));
        assertFalse(ServerClient.pairingMatches("", fp));
        assertEquals("", ServerClient.pairingCode("nije otisak"));
    }

    @Test public void httpsLoginWithCorrectPairingCode() throws Exception {
        try (FakeServer s = new FakeServer(keystoreA)) {
            String base = "https://127.0.0.1:" + s.port;
            ServerClient.Login l = ServerClient.login(base, "ana@primjer.hr", "Sunce-2026-ploce", "", "", "",
                    ServerClient.pairingCode(fingerprintA).toLowerCase());
            assertEquals(fingerprintA, l.pin());
            assertEquals(1, s.logins.get());
            // upareno: sljedeća prijava s poznatim otiskom ne traži kod
            ServerClient.login(base, "ana@primjer.hr", "Sunce-2026-ploce", fingerprintA, "", "", "");
            assertEquals(2, s.logins.get());
        }
    }

    @Test public void noOrWrongPairingCodeSendsNoPassword() throws Exception {
        try (FakeServer s = new FakeServer(keystoreA)) {
            String base = "https://127.0.0.1:" + s.port;
            for (String code : new String[] {"", "AAAA-BBBB-CCCC", ServerClient.pairingCode(fingerprint(keystoreB))}) {
                try {
                    ServerClient.login(base, "ana@primjer.hr", "Sunce-2026-ploce", "", "", "", code);
                    fail("prijava bez ispravnog koda");
                } catch (ServerClient.PairingNeeded expected) {
                    // očekivano
                }
            }
            assertEquals("lozinka nije smjela biti poslana", 0, s.logins.get());
        }
    }

    @Test public void forgottenPasswordNeedsPairingLikeLogin() throws Exception {
        try (FakeServer s = new FakeServer(keystoreA)) {
            String base = "https://127.0.0.1:" + s.port;
            try {
                ServerClient.forgotPassword(base, "ana@primjer.hr", "", "");
                fail("e-pošta poslana bez koda za uparivanje");
            } catch (ServerClient.PairingNeeded expected) {
                // očekivano
            }
            try {
                ServerClient.resetPassword(base, "ana@primjer.hr", "AAAA-AAAA", "Novo-Sunce-2027!", "", "AAAA-BBBB-CCCC");
                fail("kod poslan bez ispravnog koda za uparivanje");
            } catch (ServerClient.PairingNeeded expected) {
                // očekivano
            }
            assertEquals("e-pošta ni kod nisu smjeli biti poslani", 0, s.resets.get());
            try {
                ServerClient.forgotPassword(base, "nije-adresa", fingerprintA, "");
                fail("neispravna e-pošta prihvaćena");
            } catch (ServerClient.ServerException expected) {
                // očekivano – bez zahtjeva prema poslužitelju
            }
            assertEquals("poslano", ServerClient.forgotPassword(base, "ana@primjer.hr", "", ServerClient.pairingCode(fingerprintA)));
            assertEquals("poslano", ServerClient.resetPassword(base, "ana@primjer.hr", "ABCD-EFGH", "Novo-Sunce-2027!", fingerprintA, ""));
            assertEquals(2, s.resets.get());
        }
    }

    @Test public void certificateChangeIsRejected() throws Exception {
        try (FakeServer s = new FakeServer(keystoreB)) {  // napadač / zamijenjen certifikat
            String base = "https://127.0.0.1:" + s.port;
            try {
                ServerClient.login(base, "ana@primjer.hr", "Sunce-2026-ploce", fingerprintA, "", "", "");
                fail("drugi certifikat prihvaćen");
            } catch (IOException expected) {
                // očekivano: otisak ne odgovara
            }
            assertEquals(0, s.logins.get());
        }
    }

    @Test public void plainHttpInLanIsRefusedBeforeConnecting() throws Exception {
        try (FakeServer s = new FakeServer()) {
            try {
                ServerClient.request("http://10.255.255.1:" + s.port, "/api/v1/me", "GET", "oznaka", null, "");
                fail("HTTP u mreži dopušten");
            } catch (ServerClient.ServerException expected) {
                // očekivano: "Poslužitelj u mreži mora imati adresu https://"
            }
            assertEquals(0, s.logins.get());
        }
    }

    @Test public void tls10And11AreRejected() throws Exception {
        FakeServer s;
        try {
            s = new FakeServer(keystoreA, "TLSv1.1", "TLSv1");
        } catch (Exception e) {
            return;  // JDK ni na poslužiteljskoj strani ne dopušta TLS 1.0/1.1 – nema s čime pregovarati
        }
        try (FakeServer server = s) {
            String base = "https://127.0.0.1:" + server.port;
            try {
                ServerClient.request(base, "/api/v1/ping", "GET", "", null, "");
                fail("veza preko TLS 1.0/1.1 uspostavljena");
            } catch (IOException expected) {
                // očekivano
            }
        }
    }
}

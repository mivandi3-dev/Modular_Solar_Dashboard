"""4.0 B1 e2e: stvarni C++ servis (SolarniServer.exe --service, razvojna gradnja) + Rust gateway (solari-gateway.exe
--console, značajka dev) + prozor poslužitelja (CDP). Mrežni kriteriji AC-GW-2/5/6/7, AC-TLS-1, rute, prijava, dashboard.
Sve na kopijama u %TEMP%; razvojni podaci se ne diraju."""
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import traceback
from pathlib import Path

SP = Path(__file__).parent
sys.path.insert(0, str(SP))
import cdp  # noqa: E402

SERVER = r"C:\Modularnisolarnidashboard40\build\windows-dev\SolarniServer.exe"
GATEWAY = r"C:\Modularnisolarnidashboard40\source\gateway\target\debug\solari-gateway.exe"
HOME = Path(os.environ["TEMP"]) / "sm40_b1_server"
PORT = 8795
PIPE = r"\\.\pipe\SolariE2E.Api." + str(os.getpid())
OUT = Path(r"C:\Modularnisolarnidashboard40\reports")
results = []
fails = []


def check(area, name, ok, detail=""):
    sys.stdout.flush()
    results.append((area, name, bool(ok), str(detail)[:300]))
    print(("PASS " if ok else "FAIL ") + f"[{area}] {name}" + ("" if ok else f" -- {detail}"))
    if not ok:
        fails.append(name)


def my_sid():
    return subprocess.check_output(["powershell", "-NoProfile", "-Command",
                                    "([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value"], text=True).strip()


def ctx(minv=ssl.TLSVersion.TLSv1_2, maxv=ssl.TLSVersion.TLSv1_3):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE  # provjera je otiskom (kod za uparivanje), kao u klijentima
    c.minimum_version = minv
    c.maximum_version = maxv
    return c


def https(method, path, body=None, headers=None, src="127.0.0.1"):
    conn = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx(), timeout=10, source_address=(src, 0))
    conn.request(method, path, body=body, headers=headers or {})
    der = conn.sock.getpeercert(binary_form=True)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data, dict(r.getheaders()), der


def raw(data, host="127.0.0.1", src=None, tls=True, wait=3.0):
    s = socket.create_connection((host, PORT), timeout=wait, source_address=(src, 0) if src else None)
    if tls:
        s = ctx().wrap_socket(s)
    s.sendall(data)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except (socket.timeout, ConnectionResetError, ssl.SSLError):
        pass
    s.close()
    return out


def pairing(der):
    c = base64.b32encode(hashlib.sha256(der).digest()[:8]).decode()[:12]
    return f"{c[:4]}-{c[4:8]}-{c[8:]}"


if HOME.exists():
    shutil.rmtree(HOME)
(HOME / "data").mkdir(parents=True)
shutil.copy(os.environ.get("SOLARI_E2E_DB", str(SP / "home_features" / "data" / "solar.db")), HOME / "data" / "solar.db")
(HOME / "config.json").write_text(json.dumps({"modbus_host": "192.168.0.222", "plant_name": "B1 elektrana", "server_port": PORT,
                                              "server_lan": True, "server_gateway": True, "language": "hr"}), encoding="utf-8")
SID = my_sid()
env = {**os.environ, "SOLARI2_HOME": str(HOME), "SOLARI_DEV_GATEWAY_SID": SID, "SOLARI_DEV_API_PIPE": PIPE}
service = subprocess.Popen([SERVER, "--service"], env=env)
gw_log = open(HOME / "gateway-console.log", "w", encoding="utf-8")
gateway = None
gui = None
try:
    time.sleep(4)
    gateway = subprocess.Popen([GATEWAY, "--console", "--data-dir", str(HOME / "gateway"), "--pipe", PIPE, "--pipe-owner", SID],
                               stdout=gw_log, stderr=subprocess.STDOUT)
    for _ in range(40):
        try:
            st, body, _, der = https("GET", "/api/v1/ping")
            break
        except OSError:
            time.sleep(0.5)
    else:
        raise RuntimeError("gateway se nije javio")
    ping = json.loads(body)
    check("api", "ping preko gatewaya (HTTPS) → C++ servis", st == 200 and ping.get("api") == 4, body)
    code = pairing(der)
    gw_text = (HOME / "gateway" / "gateway.log").read_text(encoding="utf-8")
    check("tls", "kod za uparivanje iz certifikata = zapis gatewaya", code in gw_text, (code, gw_text[-300:]))
    info = json.loads((HOME / "service" / "gateway.json").read_text(encoding="utf-8"))
    check("tls", "servis je zapisao otisak gatewaya (service\\gateway.json)",
          info["fingerprint"] == ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()), info)

    # ---- AC-GW-2: samo gateway sluša port; C++ servis nema TCP listener
    # psutil (GetExtendedTcpTable); u ovom okruženju Windows prikazuje i obične listenere sa stanjem CLOSED/NONE,
    # pa se gledaju utičnice bez udaljene adrese koje drže ova dva procesa
    import psutil
    ps = [f"{c.pid}:{c.laddr.ip}:{c.laddr.port}" for c in psutil.net_connections(kind="tcp")
          if c.pid in (service.pid, gateway.pid) and not c.raddr and c.laddr]
    check("ac-gw-2", "C++ servis nema nijedan TCP listener", not any(x.startswith(f"{service.pid}:") for x in ps), ps)
    check("ac-gw-2", f"gateway sluša samo {PORT}", bool(ps) and all(x.startswith(f"{gateway.pid}:") and x.endswith(f":{PORT}") for x in ps), ps)

    # ---- AC-TLS-1
    for v, name in ((ssl.TLSVersion.TLSv1, "1.0"), (ssl.TLSVersion.TLSv1_1, "1.1")):
        try:
            c = ctx(v, v)
            c.set_ciphers("ALL:@SECLEVEL=0")
            s = c.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=5))
            s.close()
            check("ac-tls-1", f"TLS {name} odbijen", False, "spojeno")
        except (ssl.SSLError, OSError) as e:
            check("ac-tls-1", f"TLS {name} odbijen", True, e)
    for v, name in ((ssl.TLSVersion.TLSv1_2, "1.2"), (ssl.TLSVersion.TLSv1_3, "1.3")):
        s = ctx(v, v).wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=5))
        check("ac-tls-1", f"TLS {name} prihvaćen", s.version() == f"TLSv{name}", s.version())
        s.close()

    # ---- obični HTTP: s loopbacka (cloudflared) da, iz mreže ne
    plain = raw(b"GET /api/v1/ping HTTP/1.1\r\nHost: x\r\n\r\n", tls=False)
    check("http", "obični HTTP s 127.0.0.1 (cloudflared) radi", plain.startswith(b"HTTP/1.1 200"), plain[:80])
    lan_ip = next((ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")), None)
    if lan_ip:
        out = raw(b"GET /api/v1/ping HTTP/1.1\r\nHost: x\r\n\r\n", host=lan_ip, tls=False)
        check("http", f"obični HTTP iz mreže ({lan_ip}) zatvoren bez odgovora", out == b"", out[:80])
        c = http.client.HTTPSConnection(lan_ip, PORT, context=ctx(), timeout=10)
        c.request("GET", "/api/v1/ping")
        lan_status = c.getresponse().status
        c.close()
        check("http", f"HTTPS iz mreže ({lan_ip}) radi", lan_status == 200, lan_status)
    else:
        check("http", "adresa u mreži za test običnog HTTP-a", False, "nema IPv4 adrese osim loopbacka")

    # ---- rute i AC-GW-7
    for m, p, want in (("GET", "/web/index.html", 404), ("GET", "/api/dashboard", 404), ("GET", "/api/v1/users", 404),
                       ("GET", "/api/v1/images/..%2fusers.db", 404), ("DELETE", "/api/v1/me", 405), ("GET", "/api/v1/me", 401),
                       ("GET", "/api/v1/dashboard", 401)):
        st, body, hdr, _ = https(m, p)
        check("rute", f"{m} {p} → {want}", st == want, (st, body[:100]))
    st, _, hdr, _ = https("GET", "/api/v1/me", headers={"Authorization": "Bearer krivaoznaka"})
    check("rute", "kriva oznaka → 401 + WWW-Authenticate", st == 401 and {k.lower(): v for k, v in hdr.items()}.get("www-authenticate") == "Bearer", (st, hdr))
    big_hdr = b"GET /api/v1/ping HTTP/1.1\r\nHost: x\r\nX-A: " + b"a" * 9000 + b"\r\n\r\n"
    check("ac-gw-7", "zaglavlja > 8 KB → 431", raw(big_hdr).startswith(b"HTTP/1.1 431"), raw(big_hdr)[:60])
    many = b"GET /api/v1/ping HTTP/1.1\r\nHost: x\r\n" + b"".join(b"X-%d: 1\r\n" % i for i in range(120)) + b"\r\n"
    r = raw(many)
    check("ac-gw-7", "> 100 zaglavlja → 4xx", r[9:10] == b"4", r[:60])
    te = b"POST /api/v1/login HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
    check("ac-gw-7", "Transfer-Encoding → 411", raw(te).startswith(b"HTTP/1.1 411"), raw(te)[:60])
    dup = b"POST /api/v1/login HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"
    check("ac-gw-7", "dvostruki Content-Length → 400", raw(dup).startswith(b"HTTP/1.1 400"), raw(dup)[:60])
    dup_host = b"GET /api/v1/ping HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n"
    check("ac-gw-7", "dvostruki Host → 400", raw(dup_host).startswith(b"HTTP/1.1 400"), raw(dup_host)[:60])
    big = b"POST /api/v1/login HTTP/1.1\r\nHost: x\r\nContent-Length: 20000\r\n\r\n" + b"a" * 20000
    check("ac-gw-7", "tijelo > 16 KB → 413", raw(big).startswith(b"HTTP/1.1 413"), raw(big)[:60])

    # ---- prozor poslužitelja: administrator, korisnik, kod za uparivanje iz gatewaya
    gui = subprocess.Popen([SERVER], env={**env, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={cdp.PORT}"})
    t = cdp.wait_target("settings.html", timeout=40)
    time.sleep(4)
    vals = {"first_name": "Marko", "last_name": "Admin", "email": "admin@primjer.hr", "password": "Sunce-2026-ploce", "password2": "Sunce-2026-ploce"}
    cdp.js(t, "; ".join(f"document.querySelector('#admin-setup [data-user=\"{k}\"]').value = {json.dumps(v)}" for k, v in vals.items())
           + "; document.getElementById('setup-submit').click(); 0")
    time.sleep(6)
    check("gui", "administrator izrađen", cdp.js(t, "!document.getElementById('app').hidden"))
    cdp.js(t, "document.querySelector('#nav [data-panel=\"server\"]').click(); 0")
    time.sleep(3)
    cert_text = cdp.js(t, "document.getElementById('server-cert').innerText") or ""
    check("gui", "prozor poslužitelja prikazuje kod za uparivanje gatewaya", code in cert_text, (code, cert_text))
    cdp.capture(t, "e2e_b1_server_pairing")
    gui.terminate()
    gui = None
    time.sleep(2)

    # ---- prijava i dashboard kroz gateway
    st, body, _, _ = https("POST", "/api/v1/login", body=json.dumps({"email": "admin@primjer.hr", "password": "kriva", "device": "e2e"}),
                           headers={"Content-Type": "application/json"})
    check("api", "pogrešna lozinka → 401 bad_credentials", st == 401 and json.loads(body)["error"] == "bad_credentials", body)
    st, body, _, _ = https("POST", "/api/v1/login", body=json.dumps({"email": "admin@primjer.hr", "password": "Sunce-2026-ploce", "device": "e2e"}),
                           headers={"Content-Type": "application/json"})
    token = json.loads(body).get("token", "") if st == 200 else ""
    check("api", "prijava kroz gateway → oznaka", st == 200 and len(token) > 20, (st, body[:120]))
    auth = {"Authorization": "Bearer " + token}
    st, body, _, _ = https("GET", "/api/v1/me", headers=auth)
    check("api", "/me s oznakom → 200", st == 200 and b"admin@primjer.hr" in body, body[:120])
    st, body, _, _ = https("GET", "/api/v1/dashboard", headers=auth)
    d = json.loads(body) if st == 200 else {}
    check("api", "/dashboard → 200, bez modbus_host (SMA-08)", st == 200 and "modbus_host" not in json.dumps(d), (st, body[:120]))
    st, body, _, _ = https("GET", "/api/v1/report?year=2026&month=10", headers=auth)
    check("api", "/report → 200", st == 200, body[:120])
    st, body, _, _ = https("GET", "/api/v1/report?year=1999&month=10", headers=auth)
    check("api", "/report izvan raspona → 400 (C++ validacija)", st == 400, body[:120])
    st, body, hdr, _ = https("GET", "/api/v1/images/logo", headers=auth)
    check("api", "/images/logo → 200 ili 404 (slika), nikad 5xx", st in (200, 404), (st, hdr.get("Content-Type")))
    st, body, _, _ = https("HEAD", "/api/v1/ping")
    check("api", "HEAD /ping → 200 bez tijela", st == 200 and body == b"", (st, body[:40]))

    # ---- AC-GW-6 (filtar okruženja propušta samo 127.0.0.1 i adresu u mreži kao izvor)
    lan = lan_ip or "127.0.0.1"
    slow = []
    refused = 0
    for _ in range(500):  # napadač: 500 sporih veza s 127.0.0.1 (nedovršen TLS ClientHello)
        try:
            s_ = socket.create_connection(("127.0.0.1", PORT), timeout=2)
            s_.sendall(b"\x16\x03")
            slow.append(s_)
        except OSError:
            refused += 1
    time.sleep(1)
    alive = 0
    for s_ in slow:
        s_.setblocking(False)
        try:
            alive += 0 if s_.recv(1) == b"" else 1
        except BlockingIOError:
            alive += 1
        except OSError:
            pass
    check("ac-gw-6", "s jedne adrese (loopback, cloudflared) drži se najviše 32 veze, ostale odmah zatvorene", alive <= 32,
          f"žive {alive}, odbijene pri spajanju {refused}")
    t0 = time.time()
    c = http.client.HTTPSConnection(lan, PORT, context=ctx(), timeout=10)
    c.request("GET", "/api/v1/ping")
    st = c.getresponse().status
    c.close()
    dt = time.time() - t0
    check("ac-gw-6", f"legitimni klijent ({lan}) za vrijeme napada dobiva odgovor < 2 s", st == 200 and dt < 2, f"{st}, {dt:.2f} s")
    for s_ in slow:
        s_.close()
    time.sleep(1)
    # 4+1. istodobna veza s istog IP-a (adresa u mreži – granica 4)
    held = [socket.create_connection((lan, PORT), timeout=3) for _ in range(4)]
    for s_ in held:
        s_.sendall(b"\x16")
    time.sleep(0.5)
    extra = socket.create_connection((lan, PORT), timeout=3)
    extra.sendall(b"\x16\x03\x01")
    try:
        closed = extra.recv(1) == b""
    except OSError:
        closed = True
    check("ac-gw-6", f"4+1. veza s istog IP-a ({lan}) odbijena", closed)
    for s_ in held + [extra]:
        s_.close()
    time.sleep(1)

    # ---- ponovno pokretanje servisa: gateway vraća 503, pa se sam oporavlja (nova veza, novi izazov)
    service.terminate()
    service.wait(10)
    time.sleep(1)
    st, body, _, _ = https("GET", "/api/v1/ping")
    check("ipc", "servis zaustavljen → 503 (gateway ne odgovara umjesto servisa)", st == 503, body[:100])
    service = subprocess.Popen([SERVER, "--service"], env=env)
    ok = False
    for _ in range(30):
        time.sleep(1)
        try:
            st, body, _, _ = https("GET", "/api/v1/ping")
            if st == 200:
                ok = True
                break
        except OSError:
            pass
    check("ipc", "servis ponovno pokrenut → gateway nastavlja (nova veza i izazov)", ok)
    st, body, _, _ = https("GET", "/api/v1/me", headers=auth)
    check("ipc", "oznaka prijave vrijedi i nakon ponovnog pokretanja servisa", st == 200, st)

    # ---- AC-GW-5: lažni kanal (vlasnik nije očekivani) – gateway ništa ne šalje
    fake = subprocess.Popen([GATEWAY, "--console", "--data-dir", str(HOME / "gateway2"), "--pipe", PIPE, "--pipe-owner", "S-1-5-18"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(7)
    fake.terminate()
    out = fake.communicate(timeout=10)[0].decode("utf-8", "replace")
    check("ac-gw-5", "gateway odbija kanal čiji vlasnik nije SYSTEM", "vlasnik kanala je" in out and "Slušam" not in out, out[-400:])
except Exception:
    traceback.print_exc()
    fails.append("iznimka")
finally:
    if gui:
        gui.terminate()
    if gateway:
        gateway.terminate()
    service.terminate()
    gw_log.close()
    shot = SP / "e2e_b1_server_pairing.png"
    if shot.exists():
        shutil.copy(shot, OUT / "screenshots" / shot.name)
lines = [f"{'PASS' if ok else 'FAIL'} [{a}] {n}" + ("" if ok else f" -- {d}") for a, n, ok, d in results]
(OUT / "e2e_b1-result.txt").write_text("e2e B1 (gateway + C++ servis), " + time.strftime("%Y-%m-%d %H:%M") + "\n" + "\n".join(lines)
                                       + f"\n\nUkupno: {sum(r[2] for r in results)}/{len(results)} PASS\n", encoding="utf-8")
print("\nSVE PROŠLO" if not fails else f"\nNEUSPJELO: {fails}")

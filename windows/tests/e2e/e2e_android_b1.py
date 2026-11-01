"""4.0 e2e: Solarni poslužitelj 4.0 (prozor + servis) → administrator, korisnik s aktivacijskim kodom, kod za uparivanje
→ Android (emulator, debug APK) prijava: bez koda, pogrešan kod, točan kod, aktivacija vlastitom lozinkom."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

SP = Path(__file__).parent
sys.path.insert(0, str(SP))
import cdp  # noqa: E402
from emu_all import adb, connect, js, shot, check, fails  # noqa: E402

PKG = "hr.ivandic.solarnimonitor"
APK = r"C:\Modularnisolarnidashboard40\source\android\app\build\outputs\apk\debug\app-debug.apk"
SERVER = r"C:\Modularnisolarnidashboard40\build\windows-dev\SolarniServer.exe"
HOME = Path(os.environ["TEMP"]) / "sm40_e2e_android_b1"
GATEWAY = r"C:\Modularnisolarnidashboard40\source\gateway\target\debug\solari-gateway.exe"
PORT = 8794
OUT = Path(r"C:\Modularnisolarnidashboard40\reports")

if HOME.exists():
    shutil.rmtree(HOME)
(HOME / "data").mkdir(parents=True)
shutil.copy(os.environ.get("SOLARI_E2E_DB", str(SP / "home_features" / "data" / "solar.db")), HOME / "data" / "solar.db")  # kopija testne baze
(HOME / "config.json").write_text(json.dumps({"modbus_host": "192.168.0.222", "plant_name": "Test elektrana", "server_port": PORT,
                                              "server_lan": True, "server_gateway": True, "language": "hr"}), encoding="utf-8")
SID = subprocess.check_output(["powershell", "-NoProfile", "-Command", "([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value"], text=True).strip()
PIPE = '\\\\.\\pipe\\SolariE2EAndroid.' + str(os.getpid())
env = {**os.environ, "SOLARI2_HOME": str(HOME), "SOLARI_DEV_GATEWAY_SID": SID, "SOLARI_DEV_API_PIPE": PIPE}
service = subprocess.Popen([SERVER, "--service"], env=env)
time.sleep(3)
gateway = subprocess.Popen([GATEWAY, "--console", "--data-dir", str(HOME / "gateway"), "--pipe", PIPE, "--pipe-owner", SID],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
gui = None
code = pairing = ""
try:
    for _ in range(60):  # gateway se javlja servisu porukom hello (service\gateway.json) – tek tada prozor ima kod
        if (HOME / "service" / "gateway.json").exists():
            break
        time.sleep(0.5)
    time.sleep(1)
    gui = subprocess.Popen([SERVER], env={**env, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={cdp.PORT}"})
    t = cdp.wait_target("settings.html", timeout=40)
    time.sleep(4)
    vals = {"first_name": "Marko", "last_name": "Admin", "email": "admin@primjer.hr", "password": "Sunce-2026-ploce", "password2": "Sunce-2026-ploce"}
    cdp.js(t, "; ".join(f"document.querySelector('#admin-setup [data-user=\"{k}\"]').value = {json.dumps(v)}" for k, v in vals.items())
           + "; document.getElementById('setup-submit').click(); 0")
    time.sleep(6)
    check("server", "administrator izrađen", cdp.js(t, "!document.getElementById('app').hidden"))
    cdp.js(t, "document.querySelector('#nav [data-panel=\"server\"]').click(); 0")
    time.sleep(3)
    cert = cdp.js(t, "document.getElementById('server-cert').innerText")
    m = re.search(r"\b([A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4})\b", cert or "")
    pairing = m.group(1) if m else ""
    check("server", "prozor poslužitelja prikazuje kod za uparivanje", bool(pairing), cert)
    cdp.capture(t, "e2e40_server_pairing")
    cdp.js(t, "document.querySelector('[data-action=\"user-add\"]').click(); 0")
    time.sleep(0.5)
    cdp.js(t, "; ".join(f"document.querySelector('#user-dialog [data-user=\"{k}\"]').value = {json.dumps(v)}"
                        for k, v in {"first_name": "Ana", "last_name": "Horvat", "email": "ana@primjer.hr", "password": "", "password2": ""}.items())
           + "; document.getElementById('user-submit').click(); 0")
    time.sleep(4)
    code = cdp.js(t, "(document.querySelector('#users-result .activation-code code') || {}).textContent || ''")
    msg = cdp.js(t, "document.getElementById('users-result').innerText")
    check("server", "novi korisnik bez lozinke dobiva aktivacijski kod (XXXX-XXXX-XXXX)", bool(re.fullmatch(r"[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}", code or "")), msg)
    check("server", "nema zajedničke lozinke 12345678 u poruci", "12345678" not in (msg or ""), msg)
    cdp.capture(t, "e2e40_server_activation")
    for src in ("e2e40_server_pairing", "e2e40_server_activation"):
        f = SP / f"{src}.png"
        if f.exists():
            shutil.copy(f, OUT / f"{src}.png")
    gui.terminate()
    gui = None
    time.sleep(2)

    adb("uninstall", PKG, check=False)
    adb("install", "-r", APK)
    adb("shell", "am", "start", "-n", f"{PKG}/.MainActivity")
    time.sleep(7)
    connect()

    def login(pair, password, new=""):
        js(f"""(() => {{ document.querySelector('input[name=mode][value=local]').click();
          document.querySelector('[data-field=local_url]').value = 'https://10.0.2.2:{PORT}';
          document.getElementById('email').value = 'ana@primjer.hr';
          document.getElementById('pairing').value = {json.dumps(pair)};
          document.getElementById('password').value = {json.dumps(password)};
          document.querySelector('#newpw .np1').value = {json.dumps(new)}; document.querySelector('#newpw .np2').value = {json.dumps(new)};
          document.querySelector('[data-action=login]').click(); return 1; }})()""")
        time.sleep(8)
        return js("document.getElementById('test-result').textContent")

    r = login("", code)
    check("android", "bez koda za uparivanje: traži kod, lozinka se ne šalje", "uparivanje" in r.lower() or "pairing" in r.lower(), r)
    r = login("AAAA-BBBB-CCCC", code)
    check("android", "pogrešan kod: odbijeno (moguće presretanje)", "ne odgovara" in r or "does not match" in r, r)
    r = login(pairing.lower().replace("-", ""), code)
    check("android", "točan kod + aktivacijski kod: traži vlastitu lozinku", js("!document.getElementById('newpw').hidden"), r)
    shot("e2e40_android_activation")
    r = login(pairing, code, "Ana-Vlastita-Lozinka-2026")
    acc = js("document.getElementById('account').innerText")
    check("android", "aktivirano vlastitom lozinkom, prijavljena", "Ana" in acc, (r, acc))
    shot("e2e40_android_loggedin")
    prefs = adb("shell", "run-as", PKG, "cat", "shared_prefs/solari.xml", check=False).stdout.decode(errors="replace")
    check("android", "SharedPreferences: bez lozinke, koda i e-pošte u čitljivom obliku",
          "Ana-Vlastita" not in prefs and code not in prefs and "primjer.hr" not in prefs, prefs[:200])
    js("document.querySelector('[data-action=save]').click(); 1")
    time.sleep(10)
    connect()
    d = js("[document.querySelectorAll('.widget-error').length, !!document.querySelector('.hero')]")
    check("android", "dashboard s poslužitelja 4.0 preko HTTPS-a", d[1] and d[0] == 0, d)
    shot("e2e40_android_dashboard")
except Exception:
    traceback.print_exc()
    fails.append("iznimka")
finally:
    if gui:
        gui.terminate()
    service.terminate()
    gateway.terminate()
for f in SP.glob("e2e40_android_*.png"):
    shutil.copy(f, OUT / "screenshots" / f.name.replace("e2e40_", "e2e_b1_"))

print("\nSVE PROŠLO" if not fails else f"\nNEUSPJELO: {fails}")

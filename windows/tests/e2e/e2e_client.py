"""4.0 e2e sučelja klijenta (WebView2 + broker postavki, SMA-02/05/06/08): razvojna gradnja SolarniMonitor.exe,
poller s brokerom (--poller, zaseban kanal i mutex), prisilni način brokera, CDP. Sve na kopiji u %TEMP%."""
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
import urllib.request
from pathlib import Path

SP = Path(__file__).parent
sys.path.insert(0, str(SP))
import cdp  # noqa: E402

APP = r"C:\Modularnisolarnidashboard40\build\windows-dev\SolarniMonitor.exe"
HOME = Path(os.environ["TEMP"]) / "sm40_client_broker"
OUT = Path(r"C:\Modularnisolarnidashboard40\reports")
VIEW_PORT = 8697
PIN = "24680"
results, fails = [], []


def check(area, name, ok, detail=""):
    results.append((area, name, bool(ok), str(detail)[:300]))
    print(("PASS " if ok else "FAIL ") + f"[{area}] {name}" + ("" if ok else f" -- {detail}"), flush=True)
    if not ok:
        fails.append(name)


def http_get(path, key=None):
    req = urllib.request.Request(f"http://127.0.0.1:{VIEW_PORT}{path}" + ("" if path.endswith("x") else ""), method="XGET" if False else "GET")
    if key:
        req.add_header("X-Solari-View-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


if HOME.exists():
    shutil.rmtree(HOME)
(HOME / "data").mkdir(parents=True)
shutil.copy(os.environ.get("SOLARI_E2E_DB", str(SP / "home_features" / "data" / "solar.db")), HOME / "data" / "solar.db")
cfg = {"modbus_host": "192.168.0.222", "plant_name": "Klijent prije", "language": "hr", "remote_view": True, "remote_port": VIEW_PORT,
       "smtp_password_enc": "", "start_fullscreen": False}
(HOME / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
env = {**os.environ, "SOLARI2_HOME": str(HOME), "SOLARI_DEV_BROKER_PIPE": r"\\.\pipe\SolariE2E.Broker." + str(os.getpid()),
       "SOLARI_DEV_FORCE_BROKER": "1", "SOLARI_DEV_POLLER_MUTEX": "Local\\SolariE2EPoller" + str(os.getpid())}
pin_file = HOME / "pin.txt"
pin_file.write_text(PIN + "\r\n", encoding="ascii")
rc = subprocess.run([APP, "--set-pin-file", str(pin_file)], env=env).returncode
check("broker", "PIN iz instalacije (--set-pin-file) postavljen, datoteka obrisana", rc == 0 and not pin_file.exists(), rc)
poller = subprocess.Popen([APP, "--poller"], env=env)
gui = None
try:
    time.sleep(3)
    gui = subprocess.Popen([APP], env={**env, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={cdp.PORT}"})
    main = cdp.wait_target("index.html", timeout=40)
    time.sleep(5)
    st = cdp.js(main, "window.pywebview.api.get_dashboard().then(d => d.plant ? d.plant.name || '' : JSON.stringify(Object.keys(d)).slice(0,80))")
    check("gui", "dashboard se učitava (baza samo za čitanje + postavke iz brokera)", st is not None and "EXCEPTION" not in str(st), st)
    log = (HOME / "ui" / "logs" / "app.log").read_text(encoding="utf-8", errors="replace") if (HOME / "ui" / "logs" / "app.log").exists() else ""
    check("broker", "sučelje radi u načinu brokera (zapis u ui\\logs\\app.log)", "broker" in log, log[-300:])

    # ---- WebView2 (SMA-05/06, WT-10)
    before = {t["id"] for t in cdp.targets()}
    cdp.js(main, "window.open('https://example.com/zlo'); 0")
    time.sleep(2)
    new = [t for t in cdp.targets() if t["id"] not in before and t.get("type") == "page"]
    check("webview2", "window.open na vanjsku adresu ne otvara novi prozor", not new, [t.get("url") for t in new])
    cdp.js(main, "setTimeout(() => { location.href = 'https://example.com/zlo'; }, 10); 0")
    time.sleep(3)
    main = cdp.wait_target("app.solari", timeout=10)
    url = cdp.js(main, "location.href")
    check("webview2", "navigacija glavnog prozora na vanjsku adresu je blokirana", str(url).startswith("https://app.solari/"), url)
    r = cdp.js(main, "fetch('https://app.solari/config.json').then(r => r.status).catch(e => 'blokirano: ' + e)")
    check("webview2", "app.solari poslužuje samo /web/ i /assets/ (config.json → 403/blokirano)", r != 200, r)
    r = cdp.js(main, "fetch('https://app.solari/web/../data/solar.db').then(r => r.status).catch(e => 'blokirano: ' + e)")
    check("webview2", "put s .. izvan /web/ → nije 200", r != 200, r)
    r = cdp.js(main, "window.pywebview.api.save({}).then(() => 'IZVRŠENO').catch(e => 'odbijeno: ' + e.message)")
    check("webview2", "glavni prozor ne smije zvati metodu prozora postavki (save)", str(r).startswith("odbijeno"), r)
    r = cdp.js(main, "window.pywebview.api.remote_view_new_key().then(() => 'IZVRŠENO').catch(e => 'odbijeno: ' + e.message)")
    check("webview2", "glavni prozor ne smije izraditi novi ključ pregleda", str(r).startswith("odbijeno"), r)
    r = cdp.js(main, """new Promise(res => { const f = document.createElement('iframe');
        f.srcdoc = "<script>try{window.chrome.webview.postMessage(JSON.stringify({id:999,method:'quit',args:[]}));parent.postMessage('poslano','*')}catch(e){parent.postMessage('nema mosta: '+e,'*')}<\\/script>";
        window.addEventListener('message', e => res(String(e.data)), {once: true}); document.body.appendChild(f); setTimeout(() => res('bez odgovora'), 3000); })""")
    time.sleep(2)
    alive = gui.poll() is None
    check("webview2", "poruka mostu iz iframea ne izvršava naredbu (aplikacija i dalje radi)", alive, r)

    # ---- postavke: PIN, spremanje kroz broker
    cdp.js(main, "window.pywebview.api.open_settings('system'); 0")
    sett = cdp.wait_target("settings.html", timeout=30)
    time.sleep(4)
    check("broker", "postavke su zaključane PIN-om", cdp.js(sett, "!document.getElementById('lock').hidden"))
    res = cdp.js(sett, "window.pywebview.api.unlock('0000')")
    check("broker", "pogrešan PIN odbijen (provjerava broker)", res and not res.get("ok"), res)
    res = cdp.js(sett, f"window.pywebview.api.unlock('{PIN}')")
    check("broker", "ispravan PIN otključava", res and res.get("ok"), res)
    form = cdp.js(sett, """(async () => { const st = await window.pywebview.api.get_state(); const f = Object.assign({}, st.settings);
        const ifs = await window.pywebview.api.interfaces(); f.plant_name = 'Klijent kroz broker';
        f.logger_interface = (ifs[0] && (ifs[0].name || ifs[0])) || ''; return f; })()""")
    res = cdp.js(sett, f"window.pywebview.api.save({json.dumps(form)})")
    check("broker", "spremanje postavki kroz broker", res and res.get("ok"), res)
    time.sleep(1)
    disk = json.loads((HOME / "config.json").read_text(encoding="utf-8"))
    check("broker", "config.json na disku ima novu vrijednost (upisao ga je poller)", disk.get("plant_name") == "Klijent kroz broker", disk.get("plant_name"))
    check("broker", "config.json bez tajni", not any(k in disk for k in ("smtp_password_enc", "cloud_token_enc", "settings_pin_hash", "remote_view_key_enc")),
          [k for k in disk if k.endswith("_enc") or k.endswith("hash")])
    sec = HOME / "secrets" / "secrets.json"
    check("broker", "tajne u secrets\\secrets.json (PIN hash, ključ pregleda)", sec.exists() and "settings_pin_hash" in sec.read_text(encoding="utf-8"))
    bad = dict(form, modbus_host="192.168.0.222\nproxy = zlo")
    res = cdp.js(sett, f"window.pywebview.api.save({json.dumps(bad)})")
    check("broker", "neispravno polje odbijeno (validator u brokeru), ništa se ne sprema", res and not res.get("ok"), res)
    st = cdp.js(sett, "window.pywebview.api.get_state()")
    key = (st or {}).get("remote_view_key", "")
    check("broker", "ključ pregleda iz mreže dolazi od brokera", len(key) >= 20, key[:6] + "…")
    cdp.capture(sett, "e2e_client_broker_settings")

    # ---- pregled iz mreže (SMA-08) – HTTP na 127.0.0.1 (cijeli zahtjevi; filtar zadržava samo nedovršene GET-ove)
    code, _ = http_get("/api/dashboard")
    check("remote", "pregled iz mreže bez ključa → 401/403", code in (401, 403), code)
    code, body = http_get("/api/dashboard", key)
    check("remote", "pregled iz mreže s ključem → 200, bez modbus_host", code == 200 and b"modbus_host" not in body, (code, body[:80]))
    code, _ = http_get("/data/solar.db")
    check("remote", "datoteke izvan allowliste → 404", code == 404, code)

    # ---- zaključavanje nakon 5 pogrešnih PIN-ova (broker, 15 min)
    for _ in range(5):
        cdp.js(sett, "window.pywebview.api.unlock('1111')")
    res = cdp.js(sett, f"window.pywebview.api.unlock('{PIN}')")
    check("broker", "nakon 5 pogrešnih PIN-ova i ispravan je odbijen (zaključano)", res and not res.get("ok") and ("pokušaj" in res.get("message", "") or "attempt" in res.get("message", "")), res)
except Exception:
    traceback.print_exc()
    fails.append("iznimka")
finally:
    if gui:
        gui.terminate()
    poller.terminate()
    shot = SP / "shots" / "e2e_client_broker_settings.png"
    if shot.exists():
        shutil.copy(shot, OUT / "screenshots" / shot.name)
lines = [f"{'PASS' if ok else 'FAIL'} [{a}] {n}" + ("" if ok else f" -- {d}") for a, n, ok, d in results]
(OUT / "e2e_client-result.txt").write_text("e2e klijent (WebView2 + broker), " + time.strftime("%Y-%m-%d %H:%M") + "\n" + "\n".join(lines)
                                          + f"\n\nUkupno: {sum(r[2] for r in results)}/{len(results)} PASS\n", encoding="utf-8")
print("\nSVE PROŠLO" if not fails else f"\nNEUSPJELO: {fails}")

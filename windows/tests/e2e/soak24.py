"""AC-SRV-4: 24-satni rad C++ servisa poslužitelja + Rust gatewaya (razvojna gradnja, kopija podataka u %TEMP%).
Svakih 5 s: ping, dashboard (s prijavom), svakih 60 s: memorija (radni skup, privatno), ručke i niti oba procesa.
Zapis: reports\\soak24.csv (uzorci) i reports\\soak24-summary.txt (osvježava se svakih 10 min). Ne mijenja razvojne podatke."""
import csv
import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from pathlib import Path

import psutil

SP = Path(__file__).parent
SERVER = r"C:\Modularnisolarnidashboard40\build\windows-dev\SolarniServer.exe"
GATEWAY_SRC = r"C:\Modularnisolarnidashboard40\source\gateway\target\debug\solari-gateway.exe"
HOME = Path(os.environ["TEMP"]) / "sm40_soak24"
OUT = Path(r"C:\Modularnisolarnidashboard40\reports")
PORT = 8799
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 24 * 3600

if HOME.exists():
    shutil.rmtree(HOME)
shutil.copytree(Path(os.environ["TEMP"]) / "sm40_b1_server", HOME, ignore=shutil.ignore_patterns("gateway", "gateway2", "*.log"))
cfg = json.loads((HOME / "config.json").read_text(encoding="utf-8"))
cfg["server_port"] = PORT
(HOME / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
# vlastite kopije programa (gradnje se smiju mijenjati dok test traje)
GATEWAY = str(HOME / "solari-gateway.exe")
shutil.copy(GATEWAY_SRC, GATEWAY)
BIN = HOME / "bin"
BIN.mkdir()
# drugo ime: instalacija (taskkill /IM SolarniServer.exe) ne smije prekinuti test koji traje 24 h
shutil.copy(SERVER, BIN / "SolarniServerSoak.exe")
for d in ("web", "assets", "curl"):
    shutil.copytree(Path(SERVER).parent / d, BIN / d)
SERVER = str(BIN / "SolarniServerSoak.exe")
SID = subprocess.check_output(["powershell", "-NoProfile", "-Command",
                               "([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value"], text=True).strip()
PIPE = r"\\.\pipe\SolariSoak.Api." + str(os.getpid())
env = {**os.environ, "SOLARI2_HOME": str(HOME), "SOLARI_DEV_GATEWAY_SID": SID, "SOLARI_DEV_API_PIPE": PIPE,
       "SOLARI_DEV_SERVICE_MUTEX": "Local\SolariSoakService"}
svc = subprocess.Popen([SERVER, "--service"], env=env)
time.sleep(4)
gw = subprocess.Popen([GATEWAY, "--console", "--data-dir", str(HOME / "gateway"), "--pipe", PIPE, "--pipe-owner", SID],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def req(method, path, body=None, token=None):
    c = http.client.HTTPSConnection("127.0.0.1", PORT, context=ctx, timeout=15)
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def sample(p):
    try:
        with p.oneshot():
            m = p.memory_info()
            return m.rss, getattr(m, "private", m.vms), p.num_handles(), p.num_threads()
    except psutil.Error:
        return None


start = time.time()
ok = err = 0
errors = {}
token = None
last_sample = 0.0
last_summary = 0.0
first = {}
csv_path = OUT / "soak24.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["sekunde", "proces", "radni_skup_B", "privatno_B", "rucke", "niti", "zahtjevi_ok", "zahtjevi_greske"])
    procs = {"servis": psutil.Process(svc.pid), "gateway": psutil.Process(gw.pid)}
    while time.time() - start < DURATION:
        t = time.time()
        try:
            if not token:
                st, body = req("POST", "/api/v1/login", json.dumps({"email": "admin@primjer.hr", "password": "Sunce-2026-ploce", "device": "soak"}))
                token = json.loads(body).get("token") if st == 200 else None
                if not token:
                    raise RuntimeError(f"prijava {st}")
            st, _ = req("GET", "/api/v1/ping")
            st2, _ = req("GET", "/api/v1/dashboard", token=token)
            if st == 200 and st2 == 200:
                ok += 2
            else:
                err += 1
                errors[f"{st}/{st2}"] = errors.get(f"{st}/{st2}", 0) + 1
                if st2 == 401:
                    token = None
        except Exception as e:  # noqa: BLE001 – bilježi se i nastavlja
            err += 1
            errors[type(e).__name__] = errors.get(type(e).__name__, 0) + 1
        if t - last_sample >= 60:
            last_sample = t
            for name, p in procs.items():
                s = sample(p)
                if s:
                    first.setdefault(name, s)
                    w.writerow([int(t - start), name, *s, ok, err])
                else:
                    w.writerow([int(t - start), name, "ZAVRŠIO", "", "", "", ok, err])
            f.flush()
        if t - last_summary >= 600:
            last_summary = t
            lines = [f"24-satni test (AC-SRV-4) – stanje {time.strftime('%Y-%m-%d %H:%M')}",
                     f"trajanje do sada: {(t - start) / 3600:.2f} h od {DURATION / 3600:.0f} h",
                     f"zahtjevi: uspješni {ok}, greške {err} {errors}",
                     f"servis radi: {svc.poll() is None}, gateway radi: {gw.poll() is None}"]
            for name, p in procs.items():
                s = sample(p)
                if s and name in first:
                    lines.append(f"{name}: radni skup {first[name][0] // 1024} → {s[0] // 1024} KB, ručke {first[name][2]} → {s[2]}, niti {first[name][3]} → {s[3]}")
            lines.append("ZAVRŠENO" if t - start >= DURATION - 6 else "U TIJEKU (nije završeno – ne označavati kao PASS)")
            (OUT / "soak24-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        time.sleep(max(0.0, 5 - (time.time() - t)))
lines = (OUT / "soak24-summary.txt").read_text(encoding="utf-8").splitlines()
lines[-1] = f"ZAVRŠENO nakon {(time.time() - start) / 3600:.2f} h; uspješni {ok}, greške {err} {errors}"
(OUT / "soak24-summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
gw.terminate()
svc.terminate()

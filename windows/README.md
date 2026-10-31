# Solarni monitor i Solarni poslužitelj (Windows, C++)

Nativna C++20 aplikacija s WebView2 sučeljem: statički povezan `.exe`, bez runtimea, instalacija ~7 MB s
potpunom deinstalacijom. Iz istog koda nastaju dvije aplikacije:

- **Solarni monitor** (`SolarniMonitor.exe`, `SolarniMonitor2-Setup-<verzija>.exe`): dashboard preko cijelog zaslona.
- **Solarni poslužitelj** (`SolarniServer.exe`, `SolarniServer-Setup-<verzija>.exe`): bilježenje i API za klijente.

## Solarni monitor

| | |
|---|---|
| Prvo pokretanje | čarobnjak: izvor podataka (logger u lokalnoj mreži ili Solarni poslužitelj), mrežne kartice, elektrana, prikaz |
| `F11` / dvoklik, `Esc` | cijeli zaslon uključi / isključi |
| `F2` | postavke (mreža, elektrana, naslov, slike, prikaz, obavijesti, izvještaji, sustav) |
| Izbornik *Widgeti* desno | izvan cijelog zaslona: povlačenje na mrežu 12 × 5, veličina, opcije, stranice i njihova izmjena, `Ctrl + Z` |
| Slike | zaglavlje **6 : 1** (3840 × 640), crtež zgrade **16 : 9** (PNG s prozirnom pozadinom), logotip **~9 : 1** |

- **Lokalni logger:** Modbus veza se veže na adresu odabrane mrežne kartice, a prognoza (Open-Meteo) ide preko
  `curl.exe --interface` kartice prema internetu. Podaci se spremaju u `%ProgramData%\SolarniMonitor2`.
- **Solarni poslužitelj:** u *Postavke → Mreža* upišite adresu poslužitelja i prijavite se e-poštom i lozinkom
  (lozinka se ne sprema, nego samo oznaka prijave šifrirana DPAPI-jem). Podaci, naziv, naslov, logotip i slike
  dolaze s poslužitelja, a raspored widgeta, tema i jezik su na svakom računalu svoji.

## Podržani uređaji

| Uređaj (*Postavke → Mreža → Uređaj*) | Veza | Napomena |
|---|---|---|
| Huawei SmartLogger 3000 | Modbus TCP, port 502, adresa 0 | cijela elektrana; mjerač na COM portu loggera |
| Huawei SUN2000 | Modbus TCP (SDongle 502 / WLAN invertera 6607) | više invertera: adrese 1,2,3 |
| **SunSpec Modbus** | Modbus TCP | SMA (port 502, adresa 126), Fronius (502, 1; mjerač 240, GEN24 200), SolarEdge (1502, 1; mjerač na istoj adresi), Kostal (1502, 71), ABB/FIMER, Delta… Modeli 101–103 / 111–113 i mjerači 201–204 / 211–214 pronalaze se sami. |
| **Fronius Solar API** | HTTP, port 80 | Datamanager i GEN24 (na GEN24 uključite Solar API); mjerač = Fronius Smart Meter |
| **Ostali proizvođači** | Modbus TCP (502) | Sungrow SG / SH, Solis 4G/5G i RHI/S6, Fox ESS H1/H3 (adresa 247), Growatt (preko RS485 → Modbus TCP pristupnika), **Victron Energy GX** (adresa 100; energiju računa poller iz snage) |
| Deye / Sunsynk | Solarman V5, port 8899 | Wi-Fi logger: serijski broj loggera s naljepnice; ili Modbus TCP pristupnik na 502 |
| GoodWe ET/EH/BT i DT/SDT | UDP, port 8899 | Wi-Fi/LAN modul (adresa 247 / 127); noviji LAN moduli i Modbus TCP na 502 |
| **Otočni izmjenjivač (Voltronic)** | USB (HID) ili RS232, 2400 | Axpert, MPP Solar, EASUN, PowMr, Mecer, Must PV18…; protokol QPIGS (CRC); energiju računa poller iz snage PV-a |
| **Victron VE.Direct** | VE.Direct–USB kabel, 19200 | SmartSolar/BlueSolar MPPT, Phoenix 12/24/48 V, SmartShunt, BMV; više uređaja: `COM3, COM4` (zbrajaju se) |
| Growatt SPF (otočni) | Modbus RTU, RS232/RS485, 9600 | *Ostali proizvođači*; input registri prema Growatt OffGrid SPF protokolu |
| EPEver Tracer / UPower | Modbus RTU, RS485, 115200 | *Ostali proizvođači*; EPEver Modbus protokol V2.3 |
| SRNE HF / ML / ASF | Modbus RTU, RS232/RS485, 9600 | *Ostali proizvođači*; SRNE MODBUS protokol 1.96 |

Otočni uređaji nisu isprobani na stvarnom hardveru – adrese i protokoli su iz dokumentacije proizvođača. Widget
**Otočni sustav** prikazuje potrošnju na izlazu izmjenjivača, izlazni napon i frekvenciju, opterećenje i napon
baterije; widget **Baterija** prikazuje i nazivni napon sustava (12, 24 ili 48 V).

SunSpec i GEN24 ne daju dnevnu energiju, nego samo ukupnu – dnevnu računa poller (ukupno sada − ukupno na početku dana).
Predznak SunSpec mjerača razlikuje se po proizvođačima, pa ga je moguće obrnuti u postavkama. Ostali proizvođači koriste tablice registara iz službene
dokumentacije i provjerenih projekata otvorenog koda (izvor uz svaku tablicu u `src/vendors.cpp`). Sve integracije su
testirane na simulatorima prema službenoj dokumentaciji; izvještaji o radu sa stvarnim uređajima su dobrodošli.

## Solarni poslužitelj i Cloudflare tunel

1. U postavkama poslužitelja upišite adresu loggera i mrežnu karticu, naziv i naslov, te izaberite logotip,
   fotografiju zaglavlja i crtež za tok energije. Poslužitelj radi kao zadatak sustava (`--service`), a podatke
   drži u `%ProgramData%\SolarniServer`.
2. **Korisnici (3.0):** pri prvom otvaranju poslužitelj traži izradu administratora; on u *Poslužitelj → Korisnici*
   dodaje ostale (ime, prezime, e-pošta, lozinka, uloga). Prozor poslužitelja traži administratorska prava Windowsa.
   - Lozinke: samo sažetak PBKDF2-HMAC-SHA256 (600 000 ponavljanja); ime, prezime i e-pošta šifrirani AES-256-GCM-om
     (`data\users.db`, ključ u `data\users.key` zaštićen DPAPI-jem; mapa je dostupna samo administratorima i sustavu).
   - Bez valjane oznake prijave (`Authorization: Bearer …`) **svaki** odgovor je `401`.
   - 5 pogrešnih lozinki zaključava račun na 15 minuta; 10 neuspjelih pokušaja s iste adrese (iza tunela
     `CF-Connecting-IP`) blokira je na 10 minuta.
3. API sluša na `127.0.0.1:8700`. Opcija *Dostupno i u lokalnoj mreži* otvara ga i za mrežu – tada **samo HTTPS**
   (vlastiti certifikat, TLS 1.2/1.3; otisak je prikazan u postavkama poslužitelja), a vatrozid ga dopušta samo u
   privatnim mrežama. Obični HTTP prima se samo s `127.0.0.1` (za `cloudflared`).
4. Postavljanje tunela:
   - instalacija: `winget install Cloudflare.cloudflared`;
   - za probu: `cloudflared tunnel --url http://localhost:8700`;
   - stalni tunel: Zero Trust → Networks → Tunnels → Public Hostname → `http://localhost:8700`.

| API (zaglavlje `Authorization: Bearer <oznaka>`) | |
|---|---|
| `GET /api/v1/ping` | bez prijave: `{"app","api":3,"setup"}` |
| `POST /api/v1/login` | `{"email","password","device"}` → `{"token","user"}` |
| `POST /api/v1/logout` | poništava oznaku |
| `GET /api/v1/me` | prijavljeni korisnik |
| `POST /api/v1/password` | `{"old_password","new_password"}` → nova oznaka |
| `/api/v1/info` | naziv elektrane i verzija |
| `/api/v1/dashboard` | podaci za dashboard (isti JSON kao u aplikaciji) |
| `/api/v1/images/{hero,drawing,logo}` | slike (verzija u `?v=`) |
| `/api/v1/report?year=2026&month=9` | mjesečni izvještaj |

## Povijest proizvodnje sa SmartLoggera

Modbus (ni SmartLogger ni SUN2000) ne daje povijest – samo današnju i ukupnu energiju. SmartLogger je ipak čuva
u svojoj bazi performansi, koja je dio izvoza logova:

1. u web sučelju SmartLoggera izvezite logove SmartLoggera (*Maintenance → Device Log → Export*) – `log.zip`;
2. u Solarnom poslužitelju (ili klijentu s lokalnim loggerom): *Postavke → Sustav → Uvezi povijest sa
   SmartLoggera (log.zip)…*.

Iz `perfmg_day.emap` uvozi se dnevna proizvodnja elektrane od puštanja u rad. Dani koji u bazi već imaju
podatke (poller ili raniji uvoz) ostaju kakvi jesu, današnji dan se ne uvozi, a uvoz je moguće ponoviti.
Inverter spojen izravno, bez SmartLoggera, povijest ne daje.

## Izgradnja

```powershell
winget install MartinStorsjo.LLVM-MinGW.UCRT Kitware.CMake Ninja-build.Ninja JRSoftware.InnoSetup
powershell -ExecutionPolicy Bypass -File windows\build.ps1
```

Skripta preuzme biblioteke (`third_party\fetch.ps1`), prevede klijent, poslužitelj i testove (doctest), pokrene
testove i izgradi obje instalacije u `build\output`.

## Struktura

```
windows/
├── src/            C++: main (klijent), server_main (poslužitelj), app/webview/bridge (prozori i pozivi iz JS-a),
│                   config, poller + modbus (logger, inverter, mjerač), storage (SQLite), data/dashboard/report,
│                   alerts (e-pošta), api (prijava, Bearer), users (korisnici), crypto (CNG), tls (SChannel), cloud (klijent poslužitelja), remote (HTTP), i18n, images
├── web/            sučelje: index.html + dashboard/widgets/charts/components.js, settings.*, editor.js,
│                   overlay.js (prečaci, noćni način), pages.js (stranice), report.js, i18n/ (10 jezika)
├── assets/         zadane slike
├── installer/      Inno Setup (klijent; poslužitelj s /DServer), zadatak sustava (poller_task.ps1)
├── res/            ikona, manifest, podaci o verziji
└── tests/          doctest
```

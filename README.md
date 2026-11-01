# ☀️ Solarni monitor

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://revolut.me/markog68z)

**[English](#english) · [Hrvatski](#hrvatski)**

---

## English

A solar power plant dashboard for lobby screens, TVs and tablets. Supported devices (local network):
Huawei **SmartLogger 3000** and **SUN2000** inverters, **SunSpec Modbus** inverters and meters (SMA, Fronius, SolarEdge,
Kostal, ABB/FIMER, Delta…), the **Fronius Solar API** (Datamanager, GEN24), **Sungrow, GoodWe, Deye/Sunsynk, Solis,
Fox ESS, Growatt** and **Victron Energy** GX, and off-grid systems over USB/RS232/RS485: **Voltronic** (Axpert, MPP Solar,
EASUN, PowMr…), **Victron VE.Direct** (MPPT, Phoenix 12/24/48 V, SmartShunt/BMV), **Growatt SPF**, **EPEver** and **SRNE**.
All three parts share the same web interface:

| Part | Folder | What it does |
|---|---|---|
| **Solarni monitor** (Windows, C++) | [`windows/`](windows/README.md) | full-screen dashboard: reads the logger on the local network or gets data from the server |
| **Solarni poslužitelj** – Solar server (Windows, C++) | [`windows/`](windows/README.md) (`SolarniServer.exe`) | on a computer in the logger's network: records data and serves it to clients through an API (Cloudflare tunnel) |
| **Solarni monitor for Android** | [`android/`](android/README.md) | the same dashboard on a tablet or phone, connects to the server (tunnel or local network) |

**Features:**
- 27 widgets on a 12 × 5 grid arranged by drag and drop, up to 6 pages that rotate.
- Energy flow showing export to the grid, a consumption meter, savings in your currency, and production compared
  with the solar radiation forecast.
- Email alerts (device not responding, inverter fault, low production).
- Monthly reports (PDF and CSV), night mode, view from a browser on the local network.
- Production history since commissioning imported from the SmartLogger log export (`log.zip`).
- 10 languages (hr, en, de, fr, it, es, tr, zh, ja, ko), 11 colour palettes (themes), Full HD / 2K / 4K.
- Device widgets shown only when the device provides the data: battery (state of charge, charging/discharging),
  inverter temperature, grid voltage and frequency.

```
  logger / inverter ──Modbus TCP / HTTP──► Solar server ──HTTPS API (sign-in)──► Cloudflare tunnel ──► Solarni monitor (Windows / Android)
                         (SQLite, images, headline)                          └─ or directly on the local network
```

### Users and security (3.0)

Since 3.0 there is no API key: the apps sign in with the **email and password** of a user created in Solar Server.

- **First start:** Solar Server asks you to create an administrator. Only administrators open the server settings
  (Windows asks for administrator rights); they add, edit, block and delete users (first name, last name, email,
  password, role).
- **Passwords** are never stored: the server keeps only a PBKDF2-HMAC-SHA256 hash (600,000 iterations, random salt).
  First name, last name and email are stored encrypted with AES-256-GCM; the keys are protected by Windows DPAPI.
- **Sign-in:** the apps store only a random sign-in token (encrypted with DPAPI on Windows and the Android Keystore on
  Android) – never the password. A token is valid for 30 days after its last use (at most 90 days, 4.0). A new password,
  blocking or deleting a user signs them out of all devices immediately.
- 5 wrong passwords lock the account for 15 minutes; 10 failed attempts from one address block it for 10 minutes (`429`).
- **Activation code (4.0):** a user added without a password gets a one-time random activation code (12 characters, valid
  for 72 hours, shown to the administrator once) and sets their own password with it. There is no shared initial password.
- **Pairing (4.0):** the first sign-in to a server on the local network requires the 20-character pairing code (100 bits, 5.0.2) shown in the
  server window (derived from the certificate's SHA-256 fingerprint) – no trust on first use.
- **Two-factor sign-in (3.1):** the administrator enables it per account (administrators and users). At the next sign-in
  the user scans a QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy…; TOTP,
  RFC 6238) and receives 8 one-time recovery codes. The secret is stored encrypted (AES-256-GCM), a code cannot be
  used twice, wrong codes count towards the lock-out, and the administrator can reset it for a lost phone.
- **HTTPS on the local network:** the server creates its own certificate (RSA 3072, TLS 1.2/1.3 via Windows SChannel).
  The apps remember its SHA-256 fingerprint at the first sign-in and check it *before* sending a password or token.
  Plain HTTP is accepted only from `127.0.0.1` (for `cloudflared`). The Cloudflare tunnel uses the normal public
  certificate check.

### Building

| | Requirements | Command |
|---|---|---|
| Windows (client + server + installers) | LLVM-MinGW (clang), CMake, Ninja, Inno Setup 6 | `powershell -ExecutionPolicy Bypass -File windows\build.ps1` |
| Android (APK, AAB) | JDK 17, Android SDK 36 | `powershell -ExecutionPolicy Bypass -File android\build.ps1` |

External libraries (SQLite, nlohmann/json, doctest, WebView2 SDK, plotly.js-basic, curl) are downloaded by
`windows\third_party\fetch.ps1` on the first build. For a signed APK, create your own signing key (see
[`android/README.md`](android/README.md)).

### Credits and licences

- **Header photo:** NASA/Troy Cryder, *Solar power system at Kennedy Space Center*, public domain
  ([Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Solar_power_system_at_Kennedy_Space_Center.jpg)).
- **Building drawing and logo:** made for this project.
- **Font:** Plus Jakarta Sans, SIL Open Font License (`windows/web/vendor/OFL.txt`).
- **Libraries:**
  - nlohmann/json (MIT)
  - doctest (MIT)
  - SQLite (public domain)
  - Microsoft WebView2 SDK (BSD)
  - plotly.js (MIT)
  - qrcode-generator, Kazuhiko Arase (MIT) – QR code for two-factor sign-in
  - curl (curl licence / MIT) – bundled for Windows Server 2016
- **Weather forecast:** [Open-Meteo](https://open-meteo.com) (CC BY 4.0).

The program is free for personal use. All rights to the source code reserved.

---

## Hrvatski

Dashboard solarne elektrane za ekrane u predvorju, TV i tablete. Podržani uređaji (lokalna mreža): Huawei
**SmartLogger 3000** i inverteri **SUN2000**, inverteri i mjerači sa **SunSpec Modbusom** (SMA, Fronius, SolarEdge, Kostal,
ABB/FIMER, Delta…), **Fronius Solar API** (Datamanager, GEN24), **Sungrow, GoodWe, Deye/Sunsynk, Solis, Fox ESS,
Growatt** i **Victron Energy** GX, te otočni sustavi preko USB-a/RS232/RS485: **Voltronic** (Axpert, MPP Solar, EASUN,
PowMr…), **Victron VE.Direct** (MPPT, Phoenix 12/24/48 V, SmartShunt/BMV), **Growatt SPF**, **EPEver** i **SRNE**.
Tri dijela dijele isto web sučelje:

| Dio | Mapa | Što radi |
|---|---|---|
| **Solarni monitor** (Windows, C++) | [`windows/`](windows/README.md) | dashboard preko cijelog zaslona: čita logger u lokalnoj mreži ili podatke dobiva od poslužitelja |
| **Solarni poslužitelj** (Windows, C++) | [`windows/`](windows/README.md) (`SolarniServer.exe`) | na računalu u mreži s loggerom: bilježi podatke i daje ih klijentima preko API-ja (Cloudflare tunel) |
| **Solarni monitor za Android** | [`android/`](android/README.md) | isti dashboard na tabletu ili mobitelu, spaja se na poslužitelj (tunel ili lokalna mreža) |

**Mogućnosti:**
- 27 widgeta na mreži 12 × 5 koje se slažu povlačenjem, do 6 stranica koje se izmjenjuju.
- Tok energije sa smjerom predaje u mrežu, mjerač potrošnje, ušteda u valuti, usporedba proizvodnje s prognozom zračenja.
- Obavijesti e-poštom (uređaj ne odgovara, greška invertera, niska proizvodnja).
- Mjesečni izvještaji (PDF i CSV), noćni način, pregled iz preglednika u lokalnoj mreži.
- Povijest proizvodnje od puštanja u rad uvozi se iz izvoza logova SmartLoggera (`log.zip`).
- 10 jezika (hr, en, de, fr, it, es, tr, zh, ja, ko), 11 paleta boja (tema), Full HD / 2K / 4K.
- Widgeti uređaja koji se nude samo kad ih uređaj podržava: baterija (napunjenost, punjenje/pražnjenje),
  temperatura invertera, napon i frekvencija mreže.

```
  logger / inverter ──Modbus TCP / HTTP──► Solarni poslužitelj ──HTTPS API (prijava)──► Cloudflare tunel ──► Solarni monitor (Windows / Android)
                         (SQLite, slike, naslov)                                     └─ ili izravno u lokalnoj mreži
```

### Korisnici i sigurnost (3.0)

Od 3.0 nema API ključa: aplikacije se prijavljuju **e-poštom i lozinkom** korisnika izrađenog u Solarnom poslužitelju.

- **Prvo pokretanje:** Solarni poslužitelj traži izradu administratora. Postavke poslužitelja otvara samo administrator
  (Windows traži administratorska prava); on dodaje, uređuje, blokira i briše korisnike (ime, prezime, e-pošta,
  lozinka, uloga).
- **Lozinke** se nikad ne spremaju: poslužitelj čuva samo sažetak PBKDF2-HMAC-SHA256 (600 000 ponavljanja, slučajna
  sol). Ime, prezime i e-pošta spremaju se šifrirani AES-256-GCM-om; ključeve štiti Windows DPAPI.
- **Prijava:** aplikacije čuvaju samo slučajnu oznaku prijave (na Windowsu šifriranu DPAPI-jem, na Androidu ključem iz
  Android Keystorea) – nikad lozinku. Oznaka vrijedi 30 dana od zadnjeg korištenja (najdulje 90 dana, 4.0). Nova lozinka,
  blokiranje ili brisanje korisnika odmah ga odjavljuju sa svih uređaja.
- 5 pogrešnih lozinki zaključava račun na 15 minuta; 10 neuspjelih pokušaja s iste adrese blokira je na 10 minuta (`429`).
- **Aktivacijski kod (4.0):** korisnik dodan bez lozinke dobiva jednokratni slučajni kod (12 znakova, vrijedi 72 sata,
  administratoru se prikazuje jednom) i njime postavlja svoju lozinku. Zajednička početna lozinka ne postoji.
- **Uparivanje (4.0):** prva prijava na poslužitelj u lokalnoj mreži traži kod za uparivanje od 20 znakova (100 bita, 5.0.2) s prozora
  poslužitelja (izveden iz SHA-256 otiska certifikata) – bez povjerenja pri prvom kontaktu.
- **Dvofaktorska prijava (3.1):** administrator je uključuje po računu (administratori i korisnici). Pri sljedećoj prijavi
  korisnik skenira QR kod aplikacijom autentifikatorom (Google Authenticator, Microsoft Authenticator, Authy…; TOTP,
  RFC 6238) i dobije 8 jednokratnih kodova za oporavak. Tajna je šifrirana (AES-256-GCM), isti kod ne vrijedi dvaput,
  pogrešni kodovi broje se u zaključavanje, a za izgubljen mobitel administrator je poništava.
- **HTTPS u lokalnoj mreži:** poslužitelj sam izradi certifikat (RSA 3072, TLS 1.2/1.3 preko Windows SChannela).
  Aplikacije pri prvoj prijavi zapamte njegov otisak SHA-256 i provjeravaju ga *prije* slanja lozinke ili oznake.
  Obični HTTP prima se samo s `127.0.0.1` (za `cloudflared`). Cloudflare tunel ima uobičajenu provjeru javnog certifikata.

### Izgradnja

| | Potrebno | Naredba |
|---|---|---|
| Windows (klijent + poslužitelj + instalacije) | LLVM-MinGW (clang), CMake, Ninja, Inno Setup 6 | `powershell -ExecutionPolicy Bypass -File windows\build.ps1` |
| Android (APK, AAB) | JDK 17, Android SDK 36 | `powershell -ExecutionPolicy Bypass -File android\build.ps1` |

Vanjske biblioteke (SQLite, nlohmann/json, doctest, WebView2 SDK, plotly.js-basic, curl) preuzima
`windows\third_party\fetch.ps1` pri prvoj izgradnji. Za potpisani APK napravite vlastiti ključ (vidi
[`android/README.md`](android/README.md)).

### Zasluge i licence

- **Fotografija u zaglavlju:** NASA/Troy Cryder, *Solar power system at Kennedy Space Center*, javno vlasništvo
  ([Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Solar_power_system_at_Kennedy_Space_Center.jpg)).
- **Crtež zgrade i logotip:** izrađeni za ovaj projekt.
- **Font:** Plus Jakarta Sans, SIL Open Font License (`windows/web/vendor/OFL.txt`).
- **Biblioteke:**
  - nlohmann/json (MIT)
  - doctest (MIT)
  - SQLite (javno vlasništvo)
  - Microsoft WebView2 SDK (BSD)
  - plotly.js (MIT)
  - qrcode-generator, Kazuhiko Arase (MIT) – QR kod za dvofaktorsku prijavu
  - curl (licenca curl / MIT) – ugrađen zbog Windows Servera 2016
- **Vremenska prognoza:** [Open-Meteo](https://open-meteo.com) (CC BY 4.0).

Program je besplatan za osobnu upotrebu. Sva prava na izvorni kod pridržana.

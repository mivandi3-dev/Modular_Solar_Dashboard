# ☀️ Solarni monitor za Android

Isti dashboard kao Windows aplikacija (C++, `verzija2/web`): svi widgeti, stranice rasporeda s izmjenom, editor
widgeta, 10 jezika, tamna i svijetla tema, noćni način i mjesečni izvještaji (PDF preko Android ispisa, CSV za Excel).
Podatke, naziv elektrane, naslov, logotip i slike daje **Solarni poslužitelj** (`SolarniServer.exe` na računalu
u lokalnoj mreži s loggerom):

| Način | Adresa | Kada |
|---|---|---|
| Cloudflare tunel | `https://solar.tvrtka.hr` (ili `https://….trycloudflare.com`) | s bilo kojeg mjesta |
| Lokalna mreža | `https://192.168.1.20:8700` | isti Wi-Fi; na poslužitelju uključite *Dostupno i u lokalnoj mreži* |

Prijavite se e-poštom i lozinkom korisnika iz *Solarni poslužitelj → Poslužitelj → Korisnici*. Lozinka se ne sprema;
aplikacija čuva samo oznaku prijave šifriranu ključem iz Android Keystorea. JavaScript je ne vidi – zahtjeve na
`/api/v1/…` šalje Java (`MainActivity.proxy`, `ServerClient`). U lokalnoj mreži aplikacija pri prijavi zapamti otisak
certifikata poslužitelja i provjerava ga prije slanja lozinke ili oznake.
Raspored widgeta, tema, jezik i noćni način su na svakom uređaju svoji.

## Instalacija

`deploy\SolarniMonitor-Android-<verzija>.apk` – kopirajte na uređaj i otvorite (dopustite instalaciju iz tog izvora).
Android 8.0 ili noviji. Prikaz prati položaj uređaja: svi widgeti su iste širine (visina ostaje iz rasporeda) – uspravno su jedan ispod drugog, a položeno (i na tabletu) jedan pored drugog koliko ih stane; stranica se pomiče prstom.
Izbornik ☰ gore lijevo otvara *Postavke* i *Widgete* (dodavanje, uklanjanje, redoslijed i visina).
Logo, slika zaglavlja i crtež spremaju se na uređaj i preuzimaju se s poslužitelja samo kad se tamo promijene.

## Izgradnja

```powershell
powershell -ExecutionPolicy Bypass -File android\build.ps1
```

Skripta izveze zajedničko web sučelje (`verzija2/tools/export_from_python.py`), Gradle ga kopira u APK
(`app/build.gradle`, zadatak `copyWeb`) i potpiše ključem iz `keystore.properties`. **Datoteke
`android\keystore\solarni-release.jks` i `android\keystore.properties` čuvajte** – nova verzija aplikacije može se
instalirati preko stare samo ako je potpisana istim ključem.

| Datoteka | Uloga |
|---|---|
| `app/src/main/java/.../MainActivity.java` | WebView, lokalne datoteke na `https://app.solari/web/…`, proxy prema poslužitelju s ključem, ispis, CSV |
| `app/src/main/java/.../Prefs.java` | postavke, šifrirana oznaka prijave |
| `app/src/main/java/.../ServerClient.java` | HTTPS, otisak certifikata, prijava |
| `web/android-bridge.js` | `window.pywebview.api` kao na Windowsima (dashboard, editor, cijeli zaslon, noćni način) |
| `web/settings-android.html`, `.js` | postavke: poslužitelj, ključ, provjera veze, prikaz, izvještaji |

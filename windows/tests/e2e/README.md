# E2E testovi 4.0 (Windows, razvojna gradnja)

Pokreću se Pythonom s paketima `websockets`, `psutil` (i `Pillow` za snimke). Koriste razvojnu gradnju
`build\windows-dev` (`-DSOLARI_DEV_NO_UAC=ON` → `SOLARI_DEV_BUILD`) i gateway `cargo build --features dev`.
Sve radi na kopijama u `%TEMP%`; testna baza: `SOLARI_E2E_DB=<putanja do kopije solar.db>`.

| Skripta | Što provjerava | Rezultat |
|---|---|---|
| `e2e_b1.py` | C++ servis + Rust gateway: AC-GW-2/5/6/7, AC-TLS-1, rute, prijava, ponovno pokretanje servisa | `reports\e2e_b1-result.txt` |
| `e2e_client.py` | sučelje klijenta: WebView2 zaštite, broker postavki (PIN, validacija, tajne), pregled iz mreže | `reports\e2e_client-result.txt` |
| `e2e_android_b1.py` | Android (emulator, debug APK) → gateway → C++ servis: uparivanje, aktivacija, dashboard | `reports\e2e_android_b1-result.txt` |
| `soak24.py [sekunde]` | 24-satni rad servisa i gatewaya pod opterećenjem (AC-SRV-4) | `reports\soak24.csv`, `soak24-summary.txt` |

Ograničenja okruženja u kojem su izvedeni: filtar na loopbacku blokira izvorne adrese 127.0.0.2+ i zadržava nedovršene
`GET` zahtjeve; Windows tablica TCP veza prikazuje listenere sa stanjem CLOSED (zato `psutil` i utičnice bez udaljene adrese).

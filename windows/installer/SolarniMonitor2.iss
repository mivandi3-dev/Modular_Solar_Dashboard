; Instalacija Solarnog monitora 2 (C++ verzija). Gradi je verzija2\build.ps1 – ne pokretati izravno.
;   ISCC /DAppVersion=2.0.0 /DBuild=..\build /DRedist=..\build\redist SolarniMonitor2.iss
;   ISCC ... /DServer SolarniMonitor2.iss   → Solarni poslužitelj (SolarniServer.exe, zadatak --service, API)
;
; Deinstalacija (Postavke → Aplikacije ili izbornik Start): zaustavlja aplikaciju i poller, uklanja zadatak
; sustava, pokretanje pri prijavi i sve datoteke programa; podatke (povijest, postavke) briše samo na upit.

#ifndef AppVersion
  #define AppVersion "2.0.0"
#endif
#ifndef Build
  #define Build "..\build"
#endif
#ifndef Redist
  #define Redist "..\build\redist"
#endif
#ifdef Server
  #define AppName "Solarni poslužitelj"
  #define AppExe "SolarniServer.exe"
  #define AppUserModelID "MarkoIvandic.SolarniServer"
  #define DataDir "{commonappdata}\SolarniServer"
  #define TaskParams "-TaskName SolarniPosluzitelj -ExeName SolarniServer.exe -Arguments --service"
  #define FirewallRule "Solarni posluzitelj - gateway"
  #define OldFirewallRule "Solarni posluzitelj - API"
  #define SetupName "SolarniServer-Setup"
#else
  #define AppName "Solarni monitor"
  #define AppExe "SolarniMonitor.exe"
  #define AppUserModelID "MarkoIvandic.SolarniMonitor2"
  #ifdef TestInstall
    ; samo za automatsku provjeru instalacije/deinstalacije bez administratorskih prava
    #define DataDir "{localappdata}\SolarniMonitor2Test"
  #else
    #define DataDir "{commonappdata}\SolarniMonitor2"
  #endif
  #define TaskParams ""
  #define FirewallRule "Solarni monitor 2 - pregled iz mreze"
  #define SetupName "SolarniMonitor2-Setup"
#endif

[Setup]
#ifdef Server
AppId={{6E1C7A52-3B9D-4F0E-9A47-C2D85B1F0E63}
#else
AppId={{DDF5B029-0AA1-434D-A5A9-9A3A6AC7CD89}
#endif
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Marko Ivandić
AppCopyright=© 2026 Marko Ivandić
VersionInfoCompany=Marko Ivandić
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
#ifdef TestInstall
PrivilegesRequired=lowest
#else
PrivilegesRequired=admin
#endif
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1607 / Windows Server 2016 i noviji (curl.exe dolazi s instalacijom)
MinVersion=10.0.14393
OutputDir={#Build}\output
#ifdef TestInstall
OutputBaseFilename=SolarniMonitor2-Setup-TEST
#else
OutputBaseFilename={#SetupName}-{#AppVersion}
#endif
#ifdef Server
SetupIconFile=..\res\server.ico
#else
SetupIconFile=..\res\app.ico
#endif
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
UsedUserAreasWarning=no
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}

[Languages]
Name: "hr"; MessagesFile: "Croatian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "it"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "tr"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "zh"; MessagesFile: "ChineseSimplified.isl"
Name: "ja"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "ko"; MessagesFile: "compiler:Languages\Korean.isl"

[CustomMessages]
hr.TaskPoller=Bilježi podatke sa SmartLoggera i kad aplikacija nije otvorena (preporučeno)
hr.TaskAutostart=Pokreni aplikaciju pri prijavi u Windows (kiosk / TV)
hr.TaskGroupData=Rad u pozadini:
hr.InstallingWebView=Instaliram Microsoft Edge WebView2 Runtime…
hr.RegisteringTask=Registriram zadatak za bilježenje podataka…
hr.DeleteData=Obrisati i podatke aplikacije (povijest proizvodnje, postavke, raspored widgeta, slike, sigurnosne kopije)?%n%n%1%n%nOdaberite „Ne” ako ćete aplikaciju ponovno instalirati.
hr.LaunchApp=Pokreni {#AppName}

en.TaskPoller=Record SmartLogger data even when the application is closed (recommended)
en.TaskAutostart=Start the application at Windows sign-in (kiosk / TV)
en.TaskGroupData=Background operation:
en.InstallingWebView=Installing Microsoft Edge WebView2 Runtime…
en.RegisteringTask=Registering the data recording task…
en.DeleteData=Also delete the application data (production history, settings, widget layout, images, backups)?%n%n%1%n%nChoose “No” if you will reinstall the application.
en.LaunchApp=Start {#AppName}

de.TaskPoller=SmartLogger-Daten auch bei geschlossener Anwendung aufzeichnen (empfohlen)
de.TaskAutostart=Anwendung bei der Windows-Anmeldung starten (Kiosk / TV)
de.TaskGroupData=Hintergrundbetrieb:
de.InstallingWebView=Microsoft Edge WebView2 Runtime wird installiert…
de.RegisteringTask=Aufgabe zur Datenaufzeichnung wird registriert…
de.DeleteData=Auch die Anwendungsdaten löschen (Erzeugungsverlauf, Einstellungen, Widget-Anordnung, Bilder, Sicherungen)?%n%n%1%n%nWählen Sie „Nein“, wenn Sie die Anwendung erneut installieren.
de.LaunchApp={#AppName} starten

fr.TaskPoller=Enregistrer les données du SmartLogger même lorsque l'application est fermée (recommandé)
fr.TaskAutostart=Démarrer l'application à l'ouverture de session Windows (kiosque / TV)
fr.TaskGroupData=Fonctionnement en arrière-plan :
fr.InstallingWebView=Installation de Microsoft Edge WebView2 Runtime…
fr.RegisteringTask=Enregistrement de la tâche de collecte des données…
fr.DeleteData=Supprimer aussi les données de l'application (historique de production, paramètres, disposition des widgets, images, sauvegardes) ?%n%n%1%n%nChoisissez « Non » si vous allez réinstaller l'application.
fr.LaunchApp=Lancer {#AppName}

it.TaskPoller=Registra i dati dello SmartLogger anche ad applicazione chiusa (consigliato)
it.TaskAutostart=Avvia l'applicazione all'accesso a Windows (chiosco / TV)
it.TaskGroupData=Funzionamento in background:
it.InstallingWebView=Installazione di Microsoft Edge WebView2 Runtime…
it.RegisteringTask=Registrazione dell'attività di registrazione dati…
it.DeleteData=Eliminare anche i dati dell'applicazione (storico della produzione, impostazioni, disposizione dei widget, immagini, backup)?%n%n%1%n%nScegli «No» se reinstallerai l'applicazione.
it.LaunchApp=Avvia {#AppName}

es.TaskPoller=Registrar los datos del SmartLogger también con la aplicación cerrada (recomendado)
es.TaskAutostart=Iniciar la aplicación al iniciar sesión en Windows (quiosco / TV)
es.TaskGroupData=Funcionamiento en segundo plano:
es.InstallingWebView=Instalando Microsoft Edge WebView2 Runtime…
es.RegisteringTask=Registrando la tarea de registro de datos…
es.DeleteData=¿Eliminar también los datos de la aplicación (historial de producción, configuración, disposición de widgets, imágenes, copias de seguridad)?%n%n%1%n%nElija «No» si va a reinstalar la aplicación.
es.LaunchApp=Iniciar {#AppName}

tr.TaskPoller=Uygulama kapalıyken de SmartLogger verilerini kaydet (önerilen)
tr.TaskAutostart=Windows'ta oturum açılınca uygulamayı başlat (kiosk / TV)
tr.TaskGroupData=Arka planda çalışma:
tr.InstallingWebView=Microsoft Edge WebView2 Runtime yükleniyor…
tr.RegisteringTask=Veri kayıt görevi kaydediliyor…
tr.DeleteData=Uygulama verileri de silinsin mi (üretim geçmişi, ayarlar, widget yerleşimi, görüntüler, yedekler)?%n%n%1%n%nUygulamayı yeniden yükleyecekseniz „Hayır” seçin.
tr.LaunchApp={#AppName} uygulamasını başlat

zh.TaskPoller=应用程序关闭时也记录 SmartLogger 数据（推荐）
zh.TaskAutostart=登录 Windows 时启动应用程序（展示屏 / 电视）
zh.TaskGroupData=后台运行：
zh.InstallingWebView=正在安装 Microsoft Edge WebView2 Runtime…
zh.RegisteringTask=正在注册数据记录任务…
zh.DeleteData=是否同时删除应用程序数据（发电历史、设置、小组件布局、图片、备份）？%n%n%1%n%n如果您将重新安装应用程序，请选择“否”。
zh.LaunchApp=启动 {#AppName}

ja.TaskPoller=アプリケーションを閉じていても SmartLogger のデータを記録する（推奨）
ja.TaskAutostart=Windows へのサインイン時にアプリケーションを起動する（キオスク / テレビ）
ja.TaskGroupData=バックグラウンド動作：
ja.InstallingWebView=Microsoft Edge WebView2 Runtime をインストールしています…
ja.RegisteringTask=データ記録タスクを登録しています…
ja.DeleteData=アプリケーションのデータ（発電履歴、設定、ウィジェット配置、画像、バックアップ）も削除しますか？%n%n%1%n%nアプリケーションを再インストールする場合は「いいえ」を選んでください。
ja.LaunchApp={#AppName} を起動

ko.TaskPoller=애플리케이션이 닫혀 있어도 SmartLogger 데이터 기록(권장)
ko.TaskAutostart=Windows에 로그인할 때 애플리케이션 시작(키오스크 / TV)
ko.TaskGroupData=백그라운드 동작:
ko.InstallingWebView=Microsoft Edge WebView2 Runtime 설치 중…
ko.RegisteringTask=데이터 기록 작업 등록 중…
ko.DeleteData=애플리케이션 데이터(발전 기록, 설정, 위젯 배치, 이미지, 백업)도 삭제하시겠습니까?%n%n%1%n%n애플리케이션을 다시 설치하려면 "아니요"를 선택하세요.
ko.LaunchApp={#AppName} 시작

hr.PinTitle=PIN postavki
hr.PinSubtitle=Postavke Solarnog monitora štiti PIN
hr.PinText=Upišite PIN od 4 do 8 znamenki. Bez njega se postavke ne mogu mijenjati (ni administrator iz aplikacije). Pri nadogradnji ostavite prazno da ostane postojeći PIN.
hr.PinLabel=PIN:
hr.PinLabel2=Ponovite PIN:
hr.PinInvalid=PIN ima 4 do 8 znamenki.
hr.PinMismatch=PIN-ovi se ne podudaraju.
en.PinTitle=Settings PIN
en.PinSubtitle=Solarni monitor settings are protected by a PIN
en.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
en.PinLabel=PIN:
en.PinLabel2=Repeat PIN:
en.PinInvalid=The PIN must have 4 to 8 digits.
en.PinMismatch=The PINs do not match.
de.PinTitle=Settings PIN
de.PinSubtitle=Solarni monitor settings are protected by a PIN
de.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
de.PinLabel=PIN:
de.PinLabel2=Repeat PIN:
de.PinInvalid=The PIN must have 4 to 8 digits.
de.PinMismatch=The PINs do not match.
fr.PinTitle=Settings PIN
fr.PinSubtitle=Solarni monitor settings are protected by a PIN
fr.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
fr.PinLabel=PIN:
fr.PinLabel2=Repeat PIN:
fr.PinInvalid=The PIN must have 4 to 8 digits.
fr.PinMismatch=The PINs do not match.
it.PinTitle=Settings PIN
it.PinSubtitle=Solarni monitor settings are protected by a PIN
it.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
it.PinLabel=PIN:
it.PinLabel2=Repeat PIN:
it.PinInvalid=The PIN must have 4 to 8 digits.
it.PinMismatch=The PINs do not match.
es.PinTitle=Settings PIN
es.PinSubtitle=Solarni monitor settings are protected by a PIN
es.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
es.PinLabel=PIN:
es.PinLabel2=Repeat PIN:
es.PinInvalid=The PIN must have 4 to 8 digits.
es.PinMismatch=The PINs do not match.
tr.PinTitle=Settings PIN
tr.PinSubtitle=Solarni monitor settings are protected by a PIN
tr.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
tr.PinLabel=PIN:
tr.PinLabel2=Repeat PIN:
tr.PinInvalid=The PIN must have 4 to 8 digits.
tr.PinMismatch=The PINs do not match.
zh.PinTitle=Settings PIN
zh.PinSubtitle=Solarni monitor settings are protected by a PIN
zh.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
zh.PinLabel=PIN:
zh.PinLabel2=Repeat PIN:
zh.PinInvalid=The PIN must have 4 to 8 digits.
zh.PinMismatch=The PINs do not match.
ja.PinTitle=Settings PIN
ja.PinSubtitle=Solarni monitor settings are protected by a PIN
ja.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
ja.PinLabel=PIN:
ja.PinLabel2=Repeat PIN:
ja.PinInvalid=The PIN must have 4 to 8 digits.
ja.PinMismatch=The PINs do not match.
ko.PinTitle=Settings PIN
ko.PinSubtitle=Solarni monitor settings are protected by a PIN
ko.PinText=Enter a PIN of 4 to 8 digits. Without it the settings cannot be changed. When upgrading, leave it empty to keep the existing PIN.
ko.PinLabel=PIN:
ko.PinLabel2=Repeat PIN:
ko.PinInvalid=The PIN must have 4 to 8 digits.
ko.PinMismatch=The PINs do not match.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "poller"; Description: "{cm:TaskPoller}"; GroupDescription: "{cm:TaskGroupData}"
#ifndef Server
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{cm:TaskGroupData}"; Flags: unchecked
#endif

[Dirs]
; Postavke, baza i logovi su zajednički (aplikacija korisnika + zadatak sustava) – svi korisnici smiju pisati.
#ifdef Server
; 3.0: poslužitelj čuva korisnike (users.db) i njihov ključ (users.key) – samo administratori i sustav;
; prozor poslužitelja zato traži administratorska prava (res/server.manifest). Stare dozvole: icacls u [Run].
Name: "{#DataDir}"; Permissions: admins-full system-full; Flags: uninsneveruninstall
Name: "{#DataDir}\data"; Permissions: admins-full system-full; Flags: uninsneveruninstall
#else
#ifndef TestInstall
; 4.0 (SMA-02, W4): Users samo čitaju postavke i bazu – izmjene idu kroz broker zadatka sustava (ACL u [Run]);
; ui\ (raspored, slike, zapisi sučelja) mijenjaju korisnici, a zadatak sustava je nikad ne čita
Name: "{#DataDir}"; Flags: uninsneveruninstall
Name: "{#DataDir}\data"; Flags: uninsneveruninstall
Name: "{#DataDir}\service"; Flags: uninsneveruninstall
Name: "{#DataDir}\ui"; Flags: uninsneveruninstall
#endif
#endif

[Files]
Source: "{#Build}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Build}\WebView2Loader.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Build}\web\*"; DestDir: "{app}\web"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#Build}\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#Build}\curl\*"; DestDir: "{app}\curl"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "poller_task.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "acl_setup.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
#ifdef Server
; 4.0 (B1): mrežni ulaz (Rust) kao usluga s virtualnim računom NT SERVICE\SolariGateway
Source: "{#Build}\solari-gateway.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "gateway_service.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
#endif
Source: "..\third_party\webview2\LICENSE.txt"; DestDir: "{app}\licenses"; DestName: "WebView2-LICENSE.txt"; Flags: ignoreversion
Source: "{#Redist}\MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: not WebView2Installed

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppUserModelID}"
Name: "{autoprograms}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppUserModelID}"; Tasks: desktopicon

#ifndef Server
[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SolarniMonitor2"; \
  ValueData: """{app}\{#AppExe}"""; Tasks: autostart; Flags: uninsdeletevalue
#endif

[Run]
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "{cm:InstallingWebView}"; \
  Check: not WebView2Installed; Flags: waituntilterminated
#ifndef TestInstall
; 4.0 (SMA-02, W4, NEW-01): ACL mape podataka (acl_setup.ps1) – vlasnik Administratori, sve stare izričite dozvole
; uklonjene (i korisnika koji je mapu stvorio prije instalacije ili iz 3.x); poslužitelj: samo SYSTEM i Administratori;
; klijent: Users samo čitanje, ui\ Users izmjena, secrets\ bez Users (zatvoren u svakom trenutku)
#ifdef Server
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\acl_setup.ps1"" -DataDir ""{#DataDir}"" -Mode server"; \
  Flags: runhidden waituntilterminated
#else
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\acl_setup.ps1"" -DataDir ""{#DataDir}"" -Mode client"; \
  Flags: runhidden waituntilterminated
#endif
#endif
#ifndef Server
#ifndef TestInstall
; PIN postavki (obavezan; broker ga traži za svaku izmjenu) – upisan na stranici instalacije, datoteka se odmah briše
Filename: "{app}\{#AppExe}"; Parameters: "--set-pin-file ""{code:PinFile}"""; Flags: runhidden waituntilterminated; Check: PinEntered
#endif
#endif
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\poller_task.ps1"" -Register ""{app}"" {#TaskParams}"; \
  StatusMsg: "{cm:RegisteringTask}"; Tasks: poller; Flags: runhidden waituntilterminated
#ifdef Server
; 4.0 (B1): usluga gatewaya (nakon ACL-a mape poslužitelja – mapa gateway\ dobiva pravo usluge)
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\gateway_service.ps1"" -Register ""{app}"" -DataDir ""{#DataDir}"""; \
  Flags: runhidden waituntilterminated
#endif
; 4.0: pravila vezana uz program I port (ne cijeli program). Poslužitelj: samo gateway na 8700 (privatna i domenska
; mreža); C++ servis više nema mrežni port pa se staro pravilo uklanja. Klijent: pregled iz mreže na 8600, samo privatna mreža.
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; Flags: runhidden waituntilterminated
#ifdef Server
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#OldFirewallRule}"""; Flags: runhidden waituntilterminated
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#FirewallRule}"" dir=in action=allow program=""{app}\solari-gateway.exe"" protocol=TCP localport=8700 profile=private,domain enable=yes"; \
  Flags: runhidden waituntilterminated
#else
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#FirewallRule}"" dir=in action=allow program=""{app}\{#AppExe}"" protocol=TCP localport=8600 profile=private enable=yes"; \
  Flags: runhidden waituntilterminated
#endif
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchApp}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallRule"
#ifdef Server
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\gateway_service.ps1"" -Unregister"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemoveGateway"
#endif
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\poller_task.ps1"" -Unregister {#TaskParams}"; \
  Flags: runhidden waituntilterminated; RunOnceId: "RemovePollerTask"
Filename: "taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden waituntilterminated; RunOnceId: "StopApp"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\web"
Type: filesandordirs; Name: "{app}\assets"
Type: filesandordirs; Name: "{app}\curl"
Type: dirifempty; Name: "{app}"

[Code]
const
  WebView2Key = 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  WebView2UserKey = 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

function WebView2Installed: Boolean;
var
  Version: String;
begin
  Result := (RegQueryStringValue(HKLM, WebView2Key, 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0'))
         or (RegQueryStringValue(HKCU, WebView2UserKey, 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0'));
end;

{ Nadogradnja: zaustavi zadatak pollera i aplikaciju prije zamjene datoteka. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  AppDir: String;
begin
  Result := '';
  AppDir := ExpandConstant('{app}');
  if FileExists(AppDir + '\installer\poller_task.ps1') then
    Exec('powershell.exe', '-NoProfile -ExecutionPolicy Bypass -File "' + AppDir + '\installer\poller_task.ps1" -Stop {#TaskParams}',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
#ifdef Server
  if FileExists(AppDir + '\installer\gateway_service.ps1') then
    Exec('powershell.exe', '-NoProfile -ExecutionPolicy Bypass -File "' + AppDir + '\installer\gateway_service.ps1" -Stop',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
#endif
end;

#if !defined(Server) && !defined(TestInstall)
{ 4.0 (SMA-02): PIN postavki – obavezan pri prvoj instalaciji; pri nadogradnji prazno = postojeći PIN ostaje }
var
  PinPage: TInputQueryWizardPage;

function PinAlreadySet: Boolean;
begin
  Result := FileExists(ExpandConstant('{#DataDir}\secrets\secrets.json'));
end;

procedure InitializeWizard;
begin
  PinPage := CreateInputQueryPage(wpSelectTasks, CustomMessage('PinTitle'), CustomMessage('PinSubtitle'), CustomMessage('PinText'));
  PinPage.Add(CustomMessage('PinLabel'), True);
  PinPage.Add(CustomMessage('PinLabel2'), True);
end;

function IsDigits(const S: String): Boolean;
var
  I: Integer;
begin
  Result := Length(S) > 0;
  for I := 1 to Length(S) do
    if (S[I] < '0') or (S[I] > '9') then Result := False;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Pin: String;
begin
  Result := True;
  if CurPageID = PinPage.ID then
  begin
    Pin := PinPage.Values[0];
    if (Pin = '') and (PinPage.Values[1] = '') and PinAlreadySet then Exit;
    if (Length(Pin) < 4) or (Length(Pin) > 8) or not IsDigits(Pin) then
    begin
      MsgBox(CustomMessage('PinInvalid'), mbError, MB_OK);
      Result := False;
    end else if Pin <> PinPage.Values[1] then
    begin
      MsgBox(CustomMessage('PinMismatch'), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ tiha instalacija (npr. automatski test): Setup.exe /VERYSILENT /PIN=12345 – stranica se tada ne prikazuje }
function PinValue: String;
begin
  Result := PinPage.Values[0];
  if Result = '' then Result := ExpandConstant('{param:PIN|}');
  if (Length(Result) < 4) or (Length(Result) > 8) or not IsDigits(Result) then Result := '';
end;

function PinEntered: Boolean;
begin
  Result := PinValue <> '';
end;

function PinFile(Param: String): String;
begin
  Result := ExpandConstant('{tmp}\pin.txt');
  SaveStringToFile(Result, PinValue, False);
end;
#else
function PinEntered: Boolean;
begin
  Result := False;
end;

function PinFile(Param: String): String;
begin
  Result := '';
end;
#endif

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'SolarniMonitor2');
    DataDir := ExpandConstant('{#DataDir}');
    if DirExists(DataDir) and not UninstallSilent and
       (MsgBox(FmtMessage(CustomMessage('DeleteData'), [DataDir]), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
      DelTree(DataDir, True, True, True);
  end;
end;

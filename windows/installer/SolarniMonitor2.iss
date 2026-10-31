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
  #define FirewallRule "Solarni posluzitelj - API"
  #define SetupName "SolarniServer-Setup"
#else
  #define AppName "Solarni monitor 2"
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
Name: "{#DataDir}"; Permissions: users-modify; Flags: uninsneveruninstall
Name: "{#DataDir}\data"; Permissions: users-modify; Flags: uninsneveruninstall
; 4.0 (SMA-02): sigurnosne kopije, alerts.json i zapisi zadatka sustava – piše samo SYSTEM (ACL u [Run])
Name: "{#DataDir}\service"; Flags: uninsneveruninstall
#endif
#endif

[Files]
Source: "{#Build}\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Build}\WebView2Loader.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Build}\web\*"; DestDir: "{app}\web"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#Build}\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#Build}\curl\*"; DestDir: "{app}\curl"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "poller_task.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
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
#ifdef Server
; nadogradnja s 2.x: mapa je bila dostupna svim korisnicima – samo SYSTEM (S-1-5-18) i Administratori (S-1-5-32-544)
Filename: "icacls.exe"; Parameters: """{#DataDir}"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F /T /C /Q"; \
  Flags: runhidden waituntilterminated
#else
#ifndef TestInstall
; 4.0 (SMA-02): mapa servisa – SYSTEM (S-1-5-18) i Administratori (S-1-5-32-544) puna prava, Users (S-1-5-32-545) samo čitanje;
; naslijeđeno pravo izmjene se uklanja, pa korisnik ne može podmetnuti spojnicu u mapu u koju piše SYSTEM
Filename: "icacls.exe"; Parameters: """{#DataDir}\service"" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /T /C /Q";   Flags: runhidden waituntilterminated
#endif
#endif
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\poller_task.ps1"" -Register ""{app}"" {#TaskParams}"; \
  StatusMsg: "{cm:RegisteringTask}"; Tasks: poller; Flags: runhidden waituntilterminated
; Pregled iz mreže (Postavke → Sustav): dolazni TCP samo u privatnim i domenskim mrežama; aplikacija sluša
; na mreži samo kad je pregled uključen, inače samo lokalno.
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; Flags: runhidden waituntilterminated
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""{#FirewallRule}"" dir=in action=allow program=""{app}\{#AppExe}"" protocol=TCP profile=private,domain enable=yes"; \
  Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchApp}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallRule"
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
end;

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

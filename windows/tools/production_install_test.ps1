# Solarni monitor 4.0 – test PRODUKCIJSKE instalacije (UAC, zadaci SYSTEM, usluga gatewaya, ACL, vatrozid, deinstalacija).
# Pokreće VLASNIK u PowerShellu „Pokreni kao administrator” na računalu za test (najbolje čisto računalo ili VM):
#   powershell -ExecutionPolicy Bypass -File production_install_test.ps1 -Installers "C:\Modularnisolarnidashboard40\installers\windows"
# Rezultat: production-install-test.txt pokraj skripte (PASS/FAIL po provjeri, s dokazom). Ništa se ne briše osim
# programa koje skripta sama instalira na kraju (-Uninstall); podaci u %ProgramData% ostaju.
param(
    [Parameter(Mandatory = $true)][string]$Installers,
    [string]$Pin = "246813",
    [switch]$Uninstall
)
$ErrorActionPreference = "Continue"
$out = Join-Path $PSScriptRoot "production-install-test.txt"
$lines = New-Object System.Collections.Generic.List[string]
$fail = 0
function Check([string]$name, [bool]$ok, [string]$detail = "") {
    $script:lines.Add(("{0} {1}{2}" -f ($(if ($ok) { "PASS" } else { "FAIL" }), $name, $(if ($detail) { " -- $detail" } else { "" }))))
    if (-not $ok) { $script:fail++ }
    Write-Host $script:lines[$script:lines.Count - 1]
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Check "pokrenuto s administratorskim pravima (UAC potvrđen)" $admin
if (-not $admin) { $lines | Set-Content $out -Encoding utf8; exit 1 }
$lines.Add("Računalo: $env:COMPUTERNAME, Windows $([Environment]::OSVersion.Version), $(Get-Date -Format s)")

$client = Get-ChildItem $Installers -Filter "SolarniMonitor2-Setup-*.exe" | Select-Object -First 1
$server = Get-ChildItem $Installers -Filter "SolarniServer-Setup-*.exe" | Select-Object -First 1
foreach ($f in @($client, $server)) {
    $sig = Get-AuthenticodeSignature $f.FullName
    $lines.Add("$($f.Name): SHA-256 $((Get-FileHash $f.FullName).Hash), potpis: $($sig.Status)")
}

# ---------------------------------------------------------------- instalacija
$p = Start-Process $server.FullName -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=`"$PSScriptRoot\server-setup.log`"" -Wait -PassThru
Check "instalacija poslužitelja (tiho) završena s kodom 0" ($p.ExitCode -eq 0) "kod $($p.ExitCode)"
$p = Start-Process $client.FullName -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /PIN=$Pin /LOG=`"$PSScriptRoot\client-setup.log`"" -Wait -PassThru
Check "instalacija klijenta (tiho, /PIN) završena s kodom 0" ($p.ExitCode -eq 0) "kod $($p.ExitCode)"
Start-Sleep 20

# ---------------------------------------------------------------- zadaci sustava i usluga gatewaya
foreach ($t in @("Solarni monitor 2 - poller", "SolarniPosluzitelj")) {
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Check "zadatak '$t' postoji i radi kao SYSTEM" ($task -and $task.Principal.UserId -eq "SYSTEM") "$($task.Principal.UserId) / $($task.State)"
    Check "zadatak '$t' radi" ($task -and $task.State -eq "Running") "$($task.State)"
}
for ($i = 0; $i -lt 30; $i++) {  # usluga se pokreće (odgođeno automatski + Start-Service iz instalacije)
    $svc = Get-CimInstance Win32_Service -Filter "Name='SolariGateway'"
    if ($svc -and $svc.State -eq "Running") { break }
    Start-Sleep 2
}
Check "usluga SolariGateway postoji" ($null -ne $svc)
Check "usluga radi kao NT SERVICE\SolariGateway (virtualni račun)" ($svc.StartName -eq "NT SERVICE\SolariGateway") "$($svc.StartName)"
Check "usluga je pokrenuta" ($svc.State -eq "Running") "$($svc.State)"
$privs = (& sc.exe qprivs SolariGateway) -join " "
Check "usluga ima samo SeChangeNotifyPrivilege" ($privs -match "SeChangeNotifyPrivilege" -and ($privs -split "Se[A-Za-z]+Privilege").Count -le 2) $privs
$sidtype = (& sc.exe qsidtype SolariGateway) -join " "
Check "SID usluge: UNRESTRICTED" ($sidtype -match "UNRESTRICTED") $sidtype
$gw = if ($svc -and $svc.ProcessId) { Get-Process -Id $svc.ProcessId -IncludeUserName -ErrorAction SilentlyContinue }  # proces usluge, ne bilo koji istog imena
Check "proces gatewaya radi pod NT SERVICE\SolariGateway (AC-GW-3)" ($gw -and $gw.UserName -eq "NT SERVICE\SolariGateway") "$($gw.UserName)"

# ---------------------------------------------------------------- mreža (AC-GW-2) i vatrozid
# Windows u ovom okruženju listenere prikazuje i sa stanjem koje nije Listen – zato sve veze bez udaljene adrese
$listen = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 0 -or $_.State -eq "Listen" }
$srvPids = (Get-Process SolarniServer -ErrorAction SilentlyContinue).Id
Check "C++ servis poslužitelja nema TCP listener" (-not ($listen | Where-Object { $srvPids -contains $_.OwningProcess })) (($listen | Where-Object { $srvPids -contains $_.OwningProcess } | ForEach-Object { $_.LocalPort }) -join ",")
$gwPort = $listen | Where-Object { $gw -and $_.OwningProcess -eq $gw.Id }
Check "gateway sluša 8700" (($gwPort | Where-Object LocalPort -eq 8700) -ne $null) (($gwPort | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }) -join ",")
foreach ($r in @(@{n = "Solarni posluzitelj - gateway"; port = "8700"; prog = "solari-gateway.exe"}, @{n = "Solarni monitor 2 - pregled iz mreze"; port = "8600"; prog = "SolarniMonitor.exe"})) {
    $rule = Get-NetFirewallRule -DisplayName $r.n -ErrorAction SilentlyContinue
    $pf = $rule | Get-NetFirewallPortFilter
    $af = $rule | Get-NetFirewallApplicationFilter
    Check "vatrozid '$($r.n)': port $($r.port), samo $($r.prog), profil $($rule.Profile)" ($rule -and $pf.LocalPort -eq $r.port -and $af.Program -like "*$($r.prog)") "$($pf.LocalPort) $($af.Program)"
}
Check "staro pravilo 'Solarni posluzitelj - API' (cijeli program) uklonjeno" (-not (Get-NetFirewallRule -DisplayName "Solarni posluzitelj - API" -ErrorAction SilentlyContinue))
# curl.exe -k: samopotpisani certifikat gatewaya (PS 5.1 povratni poziv za certifikat ne radi izvan runspacea)
$pingRaw = (& curl.exe -sk --max-time 10 "https://127.0.0.1:8700/api/v1/ping") -join ""
$ping = try { $pingRaw | ConvertFrom-Json } catch { $null }
Check "HTTPS ping kroz gateway → C++ servis (api 4)" ($ping -and $ping.api -eq 4) $pingRaw

# ---------------------------------------------------------------- kanali (AC-GW-4)
foreach ($pipe in @("SolarniServer.Api.v1")) {
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipe, [System.IO.Pipes.PipeDirection]::InOut)
        $c.Connect(2000); $c.Dispose()
        Check "administrator (bez promjene ACL-a) NE može otvoriti kanal $pipe" $false "spojeno"
    } catch { Check "administrator (bez promjene ACL-a) NE može otvoriti kanal $pipe" ($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.InnerException -is [UnauthorizedAccessException]) $_.Exception.Message }
}

# ---------------------------------------------------------------- ACL (SMA-02)
function Has-UsersWrite([string]$path) {
    $acl = Get-Acl $path
    foreach ($a in $acl.Access) {
        $sid = try { $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "" }
        if ($a.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }  # ne vrijedi za sam objekt
        # točni bitovi pisanja (Modify/Write sadrže i bitove čitanja): WriteData 0x2, AppendData 0x4, WriteEA 0x10,
        # DeleteChild 0x40, WriteAttributes 0x100, Delete 0x10000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000, GENERIC_ALL/WRITE
        $writeBits = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
        if ($sid -in @("S-1-5-32-545", "S-1-5-11", "S-1-1-0", "S-1-5-4") -and $a.AccessControlType -eq "Allow" -and
            (([int64]$a.FileSystemRights) -band $writeBits)) { return $true }
    }
    return $false
}
$cd = Join-Path $env:ProgramData "SolarniMonitor2"
Check "klijent: mapa postavki – Users bez prava upisa" (-not (Has-UsersWrite $cd))
foreach ($sub in @("data", "service", "config.json")) { if (Test-Path (Join-Path $cd $sub)) { Check "klijent: $sub – Users bez prava upisa" (-not (Has-UsersWrite (Join-Path $cd $sub))) } }
Check "klijent: ui\ – Users smiju mijenjati (raspored, slike)" (Has-UsersWrite (Join-Path $cd "ui"))
# 5.0.2 (audit W-05): na samoj mapi ui\ korisnici nemaju DELETE ni WRITE_DAC (ne mogu je zamijeniti vezom)
$uiDel = (Get-Acl (Join-Path $cd "ui")).Access | Where-Object {
    $sid = try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "" }
    $sid -in @("S-1-5-32-545", "S-1-5-11", "S-1-1-0") -and $_.AccessControlType -eq "Allow" -and
    -not ($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
    (([int64]$_.FileSystemRights) -band (0x10000 -bor 0x40000 -bor 0x80000)) }
Check "klijent: ui\ – Users ne mogu obrisati ni preuzeti mapu" (-not $uiDel)
# 5.0.1 (audit I-01, I-02): mapa programa bez prava upisa za korisnike (SYSTEM pokreće exe iz nje); u mapama podataka nema veza
foreach ($svcExe in @((Get-ScheduledTask -TaskName "Solarni monitor 2 - poller" -ErrorAction SilentlyContinue).Actions.Execute,
                      (Get-ScheduledTask -TaskName "SolarniPosluzitelj" -ErrorAction SilentlyContinue).Actions.Execute)) {
    if (-not $svcExe) { continue }
    $appDir = Split-Path ($svcExe.Trim('"'))
    $writable = @(@(Get-Item -LiteralPath $appDir) + @(Get-ChildItem -LiteralPath $appDir -Recurse -Force) | Where-Object { Has-UsersWrite $_.FullName })
    Check "mapa programa $appDir – Users bez prava upisa (ni na jednoj datoteci)" ($writable.Count -eq 0) (($writable | Select-Object -First 3 | ForEach-Object FullName) -join ", ")
}
foreach ($dd in @($cd, (Join-Path $env:ProgramData "SolarniServer"))) {
    if (-not (Test-Path $dd)) { continue }
    $links = @(Get-ChildItem -LiteralPath $dd -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue)
    Check "u $dd nema veza (junction/symlink)" ($links.Count -eq 0) (($links | ForEach-Object FullName) -join ", ")
}
$secrets = Join-Path $cd "secrets"
Check "klijent: secrets\ postoji (PIN iz instalacije)" (Test-Path (Join-Path $secrets "secrets.json"))
Check "klijent: secrets\ – Users nemaju nikakav pristup" (-not ((Get-Acl $secrets).Access | Where-Object { $_.IdentityReference -match "Users|Korisnici|Everyone|Svi" }))
$sd = Join-Path $env:ProgramData "SolarniServer"
# NEW-01: vlasnik i izričite dozvole – samo SYSTEM, administratori (i usluga gatewaya u gateway\)
$trusted = @("S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
foreach ($p in @($cd, (Join-Path $cd "config.json"), (Join-Path $cd "data"), $secrets, (Join-Path $secrets "secrets.json"), $sd,
                 (Join-Path $sd "config.json"), (Join-Path $sd "data\users.db"), (Join-Path $sd "data\users.key"))) {
    if (-not (Test-Path $p)) { continue }
    $acl = Get-Acl $p
    $owner = try { (New-Object Security.Principal.NTAccount $acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $acl.Owner }
    Check "vlasnik $p je SYSTEM ili Administratori (NEW-01)" ($trusted -contains $owner) $acl.Owner
}
Check "poslužitelj: mapa – samo SYSTEM i administratori" (-not ((Get-Acl $sd).Access | Where-Object { $_.IdentityReference -match "Users|Korisnici|Everyone|Svi|Authenticated" }))
Check "poslužitelj: gateway\ – usluga gatewaya ima pravo izmjene" (((Get-Acl (Join-Path $sd "gateway")).Access | Where-Object { $_.IdentityReference -eq "NT SERVICE\SolariGateway" }) -ne $null)
Check "gateway je izradio certifikat (ključ pod DPAPI-jem)" (Test-Path (Join-Path $sd "gateway\key.dpapi"))
$gwLog = Get-Content (Join-Path $sd "gateway\gateway.log") -Raw -ErrorAction SilentlyContinue
Check "gateway: DPAPI računa usluge dostupan (bez zamjene DPAPI-jem računala)" ($gwLog -and $gwLog -notmatch "DPAPI računa usluge nije dostupan") ""
Check "servis je zapisao otisak gatewaya (service\gateway.json)" (Test-Path (Join-Path $sd "service\gateway.json"))

# ponovna registracija usluge (kao popravak / ponovna instalacija preko postojećih datoteka gatewaya): datoteke ne smiju
# ostati bez DACL-a, a gateway mora ponovno raditi s istim certifikatom
$fpBefore = (Get-FileHash (Join-Path $sd "gateway\cert.der") -ErrorAction SilentlyContinue).Hash
$appDir = Split-Path (Get-CimInstance Win32_Service -Filter "Name='SolariGateway'").PathName.Split('"')[1]
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $appDir "installer\gateway_service.ps1") -Register $appDir -DataDir $sd
Check "ponovna registracija usluge gatewaya uspjela" ($LASTEXITCODE -eq 0) $LASTEXITCODE
$broken = @(Get-ChildItem (Join-Path $sd "gateway") -File -Force | Where-Object {
    $a = Get-Acl -LiteralPath $_.FullName -ErrorAction SilentlyContinue
    -not $a -or -not ($a.Access | Where-Object { $_.IdentityReference -eq "NT SERVICE\SolariGateway" })
})
Check "nakon ponovne registracije svaka datoteka u gateway\ ima dozvolu usluge (nema praznog DACL-a)" ($broken.Count -eq 0) (($broken | ForEach-Object Name) -join ",")
Start-Sleep 15
Check "gateway radi 15 s nakon ponovne registracije" ((Get-Service SolariGateway).Status -eq "Running") (Get-Service SolariGateway).Status
Check "gateway je zadržao certifikat (isti kod za uparivanje)" ($fpBefore -and $fpBefore -eq (Get-FileHash (Join-Path $sd "gateway\cert.der")).Hash)

# ---------------------------------------------------------------- broker (SMA-02) – poller kao SYSTEM
$plog = Get-Content (Join-Path $cd "service\logs\poller.log") -Raw -ErrorAction SilentlyContinue
Check "poller (SYSTEM) je pokrenuo broker postavki" ([bool]("$plog" -match "Broker postavki pokrenut")) (($plog -split "`n" | Select-String "Broker" | Select-Object -Last 2) -join " | ")

# ---------------------------------------------------------------- deinstalacija
if ($Uninstall) {
    foreach ($name in @("Solarni monitor", "Solarni poslužitelj")) {
        $u = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | ForEach-Object { Get-ItemProperty $_.PSPath } |
            Where-Object { $_.DisplayName -eq $name } | Select-Object -First 1
        if ($u) {
            $exe = ($u.UninstallString -replace '"', '')
            $p = Start-Process $exe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait -PassThru
            Check "deinstalacija '$name'" ($p.ExitCode -eq 0) "kod $($p.ExitCode)"
        }
    }
    Start-Sleep 5
    Check "usluga SolariGateway uklonjena" (-not (Get-Service SolariGateway -ErrorAction SilentlyContinue))
    Check "zadaci uklonjeni" (-not (Get-ScheduledTask -TaskName "Solarni*" -ErrorAction SilentlyContinue))
    Check "pravila vatrozida uklonjena" (-not (Get-NetFirewallRule -DisplayName "Solarni*" -ErrorAction SilentlyContinue))
    Check "podaci ostaju (tiha deinstalacija ne briše %ProgramData%)" ((Test-Path $cd) -and (Test-Path $sd))
    # 5.0.2 (audit I-11): tajne (oznake prijave, ključevi, PIN) ne ostaju nakon deinstalacije
    Check "tajne obrisane pri deinstalaciji (klijent)" (-not (Test-Path (Join-Path $cd "secrets")))
}

$lines.Add("")
$lines.Add("Ukupno FAIL: $fail")
$lines | Set-Content $out -Encoding utf8
Write-Host "Rezultat: $out"

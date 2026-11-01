# 4.0 (SMA-02, NEW-01): ACL mape podataka – poziva ga instalacija (administrator).
#   acl_setup.ps1 -DataDir "C:\ProgramData\SolarniMonitor2" -Mode client   (Users čitanje, ui\ Users izmjena)
#   acl_setup.ps1 -DataDir "C:\ProgramData\SolarniServer"  -Mode server   (samo SYSTEM i Administratori)
# Vlasnik svega postaje BUILTIN\Administrators, a sve izričite dozvole se brišu – i one korisnika koji je mapu, secrets\ ili
# datoteku stvorio prije instalacije (ili iz 3.x). Redoslijed čuva secrets\ zatvorenim u svakom trenutku:
#   1. vlasnik (cijelo stablo) → 2. secrets\ atomično zaštićen (SYSTEM + Administratori), zatim njegov sadržaj nasljeđuje
#   → 3. korijen atomično zaštićen → ostale mape i datoteke nasljeđuju (/reset) → 4. ui\ (klijent).
# 5.0.1 (audit I-01): mapa podataka ne smije biti veza (junction/symlink), a veze unutar nje (npr. podmetnute u ui\
# prije instalacije) uklanjaju se kao veze – cilj se ne dira. icacls uvijek s /L (radi na vezi, ne na cilju), pa se
# dozvole nikad ne prenose na mapu programa ni drugu mapu izvan podataka.
param(
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][ValidateSet("client", "server")][string]$Mode,
    [string]$AppDir = ""   # 5.0.1 (audit I-02): mapa programa – zaštićeni ACL (korisnici samo čitaju i pokreću)
)
$ErrorActionPreference = "Stop"
$SY = "S-1-5-18"; $BA = "S-1-5-32-544"; $USERS = "S-1-5-32-545"

function Rule([string]$sid, [string]$rights) {
    New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier $sid), $rights, "ContainerInherit,ObjectInherit", "None", "Allow")
}

function Set-ProtectedAcl([string]$path, $rules) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)  # bez nasljeđivanja i bez zadržavanja starih ACE-ova
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier $BA))
    foreach ($r in $rules) { $acl.AddAccessRule($r) }
    Set-Acl -LiteralPath $path -AclObject $acl  # jedna zamjena cijelog DACL-a
}

function Reset-Children([string]$dir, [string]$except = "") {
    Get-ChildItem -LiteralPath $dir -Force | Where-Object { $_.Name -ne $except } | ForEach-Object {
        & icacls.exe $_.FullName /reset /T /C /L /Q | Out-Null
    }
}

function Test-Reparse([string]$path) {
    return (([IO.File]::GetAttributes($path)) -band [IO.FileAttributes]::ReparsePoint) -ne 0
}

# Ukloni sve veze u stablu (bez ulaska u njih): mapa-veza se briše kao veza (Directory.Delete bez rekurzije), datoteka-veza
# kao datoteka. Cilj veze ostaje netaknut.
function Remove-ReparsePoints([string]$dir) {
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($dir)) {
        $attrs = [IO.File]::GetAttributes($entry)
        if ($attrs -band [IO.FileAttributes]::ReparsePoint) {
            if ($attrs -band [IO.FileAttributes]::Directory) { [IO.Directory]::Delete($entry, $false) } else { [IO.File]::Delete($entry) }
            Write-Warning "uklonjena veza u mapi podataka: $entry"
        } elseif ($attrs -band [IO.FileAttributes]::Directory) {
            Remove-ReparsePoints $entry
        }
    }
}

if (Test-Path -LiteralPath $DataDir) {
    if (Test-Reparse $DataDir) { throw "Mapa podataka $DataDir je veza (junction/symlink) – instalacija se prekida. Uklonite je i pokrenite instalaciju ponovno." }
    Remove-ReparsePoints $DataDir
}
New-Item -ItemType Directory -Force $DataDir | Out-Null
if (Test-Reparse $DataDir) { throw "Mapa podataka $DataDir je veza – instalacija se prekida." }
& icacls.exe $DataDir /setowner "*$BA" /T /C /L /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "icacls /setowner: $LASTEXITCODE" }

$secrets = Join-Path $DataDir "secrets"
# 5.0.1 (audit I-01): secrets\ stvara samo instalacija ili zadatak sustava (vlasnik Administratori/SYSTEM). Ako vlasnik mape ili
# ijedne datoteke u njoj nije pouzdan (podmetnuto prije instalacije), sve ide u karantenu i ništa iz nje se ne koristi.
$trusted = @($SY, $BA, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")  # + TrustedInstaller
function Owner-Sid([string]$path) { (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value }
if (Test-Path -LiteralPath $secrets) {
    $untrusted = @(@(Get-Item -LiteralPath $secrets -Force) + @(Get-ChildItem -LiteralPath $secrets -Force -Recurse) |
        Where-Object { $trusted -notcontains (Owner-Sid $_.FullName) })
    if ($untrusted.Count -gt 0) {
        $quarantine = "$secrets.untrusted-$(Get-Date -Format yyyyMMddHHmmss)"
        Rename-Item -LiteralPath $secrets -NewName (Split-Path $quarantine -Leaf)
        Set-ProtectedAcl $quarantine @((Rule $SY "FullControl"), (Rule $BA "FullControl"))
        Reset-Children $quarantine
        Write-Warning "secrets\ nije stvorila instalacija (vlasnik: $(Owner-Sid $untrusted[0].FullName)) – premješteno u $quarantine"
    }
}
if (Test-Path -LiteralPath $secrets) {
    Set-ProtectedAcl $secrets @((Rule $SY "FullControl"), (Rule $BA "FullControl"))
    Reset-Children $secrets
}

$rootRules = @((Rule $SY "FullControl"), (Rule $BA "FullControl"))
if ($Mode -eq "client") { $rootRules += (Rule $USERS "ReadAndExecute") }
Set-ProtectedAcl $DataDir $rootRules
Reset-Children $DataDir "secrets"

if ($Mode -eq "client") {
    $ui = Join-Path $DataDir "ui"
    if ((Test-Path -LiteralPath $ui) -and (Test-Reparse $ui)) { [IO.Directory]::Delete($ui, $false) }  # utrka nakon čišćenja
    New-Item -ItemType Directory -Force $ui | Out-Null
    if (Test-Reparse $ui) { throw "ui\ je veza – instalacija se prekida." }
    # dozvola samo na mapi ui\ (bez /T): datoteke i podmape je nasljeđuju nakon /reset iz koraka 3
    # 5.0.2 (audit W-05): na samoj mapi ui\ korisnici smiju samo čitati i dodavati (bez brisanja ili zamjene mape);
    # izmjena vrijedi samo za sadržaj (IO = samo nasljeđivanje)
    & icacls.exe $ui /grant "*$($USERS):(RX,WD,AD)" /C /L /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls (ui): $LASTEXITCODE" }
    & icacls.exe $ui /grant "*$($USERS):(OI)(CI)(IO)M" /C /L /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls (ui, sadržaj): $LASTEXITCODE" }
}

if ($AppDir) {
    # 5.0.1 (audit I-02): mapa programa iz koje SYSTEM pokreće exe – bez prava pisanja za korisnike, i kad je instalacija
    # u mapi izvan Program Files (npr. C:\Solarni nasljeđuje „Authenticated Users: Modify” s korijena diska)
    if (Test-Reparse $AppDir) { throw "Mapa programa $AppDir je veza – instalacija se prekida." }
    $appRules = @((Rule $SY "FullControl"), (Rule $BA "FullControl"), (Rule $USERS "ReadAndExecute"),
                  (Rule "S-1-15-2-1" "ReadAndExecute"), (Rule "S-1-15-2-2" "ReadAndExecute"))
    Set-ProtectedAcl $AppDir $appRules
    Reset-Children $AppDir
}

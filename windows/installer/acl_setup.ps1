# 4.0 (SMA-02, NEW-01): ACL mape podataka – poziva ga instalacija (administrator).
#   acl_setup.ps1 -DataDir "C:\ProgramData\SolarniMonitor2" -Mode client   (Users čitanje, ui\ Users izmjena)
#   acl_setup.ps1 -DataDir "C:\ProgramData\SolarniServer"  -Mode server   (samo SYSTEM i Administratori)
# Vlasnik svega postaje BUILTIN\Administrators, a sve izričite dozvole se brišu – i one korisnika koji je mapu, secrets\ ili
# datoteku stvorio prije instalacije (ili iz 3.x). Redoslijed čuva secrets\ zatvorenim u svakom trenutku:
#   1. vlasnik (cijelo stablo) → 2. secrets\ atomično zaštićen (SYSTEM + Administratori), zatim njegov sadržaj nasljeđuje
#   → 3. korijen atomično zaštićen → ostale mape i datoteke nasljeđuju (/reset) → 4. ui\ (klijent).
param(
    [Parameter(Mandatory = $true)][string]$DataDir,
    [Parameter(Mandatory = $true)][ValidateSet("client", "server")][string]$Mode
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
        & icacls.exe $_.FullName /reset /T /C /Q | Out-Null
    }
}

New-Item -ItemType Directory -Force $DataDir | Out-Null
& icacls.exe $DataDir /setowner "*$BA" /T /C /Q | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning "icacls /setowner: $LASTEXITCODE" }

$secrets = Join-Path $DataDir "secrets"
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
    New-Item -ItemType Directory -Force $ui | Out-Null
    & icacls.exe $ui /grant "*$($USERS):(OI)(CI)M" /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls (ui): $LASTEXITCODE" }
}

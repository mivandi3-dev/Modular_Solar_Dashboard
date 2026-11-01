# 4.0 (B1): Windows usluga SolariGateway (solari-gateway.exe --service) s virtualnim računom NT SERVICE\SolariGateway –
# bez administratorskih prava, samo SeChangeNotifyPrivilege. Poziva je instalacija Solarnog poslužitelja:
#   gateway_service.ps1 -Register "<mapa programa>" -DataDir "<%ProgramData%\SolarniServer>"  |  -Unregister  |  -Stop
param(
    [string]$Register,
    [string]$DataDir,
    [switch]$Unregister,
    [switch]$Stop
)
$ErrorActionPreference = "Stop"
$Name = "SolariGateway"

function Invoke-Sc([string]$arguments) {
    # Start-Process: argumenti idu doslovno (PowerShell 5.1 inače kvari ugniježđene navodnike u binPath=)
    $p = Start-Process -FilePath "$env:SystemRoot\System32\sc.exe" -ArgumentList $arguments -Wait -NoNewWindow -PassThru
    return $p.ExitCode
}

function Stop-Gateway {
    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne "Stopped") {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        try { $s.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(20)) } catch { }
    }
}

if ($Stop) { Stop-Gateway; exit 0 }
if ($Unregister) {
    Stop-Gateway
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) { Invoke-Sc "delete $Name" | Out-Null }
    exit 0
}
if ($Register) {
    if (-not $DataDir) { throw "-DataDir je obavezan" }
    Stop-Gateway
    $exe = Join-Path $Register "solari-gateway.exe"
    $bin = "binPath= `"\`"$exe\`" --service`" obj= `"NT SERVICE\$Name`" start= delayed-auto"
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        $rc = Invoke-Sc "config $Name $bin"
    } else {
        $rc = Invoke-Sc "create $Name $bin DisplayName= `"Solarni posluzitelj - mrezni ulaz`""
    }
    if ($rc -ne 0) { throw "sc create/config: $rc" }
    Invoke-Sc "description $Name `"Solarni monitor 4.0: HTTPS ulaz Solarnog posluzitelja (bez administratorskih prava)`"" | Out-Null
    Invoke-Sc "sidtype $Name unrestricted" | Out-Null
    Invoke-Sc "privs $Name SeChangeNotifyPrivilege" | Out-Null
    Invoke-Sc "failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/60000" | Out-Null
    Invoke-Sc "failureflag $Name 1" | Out-Null  # ponovno pokretanje i kad usluga sama javi grešku (izlazni kod ≠ 0)

    # mapa gatewaya: certifikat (ključ pod DPAPI-jem usluge) i zapisnik – SYSTEM, Administratori, usluga gatewaya
    $gw = Join-Path $DataDir "gateway"
    New-Item -ItemType Directory -Force $gw | Out-Null
    # samo mapa dobiva zaštićeni ACL; datoteke u njoj NASLJEĐUJU (/reset). Ne /T s (OI)(CI) dozvolama: na datoteci
    # /inheritance:r ukloni naslijeđene ACE-ove, a (OI)(CI) ne vrijedi za datoteku – ostaje prazan DACL i ni usluga ni
    # administrator ne mogu čitati ključ, certifikat ni zapisnik (gateway nakon ponovne instalacije ne može krenuti).
    & icacls.exe $gw /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\${Name}:(OI)(CI)M" /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls (gateway): $LASTEXITCODE" }
    if (Get-ChildItem -LiteralPath $gw -Force -ErrorAction SilentlyContinue) {
        & icacls.exe (Join-Path $gw "*") /reset /T /C /Q | Out-Null  # popravlja i datoteke oštećene starijom instalacijom
        if ($LASTEXITCODE -ne 0) { throw "icacls (gateway, datoteke): $LASTEXITCODE" }
    }
    Start-Service -Name $Name
}

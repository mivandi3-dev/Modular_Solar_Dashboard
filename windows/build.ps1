# Gradi Solarni monitor 2 (C++) i njegovu instalaciju: build\output\SolarniMonitor2-Setup-<verzija>.exe
#
#   powershell -ExecutionPolicy Bypass -File windows\build.ps1 [-Build <mapa>]
#
# Preduvjeti (samo na računalu na kojem se gradi):
#   winget install MartinStorsjo.LLVM-MinGW.UCRT Kitware.CMake Ninja-build.Ninja JRSoftware.InnoSetup
param([string]$Build = "")  # 4.0: mapa gradnje (zadano: build u mapi windows); npr. -Build <izlazna mapa>
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
if (-not $Build) { $Build = Join-Path $Root "build" }
$Redist = Join-Path $Build "redist"

function Step($text) { Write-Host "==> $text" -ForegroundColor Green }
function Find-Tool($name, [string[]]$extra = @()) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $found = $extra | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $found) { throw "$name nije pronađen – vidi preduvjete na početku build.ps1" }
    return $found
}

# winget alati su u korisničkom PATH-u; nova sesija ih možda još ne vidi
$env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + $env:Path
$llvm = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW*\*\bin" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if ($llvm) { $env:Path = "$($llvm.FullName);$env:LOCALAPPDATA\Microsoft\WinGet\Links;$env:Path" }
$Cmake = Find-Tool cmake
$Clang = Find-Tool clang++
$Iscc = Find-Tool ISCC @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe")
$Version = (Select-String -Path "$Root\CMakeLists.txt" -Pattern 'project\(SolarniMonitor2 VERSION ([\d.]+)').Matches[0].Groups[1].Value
Step "Solarni monitor $Version (C++) · $Clang"

Step "Vanjske biblioteke"
& powershell -NoProfile -ExecutionPolicy Bypass -File "$Root\third_party\fetch.ps1"

Step "Prevođenje (Release)"
& $Cmake -S $Root -B $Build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_RC_COMPILER=windres -DSOLARI_DEV_NO_UAC=OFF | Out-Null
if ($LASTEXITCODE -ne 0) { throw "CMake konfiguracija nije uspjela" }
& $Cmake --build $Build
if ($LASTEXITCODE -ne 0) { throw "Prevođenje nije uspjelo" }

Step "Testovi"
& "$Build\solari_tests.exe"
if ($LASTEXITCODE -ne 0) { throw "Testovi nisu prošli – instalacija se ne gradi" }

Step "Rust gateway (B1)"
# fiksni toolchain iz gateway\rust-toolchain.toml (rustup ga preuzme ako ga nema); zaključane ovisnosti (--locked)
$Cargo = Find-Tool cargo @("$env:USERPROFILE\.cargo\bin\cargo.exe")
$GatewaySrc = Join-Path (Split-Path $Root -Parent) "gateway"
$env:CARGO_TARGET_DIR = Join-Path $Build "gateway-target"
Push-Location $GatewaySrc
try {
    & $Cargo test --release --locked
    if ($LASTEXITCODE -ne 0) { throw "Testovi gatewaya nisu prošli – instalacija se ne gradi" }
    & $Cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw "Gradnja gatewaya nije uspjela" }
} finally {
    Pop-Location
}
Copy-Item (Join-Path $env:CARGO_TARGET_DIR "release\solari-gateway.exe") (Join-Path $Build "solari-gateway.exe") -Force

Step "Provjera ovisnosti (samo sistemski DLL-ovi)"
# 4.0: ciljno računalo nema llvm-mingw – exe koji uvozi libunwind.dll / libc++.dll se tamo ne pokreće (usluga: istek roka)
$Objdump = Find-Tool llvm-objdump
foreach ($exe in "SolarniMonitor.exe", "SolarniServer.exe", "solari-gateway.exe") {
    $dlls = & $Objdump -p (Join-Path $Build $exe) | Select-String "DLL Name: (.+)$" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
    $bad = $dlls | Where-Object { $_ -match "^(libunwind|libc\+\+|libwinpthread|libgcc|libstdc\+\+)" }
    if ($bad) { throw "$exe uvozi DLL koji na ciljnom računalu ne postoji: $($bad -join ', ')" }
}

$WebView = Join-Path $Redist "MicrosoftEdgeWebview2Setup.exe"
if (-not (Test-Path $WebView)) {
    Step "Preuzimanje WebView2 bootstrappera"
    New-Item -ItemType Directory -Force $Redist | Out-Null
    Invoke-WebRequest "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $WebView -UseBasicParsing
}
# 4.0 (SMA-12): bootstrapper se mijenja (evergreen) pa se umjesto sažetka provjerava Microsoftov Authenticode potpis
$sig = Get-AuthenticodeSignature $WebView
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
    Remove-Item $WebView -Force
    throw "WebView2 bootstrapper nema valjan Microsoftov potpis – gradnja zaustavljena"
}

Step "Inno Setup"
& $Iscc /Q "/DAppVersion=$Version" "/DBuild=$Build" "/DRedist=$Redist" "$Root\installer\SolarniMonitor2.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup nije uspio" }
& $Iscc /Q "/DAppVersion=$Version" "/DBuild=$Build" "/DRedist=$Redist" /DServer "$Root\installer\SolarniMonitor2.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup (poslužitelj) nije uspio" }
Step ("Poslužitelj: {0}" -f (Get-Item "$Build\output\SolarniServer-Setup-$Version.exe").FullName)
$Setup = Get-Item "$Build\output\SolarniMonitor2-Setup-$Version.exe"
Step ("Gotovo: {0} ({1:N1} MB)" -f $Setup.FullName, ($Setup.Length / 1MB))

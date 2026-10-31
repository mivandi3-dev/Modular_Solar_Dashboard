# Izgradnja Android aplikacije: web sučelje iz windows/web i potpisani APK u deploy\.
#   powershell -ExecutionPolicy Bypass -File android\build.ps1
# Potrebno: JDK 17, Android SDK (platforma 34, build-tools 34). Ključ za potpisivanje: android\keystore.properties
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

if (-not $env:JAVA_HOME) {
    $jdk = Get-ChildItem "C:\Program Files\Microsoft", "C:\Program Files\Eclipse Adoptium" -Directory -Filter "jdk-17*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($jdk) { $env:JAVA_HOME = $jdk.FullName }
}
if (-not (Test-Path "$PSScriptRoot\local.properties")) {
    "sdk.dir=$(("$env:LOCALAPPDATA\Android\Sdk") -replace '\\', '\\')" | Set-Content -Encoding ascii "$PSScriptRoot\local.properties"
}

Step "Gradle: assembleRelease i bundleRelease (.aab za Google Play)"
Push-Location $PSScriptRoot
try {
    $ErrorActionPreference = "Continue"  # napomene javac-a na stderr nisu greške – odlučuje izlazni kod
    & .\gradlew.bat assembleRelease bundleRelease --console=plain -q 2>&1 | Where-Object { $_ -notmatch "^Note:" } | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($code -ne 0) { throw "Gradle nije uspio" }
} finally {
    Pop-Location
}

$version = (Select-String -Path "$PSScriptRoot\app\build.gradle" -Pattern 'versionName "(.+)"').Matches[0].Groups[1].Value
$deploy = Join-Path $Root "deploy"
New-Item -ItemType Directory -Force $deploy | Out-Null
$apk = Join-Path $deploy "SolarniMonitor-Android-$version.apk"
Copy-Item "$PSScriptRoot\app\build\outputs\apk\release\app-release.apk" $apk -Force
Copy-Item "$PSScriptRoot\app\build\outputs\bundle\release\app-release.aab" (Join-Path $deploy "SolarniMonitor-Android-$version.aab") -Force
if (-not (Test-Path "$PSScriptRoot\keystore.properties")) { Write-Warning "Nema keystore.properties – APK je potpisan testnim (debug) ključem." }
Step ("Gotovo: {0} ({1:N1} MB)" -f $apk, ((Get-Item $apk).Length / 1MB))

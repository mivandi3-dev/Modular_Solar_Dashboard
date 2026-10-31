# Preuzima vanjske biblioteke u third_party/ (pokreće ga build.ps1) i PROVJERAVA SHA-256 svake datoteke (4.0, SMA-12).
#   nlohmann/json 3.11.3 (MIT) · SQLite 3.50.4 (javno dobro) · doctest 2.4.11 (MIT)
#   Microsoft.Web.WebView2 SDK 1.0.2903.40 (BSD) · plotly.js-basic 2.35.2 (MIT) · curl 8.23.0_6 (curl/MIT)
# Font Plus Jakarta Sans (OFL) je u repozitoriju (web/vendor). Datoteka s pogrešnim sažetkom se briše i gradnja staje.
# Sažeci su izračunati iz datoteka preuzetih s navedenih službenih adresa; nova verzija = novi sažetak u ovoj tablici.
$ErrorActionPreference = "Stop"
$Dir = $PSScriptRoot
$Web = Join-Path (Split-Path $Dir) "web\vendor"
$ProgressPreference = "SilentlyContinue"

$Expected = [ordered]@{
    "nlohmann\json.hpp"                             = "9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6"
    "doctest\doctest.h"                             = "44faa038e9c3f9728efbda143748d01124ea0a27f4bf78f35a15d8fab2e039fb"
    "sqlite\sqlite3.c"                              = "e3f5d6901e7492af4a1fc8c4d745cae84c264942524c3fbfc02b82a5ca8818c8"
    "sqlite\sqlite3.h"                              = "abd1514e0351f79393d1be882830afdb40a8099e8257f311f0bfdf8486f11bea"
    "webview2\include\WebView2.h"                   = "8d298691104964129bd6bd8fc3119608607d794135752dc02217f72f7bddedb1"
    "webview2\include\WebView2EnvironmentOptions.h" = "c2a2eac494f4b0c766fa19e1788ad0474a36e4dd9b8b1b22aded7172fcbf8f18"
    "webview2\x64\WebView2Loader.dll"               = "462b36fd1be6ca9f7563466a89e57c41ef4a4def3e0a84fa885d203aea4a3aaf"
    "curl\curl.exe"                                 = "546c585d608b0f3998be1c3006ae6a27a1d260c1da6f9ea74478d66abedd61ae"
    "..\web\vendor\plotly-basic.min.js"             = "138c2e81014b979dc00867a93da55b7605a17495ee78dd7afb433b7f021dfcfa"
    "..\web\vendor\PlusJakartaSans.ttf"             = "89b3fb38aa0d275d7a731d0d817a4f1622b316b4d7fbdedcf02ee9099ff68bc8"
}

function Get-File($url, $out) {
    if (Test-Path $out) { return }
    New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
    Write-Host "  $url"
    Invoke-WebRequest $url -OutFile $out -UseBasicParsing
}

function Expand-Fresh($zip, $dest) {
    if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
    Expand-Archive $zip $dest -Force
}

Get-File "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp" "$Dir\nlohmann\json.hpp"
Get-File "https://raw.githubusercontent.com/doctest/doctest/v2.4.11/doctest/doctest.h" "$Dir\doctest\doctest.h"

if (-not (Test-Path "$Dir\sqlite\sqlite3.c")) {
    $zip = "$env:TEMP\sqlite-amalgamation.zip"
    Get-File "https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip" $zip
    Expand-Fresh $zip "$env:TEMP\sqlite-amalgamation"
    New-Item -ItemType Directory -Force "$Dir\sqlite" | Out-Null
    Copy-Item "$env:TEMP\sqlite-amalgamation\sqlite-amalgamation-3500400\sqlite3.c", "$env:TEMP\sqlite-amalgamation\sqlite-amalgamation-3500400\sqlite3.h" "$Dir\sqlite\"
    Remove-Item $zip
}

if (-not (Test-Path "$Dir\webview2\include\WebView2.h")) {
    $pkg = "$env:TEMP\webview2.zip"
    Get-File "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.2903.40" $pkg
    Expand-Fresh $pkg "$env:TEMP\webview2-sdk"
    New-Item -ItemType Directory -Force "$Dir\webview2\include", "$Dir\webview2\x64" | Out-Null
    Copy-Item "$env:TEMP\webview2-sdk\build\native\include\WebView2.h", "$env:TEMP\webview2-sdk\build\native\include\WebView2EnvironmentOptions.h" "$Dir\webview2\include\"
    Copy-Item "$env:TEMP\webview2-sdk\build\native\x64\WebView2Loader.dll" "$Dir\webview2\x64\"
    Copy-Item "$env:TEMP\webview2-sdk\LICENSE.txt" "$Dir\webview2\LICENSE.txt" -ErrorAction SilentlyContinue
    Remove-Item $pkg
}

Get-File "https://cdn.jsdelivr.net/npm/plotly.js-basic-dist-min@2.35.2/plotly-basic.min.js" "$Web\plotly-basic.min.js"

# curl za Windows (curl.se) – Windows Server 2016 i Win10 prije 1803 nemaju curl.exe
if (-not (Test-Path "$Dir\curl\curl.exe")) {
    $zip = "$env:TEMP\curl-win64.zip"
    Get-File "https://curl.se/windows/dl-8.23.0_6/curl-8.23.0_6-win64-mingw.zip" $zip
    Expand-Fresh $zip "$env:TEMP\curl-win64"
    $src = Get-ChildItem "$env:TEMP\curl-win64" -Directory | Select-Object -First 1
    New-Item -ItemType Directory -Force "$Dir\curl" | Out-Null
    Copy-Item "$($src.FullName)\bin\curl.exe" "$Dir\curl\"  # statički povezan; certifikati iz Windowsa (--ca-native)
    Copy-Item "$($src.FullName)\COPYING.txt" "$Dir\curl\LICENSE.txt" -ErrorAction SilentlyContinue
    Remove-Item $zip
}

# Provjera sažetaka (i za datoteke koje su već bile na disku)
$bad = @()
foreach ($rel in $Expected.Keys) {
    $path = Join-Path $Dir $rel
    if (-not (Test-Path $path)) { $bad += "$rel (nema datoteke)"; continue }
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $Expected[$rel]) {
        $bad += "$rel (SHA-256 $hash)"
        if ($rel -notlike "*PlusJakartaSans*") { Remove-Item $path -Force }  # podmetnuta/oštećena datoteka se ne koristi
    }
}
if ($bad.Count) { throw ("Neispravne vanjske datoteke – gradnja zaustavljena:`n  " + ($bad -join "`n  ")) }
Write-Host "Biblioteke su spremne (SHA-256 provjeren za $($Expected.Count) datoteka)."

# Preuzima vanjske biblioteke u third_party/ (pokreće ga build.ps1 ako nešto nedostaje).
#   nlohmann/json 3.11.3 (MIT) · SQLite 3.50.4 (javno dobro) · doctest 2.4.11 (MIT)
#   Microsoft.Web.WebView2 SDK 1.0.2903.40 (BSD) · plotly.js-basic 2.35.2 (MIT) · Plus Jakarta Sans (OFL)
$ErrorActionPreference = "Stop"
$Dir = $PSScriptRoot
$ProgressPreference = "SilentlyContinue"

function Get-File($url, $out) {
    if (Test-Path $out) { return }
    New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
    Write-Host "  $url"
    Invoke-WebRequest $url -OutFile $out -UseBasicParsing
}

Get-File "https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp" "$Dir\nlohmann\json.hpp"
Get-File "https://raw.githubusercontent.com/doctest/doctest/v2.4.11/doctest/doctest.h" "$Dir\doctest\doctest.h"

if (-not (Test-Path "$Dir\sqlite\sqlite3.c")) {
    $zip = "$env:TEMP\sqlite-amalgamation.zip"
    Get-File "https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip" $zip
    Expand-Archive $zip "$env:TEMP\sqlite-amalgamation" -Force
    New-Item -ItemType Directory -Force "$Dir\sqlite" | Out-Null
    Copy-Item "$env:TEMP\sqlite-amalgamation\sqlite-amalgamation-3500400\sqlite3.*" "$Dir\sqlite\"
    Remove-Item $zip
}

if (-not (Test-Path "$Dir\webview2\include\WebView2.h")) {
    $pkg = "$env:TEMP\webview2.zip"
    Get-File "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.2903.40" $pkg
    Expand-Archive $pkg "$env:TEMP\webview2-sdk" -Force
    New-Item -ItemType Directory -Force "$Dir\webview2\include", "$Dir\webview2\x64" | Out-Null
    Copy-Item "$env:TEMP\webview2-sdk\build\native\include\WebView2*.h" "$Dir\webview2\include\"
    Copy-Item "$env:TEMP\webview2-sdk\build\native\x64\WebView2Loader.dll" "$Dir\webview2\x64\"
    Copy-Item "$env:TEMP\webview2-sdk\LICENSE.txt" "$Dir\webview2\LICENSE.txt" -ErrorAction SilentlyContinue
    Remove-Item $pkg
}

$Web = Join-Path (Split-Path $Dir) "web\vendor"
Get-File "https://cdn.jsdelivr.net/npm/plotly.js-basic-dist-min@2.35.2/plotly-basic.min.js" "$Web\plotly-basic.min.js"

# curl za Windows (curl.se, licenca curl/MIT) – Windows Server 2016 i Win10 prije 1803 nemaju curl.exe
if (-not (Test-Path "$Dir\curl\curl.exe")) {
    $zip = "$env:TEMP\curl-win64.zip"
    Get-File "https://curl.se/windows/dl-8.23.0_6/curl-8.23.0_6-win64-mingw.zip" $zip
    Expand-Archive $zip "$env:TEMP\curl-win64" -Force
    $src = Get-ChildItem "$env:TEMP\curl-win64" -Directory | Select-Object -First 1
    New-Item -ItemType Directory -Force "$Dir\curl" | Out-Null
    Copy-Item "$($src.FullName)\bin\curl.exe" "$Dir\curl\"  # statički povezan; certifikati iz Windowsa (--ca-native)
    Copy-Item "$($src.FullName)\COPYING.txt" "$Dir\curl\LICENSE.txt" -ErrorAction SilentlyContinue
    Remove-Item $zip
}
if (-not (Test-Path "$Web\PlusJakartaSans.ttf")) {
    Copy-Item (Join-Path (Split-Path (Split-Path $Dir)) "static\fonts\PlusJakartaSans.ttf") "$Web\PlusJakartaSans.ttf"
}
Write-Host "Biblioteke su spremne."

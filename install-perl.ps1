# PineCrack - install Strawberry Perl (needed for John's *2john ".pl" hash extractors,
# e.g. 7z2john.pl). Downloads the official portable build and writes perl_path into the config.
# The installer runs this as Administrator. Re-run any time:
#     powershell -ExecutionPolicy Bypass -File install-perl.ps1
param([switch]$NoPause)
$ErrorActionPreference = "Continue"
$ProgressPreference = 'SilentlyContinue'   # ~100x faster Invoke-WebRequest (progress bar is the bottleneck)
try { $OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$URL    = "https://strawberryperl.com/download/5.32.1.1/strawberry-perl-5.32.1.1-64bit-portable.zip"
$zip    = Join-Path $env:TEMP "pinecrack_sperl.zip"
$target = "C:\strawberry"

Write-Host "==================================================================="
Write-Host "  PineCrack - installing Strawberry Perl (for .pl hash extractors)"
Write-Host "==================================================================="
Write-Host ""
Write-Host "[1/3] Downloading Strawberry Perl portable (~152 MB)..."
try {
    Invoke-WebRequest -Uri $URL -OutFile $zip -UseBasicParsing -TimeoutSec 900
} catch {
    Write-Host "  download failed: $($_.Exception.Message)"
}

if (Test-Path $zip) {
    Write-Host "[2/3] Extracting to $target ..."
    try {
        if (Test-Path $target) { Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        Expand-Archive -Path $zip -DestinationPath $target -Force
    } catch { Write-Host "  extract failed: $($_.Exception.Message)" }
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
}

Write-Host "[3/3] Writing perl_path into PineCrack config..."
$perl = Get-ChildItem $target -Recurse -Filter "perl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($perl) {
    $cfgPath = Join-Path $env:LOCALAPPDATA "PineCrack\pinecrack_config.json"
    New-Item -ItemType Directory -Force -Path (Split-Path $cfgPath -Parent) | Out-Null
    $cfg = $null
    if (Test-Path $cfgPath) { try { $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json } catch { $cfg = $null } }
    if ($null -eq $cfg) { $cfg = [PSCustomObject]@{} }
    $cfg | Add-Member -NotePropertyName perl_path -NotePropertyValue $perl.FullName -Force
    $cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $cfgPath -Encoding UTF8
    Write-Host ""
    Write-Host "SUCCESS - Strawberry Perl: $($perl.FullName)"
} else {
    Write-Host ""
    Write-Host "Perl was not installed - check your internet connection and re-run this script."
}
Write-Host ""
if (-not $NoPause) { Read-Host "Press Enter to close" }

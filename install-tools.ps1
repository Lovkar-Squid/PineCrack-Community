# PineCrack - download + install the cracking engine (hashcat, and aircrack-ng).
# Downloads from the OFFICIAL sites (hashcat.net / aircrack-ng.org). An OPTIONAL private
# fallback (e.g. your own server) can be enabled by setting the PINECRACK_TOOLS_URL
# environment variable to a .rar of the tools — it is NOT stored in this repo.
# Then writes the tool paths into the PineCrack config so the app finds them.
# The installer runs this as Administrator. You can re-run it any time:
#     powershell -ExecutionPolicy Bypass -File install-tools.ps1
param(
    [string]$Root = ($env:SystemDrive + "\"),
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA "PineCrack\pinecrack_config.json"),
    [switch]$NoPause
)
$ErrorActionPreference = "Continue"
$ProgressPreference = 'SilentlyContinue'   # ~100x faster Invoke-WebRequest (progress bar is the bottleneck)
try { $OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$sevenzr  = Join-Path $here "7zr.exe"
$unrar    = Join-Path $here "UnRAR.exe"
$tmp      = Join-Path $env:TEMP ("pinecrack_tools_" + ([guid]::NewGuid().ToString("N").Substring(0,6)))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$HC_URL  = "https://hashcat.net/files/hashcat-7.1.2.7z"
$AC_URL  = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
$SRV_URL = $env:PINECRACK_TOOLS_URL   # optional PRIVATE fallback; set this env var on your own machines (never committed)

Write-Host "==================================================================="
Write-Host "  PineCrack - installing hashcat (+ aircrack-ng)"
Write-Host "  official sites (optional private fallback via PINECRACK_TOOLS_URL)"
Write-Host "==================================================================="
Write-Host ""

function Try-DL($url, $out, $minKB) {
    try {
        Write-Host ("  downloading " + [IO.Path]::GetFileName($out) + " ...")
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 300
        return (Test-Path $out) -and ((Get-Item $out).Length -gt ($minKB * 1KB))
    } catch { Write-Host ("    failed: " + $_.Exception.Message); return $false }
}

$haveHC = $false; $haveAC = $false

# ---- 1) official downloads -------------------------------------------------
Write-Host "[1/3] Trying official downloads (hashcat.net, aircrack-ng.org)..."
$hc7z  = Join-Path $tmp "hashcat.7z"
$aczip = Join-Path $tmp "aircrack.zip"
$okHC = Try-DL $HC_URL  $hc7z  5000
$okAC = Try-DL $AC_URL  $aczip 1000

if ($okHC) {
    Write-Host "  extracting hashcat..."
    & $sevenzr x $hc7z ("-o" + $Root) -y | Out-Null
    $d = Get-ChildItem $Root -Directory -Filter "hashcat-*" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($d) {
        $dest = Join-Path $Root "hashcat"
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue }
        Rename-Item $d.FullName $dest -ErrorAction SilentlyContinue
        $haveHC = Test-Path (Join-Path $dest "hashcat.exe")
    }
}
if ($okAC) {
    Write-Host "  extracting aircrack-ng..."
    $acx = Join-Path $tmp "ac"
    New-Item -ItemType Directory -Force -Path $acx | Out-Null
    try { Expand-Archive -Path $aczip -DestinationPath $acx -Force } catch { & tar -xf $aczip -C $acx 2>$null }
    $exe = Get-ChildItem $acx -Recurse -Filter "aircrack-ng.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($exe) {
        $dest = Join-Path $Root "aircrack-ng"
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue }
        $top = Get-ChildItem $acx -Directory | Select-Object -First 1
        if ($top) { Copy-Item $top.FullName $dest -Recurse -Force } else { Copy-Item $acx $dest -Recurse -Force }
        $haveAC = [bool](Get-ChildItem $dest -Recurse -Filter "aircrack-ng.exe" -ErrorAction SilentlyContinue | Select-Object -First 1)
    }
}

# ---- 2) optional private fallback (only if PINECRACK_TOOLS_URL is set) ------
if ((-not $haveHC -or -not $haveAC) -and $SRV_URL) {
    Write-Host "[2/3] Official incomplete - trying your private fallback (PINECRACK_TOOLS_URL)..."
    $rar = Join-Path $tmp "pctools.rar"
    if (Try-DL $SRV_URL $rar 10000) {
        & $unrar x -o+ -y $rar $Root | Out-Null
        if (-not $haveHC) { $haveHC = Test-Path (Join-Path $Root "hashcat\hashcat.exe") }
        if (-not $haveAC) { $haveAC = [bool](Get-ChildItem (Join-Path $Root "aircrack-ng") -Recurse -Filter "aircrack-ng.exe" -ErrorAction SilentlyContinue | Select-Object -First 1) }
    }
} else {
    Write-Host "[2/3] Using official downloads."
}

# ---- 3) write tool paths into config --------------------------------------
Write-Host "[3/3] Writing tool paths into PineCrack config..."
$hcexe = Join-Path $Root "hashcat\hashcat.exe"
$acexe = Get-ChildItem (Join-Path $Root "aircrack-ng") -Recurse -Filter "aircrack-ng.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$cfgDir = Split-Path -Parent $ConfigPath
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
$cfg = $null
if (Test-Path $ConfigPath) { try { $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json } catch { $cfg = $null } }
if ($null -eq $cfg) { $cfg = [PSCustomObject]@{} }
if (Test-Path $hcexe) { $cfg | Add-Member -NotePropertyName hashcat_path -NotePropertyValue $hcexe -Force }
if ($acexe)           { $cfg | Add-Member -NotePropertyName aircrack_path -NotePropertyValue $acexe.FullName -Force }
$cfg | ConvertTo-Json -Depth 8 | Set-Content -Path $ConfigPath -Encoding UTF8

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
if ($haveHC) { Write-Host ("SUCCESS - hashcat: " + $hcexe) } else { Write-Host "hashcat NOT installed - check your internet connection and re-run." }
if ($haveAC -and $acexe) { Write-Host ("aircrack-ng: " + $acexe.FullName) }
Write-Host ""
if (-not $NoPause) { Read-Host "Press Enter to close" }

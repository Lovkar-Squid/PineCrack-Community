# PineCrack - WSL + hcxtools setup
# Enables LOCAL .pcap/.cap -> .hc22000 conversion (no server needed).
# The installer runs this as Administrator. You can also re-run it any time:
#     powershell -ExecutionPolicy Bypass -File setup-wsl.ps1
# Requires Windows 10 (2004+) or Windows 11.

$ErrorActionPreference = "Continue"
try { $OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch {}

Write-Host "==================================================================="
Write-Host "  PineCrack  -  WSL + hcxtools setup"
Write-Host "  (only needed to convert .pcap/.cap captures to .hc22000 locally)"
Write-Host "==================================================================="
Write-Host ""

function Have-Distro {
    $k = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    return ((Get-ChildItem $k -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
}

# ---- 1) make sure a WSL distro is installed --------------------------------
if (-not (Have-Distro)) {
    Write-Host "[1/3] Installing WSL + Ubuntu (downloads ~500 MB - please wait)..."
    Write-Host ""
    wsl --install -d Ubuntu --no-launch
    Start-Sleep -Seconds 8
    if (-not (Have-Distro)) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------------"
        Write-Host "  WSL has been ENABLED, but Windows needs a RESTART to finish."
        Write-Host ""
        Write-Host "  1) Restart your PC."
        Write-Host "  2) Run this setup again:  Start Menu -> 'PineCrack - Set up WSL'"
        Write-Host "     (or run setup-wsl.ps1 from the PineCrack folder)."
        Write-Host "-------------------------------------------------------------------"
        Write-Host ""
        Read-Host "Press Enter to close"
        exit 0
    }
} else {
    Write-Host "[1/3] WSL distro already present - good."
}

# ---- 2) install hcxtools inside Linux (as root) ----------------------------
Write-Host "[2/3] Installing hcxtools inside Linux..."
wsl -u root -- bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y hcxtools"

# ---- 3) verify -------------------------------------------------------------
Write-Host "[3/3] Verifying..."
$ver = (wsl -u root -- bash -lc "timeout 20 hcxpcapngtool --version </dev/null 2>&1 | head -n1")
Write-Host ""
if ("$ver" -match "hcxpcapngtool") {
    Write-Host "SUCCESS  -  $ver"
    Write-Host "PineCrack can now convert .pcap / .cap captures locally (no server needed)."
} else {
    Write-Host "hcxtools was not detected."
    Write-Host "Check your internet connection, then run this setup again."
}
Write-Host ""
Read-Host "Press Enter to close"

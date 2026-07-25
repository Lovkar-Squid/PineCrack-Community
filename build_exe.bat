@echo off
title Build PineCrack Community (.exe)
cd /d "%~dp0"

echo Building PineCrack.exe  (config + starter wordlists bundled)...
py -3.11 -m pip install pyinstaller --quiet
py -3.11 -m PyInstaller --noconfirm --onefile --windowed ^
  --collect-all customtkinter --collect-all paramiko ^
  --add-data "pinecrack_config.json;." --add-data "wordlists;wordlists" --add-data "tools;tools" ^
  --icon pinecrack.ico --version-file version.txt ^
  --name PineCrack pinecrack2.py

if exist dist\PineCrack.exe (
  copy /Y dist\PineCrack.exe PineCrack.exe >nul
  rmdir /S /Q build dist __pycache__ 2>nul
  del PineCrack.spec 2>nul
  echo.
  echo Done. PineCrack.exe built (run anywhere; needs hashcat + a GPU).
) else (
  echo.
  echo BUILD FAILED - see messages above.
)
pause

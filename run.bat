@echo off
title PineCrack Community
cd /d "%~dp0"

rem prefer Python 3.11, else whatever "python" is
set "PY=py -3.11"
%PY% --version >nul 2>nul || set "PY=python"

echo Checking dependencies...
%PY% -c "import customtkinter" 2>nul || %PY% -m pip install customtkinter
%PY% -c "import paramiko" 2>nul || %PY% -m pip install paramiko

%PY% pinecrack2.py
echo.
pause

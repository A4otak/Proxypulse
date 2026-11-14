@echo off
setlocal
cd /d "%~dp0"
title ProxyPulse CLI
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
chcp 65001 >nul

set "PY_CMD="
where py >nul 2>nul && set "PY_CMD=py -3"
if not defined PY_CMD (
    where python >nul 2>nul && set "PY_CMD=python"
)
if not defined PY_CMD goto :nopython

%PY_CMD% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
if errorlevel 1 goto :oldpython

if not exist ".venv\Scripts\python.exe" (
    echo [setup] Creating virtual environment...
    %PY_CMD% -m venv .venv
    if errorlevel 1 goto :fail
)

set "VENV_PY=.venv\Scripts\python.exe"

if not exist ".venv\deps_installed.flag" (
    echo [setup] Installing dependencies...
    "%VENV_PY%" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto :fail
    echo ok> ".venv\deps_installed.flag"
)

"%VENV_PY%" main.py
goto :end

:nopython
echo [error] Python was not found. Install Python 3.11 or newer from https://www.python.org/downloads/
echo         and enable the option "Add python.exe to PATH" during installation.
goto :end

:oldpython
echo [error] Python 3.11 or newer is required. Please update Python.
goto :end

:fail
echo [error] Setup failed. Check your internet connection and try again.

:end
echo.
pause
endlocal

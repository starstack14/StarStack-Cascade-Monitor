$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path '.venv\Scripts\python.exe')) {
    python -m venv .venv
}

& '.venv\Scripts\python.exe' -m pip install --disable-pip-version-check --upgrade pip
& '.venv\Scripts\python.exe' -m pip install --disable-pip-version-check -r requirements-dev.txt
& '.venv\Scripts\python.exe' build_icon.py
& '.venv\Scripts\pyinstaller.exe' --noconfirm --clean --onefile --windowed `
    --name 'StarStack-Cascade-Monitor' --icon 'assets\starstack.ico' main.py

Write-Host "Built: $root\dist\StarStack-Cascade-Monitor.exe"

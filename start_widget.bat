@echo off
cd /d "%~dp0"
if exist "%~dp0dist\StarStack-Cascade-Monitor.exe" (
  start "" "%~dp0dist\StarStack-Cascade-Monitor.exe"
) else if exist "%~dp0.venv\Scripts\pythonw.exe" (
  start "StarStack Cascade Monitor" /b "%~dp0.venv\Scripts\pythonw.exe" main.py
) else (
  start "StarStack Cascade Monitor" /b pythonw.exe main.py
)

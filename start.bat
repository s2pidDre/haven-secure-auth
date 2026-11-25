@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js 24.12 or newer within the 24.x release line, then reopen this file.
  pause
  exit /b 1
)
node scripts\setup.mjs
if errorlevel 1 (
  pause
  exit /b 1
)
node server.mjs
pause

@echo off
setlocal
for %%I in ("%~dp0.") do set "APP_ROOT=%%~fI"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%APP_ROOT%\start-codex-alert-helper.ps1"
set "EXITCODE=%ERRORLEVEL%"
endlocal & exit /b %EXITCODE%

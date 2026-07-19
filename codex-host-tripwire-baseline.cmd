@echo off
setlocal
for %%I in ("%~dp0.") do set "APP_ROOT=%%~fI"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%APP_ROOT%\invoke-host-tripwire.ps1" -Mode Baseline -StateDbPath "%APP_ROOT%\state\ioc-store.db"
set "EXITCODE=%ERRORLEVEL%"
endlocal & exit /b %EXITCODE%

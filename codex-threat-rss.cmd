@echo off
setlocal
for %%I in ("%~dp0.") do set "APP_ROOT=%%~fI"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%APP_ROOT%\monitor-threat-rss.ps1" -StateDbPath "%APP_ROOT%\state\ioc-store.db" -RunTripwireCheckOnMatch
set "EXITCODE=%ERRORLEVEL%"
endlocal & exit /b %EXITCODE%

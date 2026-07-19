@echo off
setlocal
for %%I in ("%~dp0.") do set "APP_ROOT=%%~fI"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%APP_ROOT%\invoke-host-ioc.ps1" -Mode IOC
set "EXITCODE=%ERRORLEVEL%"
endlocal & exit /b %EXITCODE%

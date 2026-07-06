@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\CodexTest\invoke-host-ioc.ps1" -Mode IOC
exit /b %ERRORLEVEL%

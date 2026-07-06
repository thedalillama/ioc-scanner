@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\CodexTest\invoke-host-tripwire.ps1" -Mode Baseline -StateDbPath "C:\CodexTest\state\ioc-store.db"
exit /b %ERRORLEVEL%

@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\CodexTest\invoke-host-tripwire.ps1" -Mode Baseline -StateDbPath "C:\CodexTest\state\ioc-store.db"
exit /b %ERRORLEVEL%

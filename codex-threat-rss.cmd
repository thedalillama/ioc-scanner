@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\CodexTest\monitor-threat-rss.ps1" -StateDbPath "C:\CodexTest\state\ioc-store.db" -RunTripwireCheckOnMatch
exit /b %ERRORLEVEL%

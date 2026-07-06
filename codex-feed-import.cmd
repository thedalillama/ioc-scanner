@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\CodexTest\import-threat-feeds.ps1"
exit /b %ERRORLEVEL%

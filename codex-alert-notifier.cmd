@echo off
powershell.exe -ExecutionPolicy Bypass -File "C:\CodexTest\start-codex-alert-helper.ps1" -WatchPath "C:\CodexTest\alerts\pending" -StateDbPath "C:\CodexTest\state\ioc-store.db"
exit /b %ERRORLEVEL%

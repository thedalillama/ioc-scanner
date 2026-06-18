@echo off
setlocal

set "LOG=%USERPROFILE%\Desktop\codex-install.log"
set "STATUS=%USERPROFILE%\Desktop\codex-status.txt"
set "RUNTIME=%LOCALAPPDATA%\CodexMonitorRuntime"
set "DATA=%LOCALAPPDATA%\CodexMonitorData"
set "SRCROOT=%~d0\."

echo Codex VM install wrapper > "%LOG%"
echo Started: %DATE% %TIME%>> "%LOG%"
echo Source drive: %~d0>> "%LOG%"
echo.>> "%LOG%"

where python >> "%LOG%" 2>&1
python --version >> "%LOG%" 2>&1
where py >> "%LOG%" 2>&1
py -3 --version >> "%LOG%" 2>&1
echo.>> "%LOG%"
echo RuntimeRoot=%RUNTIME%>> "%LOG%"
echo DataRoot=%DATA%>> "%LOG%"
echo.>> "%LOG%"

set "INSTALLER_SCRIPT="
if exist "%~d0\installer.ps1" set "INSTALLER_SCRIPT=%~d0\installer.ps1"
if not defined INSTALLER_SCRIPT (
  for %%I in ("%~d0\instal*.ps1") do set "INSTALLER_SCRIPT=%%~fI"
)

if not defined INSTALLER_SCRIPT (
  echo Installer script was not found on the mounted media.>> "%LOG%"
  start "" notepad "%LOG%"
  exit /b 1
)

echo InstallerScript=%INSTALLER_SCRIPT%>> "%LOG%"

powershell -NoProfile -ExecutionPolicy Bypass -File "%INSTALLER_SCRIPT%" -SourceRoot "%SRCROOT%" -RuntimeRoot "%RUNTIME%" -DataRoot "%DATA%" -InstallPythonIfMissing -CreateSystemTasks -CreateUserNotifierTask -InitializeProtection >> "%LOG%" 2>&1
set "INSTALL_EXIT=%ERRORLEVEL%"
echo.>> "%LOG%"
echo InstallerExitCode=%INSTALL_EXIT%>> "%LOG%"

if "%INSTALL_EXIT%"=="0" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%RUNTIME%\get-codex-monitor-status.ps1" -SettingsPath "%RUNTIME%\codex-monitor.settings.json" > "%STATUS%" 2>&1
)

start "" notepad "%LOG%"
if exist "%STATUS%" start "" notepad "%STATUS%"

exit /b %INSTALL_EXIT%

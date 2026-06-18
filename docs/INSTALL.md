# Install

## Supported environment

- Windows 10 / Windows 11
- PowerShell 5.1 or later
- Python 3.x available to the installer and runtime scripts
- local administrative rights for audit-policy and scheduled-task setup
- an interactive user session for popup alert display

## Files to keep in the repo

- `invoke-host-ioc.ps1`
- `invoke-host-tripwire.ps1`
- `monitor-threat-rss.ps1`
- `start-codex-alert-helper.ps1`
- `install-codex-monitor.ps1`
- `import-threat-feeds.ps1`
- `get-codex-monitor-status.ps1`
- `codex_monitor_ui.py`
- `start-codex-monitor-ui.ps1`
- `ioc_store.py`
- `ioc-monitor-locations.json`
- `codex-monitor.settings.example.json`
- `run-hidden.vbs`
- `examples\`

Do not commit generated `HOST_*`, `THREAT_RSS_*`, `ALERT_*`, or local `*-state.json` files.

Treat the repo clone as development source only. The live deployment should use:

- protected scripts under `C:\Program Files\CodexMonitor`
- mutable alerts and state under `C:\ProgramData\CodexMonitor`

## Recommended protected runtime path

For `SYSTEM` scheduled tasks, copy the runtime scripts to an admin-only directory such as:

```text
C:\Program Files\CodexMonitor
```

Reason:
- running a scheduled task as `SYSTEM` from a user-writable path is a privilege-escalation risk

## Popup alert prerequisites

The current alert surface is an interactive desktop popup window.

Requirements:

- the `Codex Alert Notifier` task must run as the signed-in user
- the user must be logged in with an interactive desktop session
- no extra PowerShell notification module is required

## Audit and logging prerequisites

Enable Task Scheduler operational logging:

```powershell
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
```

Enable task- and process-related auditing:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```

Verify:

```powershell
wevtutil gl Microsoft-Windows-TaskScheduler/Operational
auditpol /get /subcategory:"Other Object Access Events" /r
auditpol /get /subcategory:"Process Creation" /r
```

## Installer

Preferred deployment:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -DataRoot "C:\ProgramData\CodexMonitor" -CreateSystemTasks -CreateUserNotifierTask
```

If Python is missing, the installer can attempt to install it first:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -DataRoot "C:\ProgramData\CodexMonitor" -InstallPythonIfMissing -CreateSystemTasks -CreateUserNotifierTask
```

Optional Python bootstrap parameters:

- `-PythonInstallerPath`
  - use a local Python installer instead of `winget`
- `-PythonInstallerArguments`
  - override the silent install arguments passed to that installer
- `-PythonWingetId`
  - choose a different `winget` package ID than the default `Python.Python.3.12`

This installer:

- copies runtime scripts into the protected runtime path
- copies the Python management UI and launcher
- copies the IOC location config
- writes `codex-monitor.settings.json` into the runtime root by default
- records the resolved interpreter path as `PythonCommand`
- creates mutable operational directories under the data root
- initializes the SQLite IOC store
- optionally creates the scheduled tasks using the chosen paths

Python handling notes:

- the installer verifies a real Python interpreter by running code, not just by checking `python.exe` on `PATH`
- the Microsoft Store alias stub is rejected as unusable
- if Python is still missing after bootstrap, the installer stops before partial setup continues

If you want the settings file elsewhere, use:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -DataRoot "C:\ProgramData\CodexMonitor" -SettingsRoot "C:\Some\Other\Path"
```

## Example scheduled tasks

### `SYSTEM` collection tasks

```powershell
schtasks /Create /SC HOURLY /MO 1 /TN "Codex Host Tripwire" /TR "powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\invoke-host-tripwire.ps1 -Mode Check" /RU SYSTEM /RL HIGHEST /F
schtasks /Create /SC HOURLY /MO 1 /TN "Codex Threat RSS Monitor" /TR "powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch" /RU SYSTEM /RL HIGHEST /F
schtasks /Create /SC DAILY /ST 02:00 /TN "Codex Threat Feed Import" /TR "powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\import-threat-feeds.ps1 -OutputPath <DataRoot>\indicators\feed-indicators-latest.json -LocationConfigPath <RuntimeRoot>\ioc-monitor-locations.json -IocStorePath <DataRoot>\state\ioc-store.db" /RU SYSTEM /RL HIGHEST /F
schtasks /Create /SC DAILY /ST 03:00 /TN "Codex IOC Daily Scan" /TR "powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\invoke-host-ioc.ps1 -Mode IOC -IocPath <DataRoot>\indicators\feed-indicators-latest.json" /RU SYSTEM /RL HIGHEST /F
```

### User-context notification helper

```powershell
schtasks /Create /SC MINUTE /MO 1 /TN "Codex Alert Notifier" /TR "wscript.exe //B //nologo <RuntimeRoot>\run-hidden.vbs ""powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\start-codex-alert-helper.ps1 -WatchPath <DataRoot>\alerts\pending -StateDbPath <DataRoot>\state\ioc-store.db""" /RL LIMITED /F
```

The notifier should run from the protected runtime path, but consume and mutate files in the writable data root. It is a one-shot task that runs each minute, not a long-running watcher.
It shows an interactive popup with:

- `Open Alert`
- `Open Folder`
- `Dismiss`

## First-run sequence

1. copy runtime scripts to the protected runtime path
2. ensure Python is installed, or rerun the installer with `-InstallPythonIfMissing`
3. enable notifications, task scheduler logging, and auditing
4. create the `SYSTEM` scheduled tasks
5. run:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Baseline
```

6. create the user notification task
7. verify popup delivery by dropping a synthetic `ALERT_*.json` into `<DataRoot>\alerts\pending`
8. confirm protection health with:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
```

9. optionally launch the local operations dashboard:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-monitor-ui.ps1 -OpenBrowser
```

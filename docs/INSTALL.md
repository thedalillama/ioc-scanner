# Install

## Supported environment

- Windows 10 / Windows 11
- PowerShell 5.1 or later
- local administrative rights for audit-policy and scheduled-task setup

## Files to keep in the repo

- `invoke-host-ioc.ps1`
- `invoke-host-tripwire.ps1`
- `monitor-threat-rss.ps1`
- `start-codex-alert-helper.ps1`
- `install-codex-monitor.ps1`
- `codex-monitor.settings.example.json`
- `ioc-packs\`
- `examples\`

Do not commit generated `HOST_*`, `THREAT_RSS_*`, `ALERT_*`, or local `*-state.json` files.

## Recommended protected runtime path

For `SYSTEM` scheduled tasks, copy the runtime scripts to an admin-only directory such as:

```text
C:\Program Files\CodexMonitor
```

Reason:
- running a scheduled task as `SYSTEM` from a user-writable path is a privilege-escalation risk

## PowerShell module for notifications

Install `BurntToast` for the interactive user who should receive notifications:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module BurntToast -Scope CurrentUser -Force -AllowClobber
```

## Windows settings required for visibility

Enable app notifications in Windows:

- `Settings` -> `System` -> `Notifications`
- turn on `Get notifications from apps and other senders`

If toast notifications do not appear, confirm:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' |
Select-Object ToastEnabled
```

Expected:
- `ToastEnabled = 1`

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
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -CreateSystemTasks -CreateUserNotifierTask
```

This installer:

- copies runtime scripts into the protected runtime path
- copies `ioc-packs`
- writes `codex-monitor.settings.json`
- optionally creates the scheduled tasks using the chosen paths

## Example scheduled tasks

### `SYSTEM` collection tasks

```powershell
schtasks /Create /SC HOURLY /MO 1 /TN "Codex Host Tripwire" /TR "powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\invoke-host-tripwire.ps1 -Mode Check" /RU SYSTEM /RL HIGHEST /F
schtasks /Create /SC HOURLY /MO 1 /TN "Codex Threat RSS Monitor" /TR "powershell.exe -ExecutionPolicy Bypass -File <RuntimeRoot>\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch" /RU SYSTEM /RL HIGHEST /F
```

### User-context notification helper

```powershell
schtasks /Create /SC ONLOGON /TN "Codex Alert Helper" /TR "powershell.exe -ExecutionPolicy Bypass -File <RepoRoot>\start-codex-alert-helper.ps1 -WatchPath <RuntimeRoot>" /RL LIMITED /F
```

## First-run sequence

1. copy runtime scripts to the protected runtime path
2. install `BurntToast` for the interactive user
3. enable notifications, task scheduler logging, and auditing
4. create the `SYSTEM` scheduled tasks
5. run:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Baseline
```

6. create the user logon notification helper task

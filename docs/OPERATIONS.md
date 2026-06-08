# Operations

## Main workflows

### Baseline a host

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Baseline
```

### Run a deeper host collection

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Deep
```

### Screen a host against an IOC pack

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC -IocPath .\ioc-packs\cisa-play-ransomware-2025.json
```

### Poll threat-intel feeds

```powershell
powershell -ExecutionPolicy Bypass -File .\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch
```

## Alert files

The detection scripts write explicit alert artifacts:

- `ALERT_HOST_TRIPWIRE_<timestamp>.json/md`
- `ALERT_THREAT_RSS_<timestamp>.json/md`

The user-context notifier should watch these files, not the larger report files.

The watch path is configurable by:

- `-WatchPath`
- `CODEX_MONITOR_WATCHPATH`
- `codex-monitor.settings.json`

## Severity model

Current tripwire severity is simple:

- `High`
  - scheduled task changes
  - local group membership changes
  - autorun changes
- `Medium`
  - service changes
  - watched-file changes
- `Low`
  - other drift

This is intentionally conservative and can be expanded later.

## Common maintenance

### Update the tripwire baseline

After a known-good intentional change:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
```

### Add watched locations

Edit `host-tripwire-config.json` or use the example in `examples\host-tripwire-config.example.json`.

Recommended additions:

- selected `AppData` subtrees
- software-specific script/plugin directories
- line-of-business startup paths

### Add new IOC packs

Create a JSON file under `ioc-packs\` with supported keys:

- `Hashes`
- `Paths`
- `ServiceNames`
- `TaskNames`
- `RegistryPaths`
- `CommandLinePatterns`
- `FileNames`

## Troubleshooting

### Notifications do not appear

Check:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' |
Select-Object ToastEnabled
```

Expected:
- `ToastEnabled = 1`

Then test interactively:

```powershell
Import-Module BurntToast
New-BurntToastNotification -Text 'Codex test','Interactive toast test'
```

### Scheduled task creation is not visible in logs

Check:

```powershell
wevtutil gl Microsoft-Windows-TaskScheduler/Operational
auditpol /get /subcategory:"Other Object Access Events" /r
```

### Helper appears to do nothing

Validate the pipeline in order:

1. direct interactive `BurntToast`
2. detached hidden-process `BurntToast`
3. `ALERT_*.json` creation
4. helper state file advancing

If direct toasts work but the helper does not, the issue is usually with the user-session watcher lifecycle or watch-path configuration, not the notification stack.

## Suggested repo hygiene

- commit scripts, examples, docs, and curated IOC packs
- ignore generated reports and local state
- keep the protected runtime copy out of the repository

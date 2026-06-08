# Codex Host Monitor

Windows-first host monitoring and IOC screening scripts for unmanaged or lightly managed systems.

This repository is built around three jobs:

- collect host state and screen it against IOC packs
- baseline and detect local persistence or account drift
- monitor reputable threat-intel RSS feeds and trigger follow-up collection

## Scripts

- `invoke-host-ioc.ps1`
  - `Baseline`: fast host snapshot
  - `Deep`: broader IOC-oriented collection
  - `IOC`: match a supplied IOC JSON pack against collected data
- `invoke-host-tripwire.ps1`
  - `Baseline`: save local baseline state
  - `Check`: compare current state to baseline and emit `ALERT_*.json/md` on drift
- `monitor-threat-rss.ps1`
  - poll CISA and Microsoft threat-intel feeds
  - emit `ALERT_*.json/md` when relevant items are found
  - optionally trigger tripwire or IOC follow-up
- `start-codex-alert-helper.ps1`
  - user-session helper that watches for `ALERT_*.json`
  - sends Windows notifications via `BurntToast`
- `install-codex-monitor.ps1`
  - copies runtime files to a protected path
  - writes local settings
  - optionally creates scheduled tasks

## Repository layout

- `ioc-packs/`
  - curated IOC packs from reputable sources
- `docs/INSTALL.md`
  - setup, scheduling, audit-policy, and notification prerequisites
- `docs/OPERATIONS.md`
  - day-2 usage, alert flow, troubleshooting, and maintenance
- `examples/`
  - example config files

## Quick start

Run a baseline:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Baseline
```

Run an IOC pack:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC -IocPath .\ioc-packs\microsoft-nobelium-sibot-goldmax-2021.json
```

Run the RSS monitor once:

```powershell
powershell -ExecutionPolicy Bypass -File .\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch
```

Install to a protected runtime path:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -CreateSystemTasks -CreateUserNotifierTask
```

## Outputs

Each script writes timestamped JSON and Markdown artifacts into its working directory.

Important patterns:

- `HOST_IOC_*.json/md`
- `HOST_TRIPWIRE_*.json/md`
- `THREAT_RSS_*.json/md`
- `ALERT_*.json/md`

The alert helper watches for `ALERT_*.json`.

## Alert flow

1. `SYSTEM` tasks run tripwire and RSS collection from the configured runtime path.
2. Detection scripts write `ALERT_*.json`.
3. A user-context notifier reads those files from the configured watch path.
4. The notifier sends Windows notifications into Notification Center.

## Status notes

- The host/IOC/tripwire scripts are the primary supported pieces.
- The alert helper depends on user-session Windows notifications and the `BurntToast` PowerShell module.
- Generated report files and local state files are intentionally excluded from version control by `.gitignore`.

## Reputable IOC sources already included

See `ioc-packs/README.md`.

Current packs include Microsoft, CISA, and Unit 42 sourced indicators.

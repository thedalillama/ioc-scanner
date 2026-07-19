# Codex Host Monitor

Windows-first host monitoring and IOC screening scripts for unmanaged or lightly managed systems.

This repository is built around three jobs:

- collect host state and screen it against normalized indicators
- baseline and detect local persistence or account drift
- monitor reputable threat-intel RSS feeds and trigger follow-up collection

The IOC side is greenfield and uses a normalized indicator model instead of a custom ad hoc pack format. The intended pipeline is:

```text
public feeds or STIX bundle
        ->
normalized indicator set
        ->
Windows host collection
        ->
matching and findings
```

## Scripts

- `invoke-host-ioc.ps1`
  - `Baseline`: fast host snapshot
  - `Deep`: broader IOC-oriented collection
  - `IOC`: match a normalized indicator set or STIX bundle against collected data
- `import-threat-feeds.ps1`
  - ingest ThreatFox, MalwareBazaar, URLhaus, Feodo Tracker, and CISA KEV
  - normalize them into the internal indicator schema
  - merge direct path-bearing indicators into `ioc-monitor-locations.json`
  - load the normalized indicators into the local SQLite IOC store
- `ioc_store.py`
  - initialize and manage the local SQLite IOC store
  - import normalized indicator JSON
  - export scanner-ready normalized indicator JSON
  - report IOC store statistics
- `invoke-host-tripwire.ps1`
  - `Baseline`: save local baseline state
  - `Check`: compare current state to baseline and emit `ALERT_*.json/md` on drift
- `monitor-threat-rss.ps1`
  - poll CISA and Microsoft threat-intel feeds
  - emit `ALERT_*.json/md` when relevant items are found
  - optionally trigger tripwire or IOC follow-up
- `start-codex-alert-helper.ps1`
  - one-shot user-session notifier for pending `ALERT_*.json`
  - shows an interactive desktop popup window
  - supports `Open Alert`, `Open Folder`, and `Dismiss`
- `install-codex-monitor.ps1`
  - copies runtime files to a protected path
  - writes local settings
  - optionally creates scheduled tasks
- `get-codex-monitor-status.ps1`
  - shows one-screen protection health and task status
  - reports stale feeds, missing baselines, pending alerts, and task problems
- `codex_monitor_ui.py`
  - self-contained Python management UI on `http://127.0.0.1:8765`
  - surfaces scheduled task actions, SQLite state, alerts, reports, and indicator-store stats
  - lets you trigger scheduled tasks from the browser
- `start-codex-monitor-ui.ps1`
  - resolves `PythonCommand` from settings
  - launches the Python dashboard with the correct settings path
- `run-hidden.vbs`
  - launches a command without flashing a console window
  - used by the user-context notifier task

## Repository layout

- `docs/INSTALL.md`
  - setup, scheduling, audit-policy, and notification prerequisites
- `docs/OPERATIONS.md`
  - day-2 usage, alert flow, troubleshooting, and maintenance
- `docs/TESTING.md`
  - automated and manual verification procedures
- `examples/`
  - example config files
- `indicators/`
  - normalized feed exports for scanner input
- `state/`
  - SQLite IOC store and local scanner state
- `tests/`
  - unit tests, smoke tests, and fixtures
- `ioc-monitor-locations.json`
  - IOC-derived watch locations merged into tripwire at runtime

## Directory structure

```text
<repo-root> (development workspace example)
|-- .git/
|-- alerts/
|   |-- pending/
|   `-- archive/
|-- docs/
|   |-- INSTALL.md
|   |-- OPERATIONS.md
|   `-- TESTING.md
|-- examples/
|   |-- host-tripwire-config.example.json
|   `-- normalized-indicators.example.json
|-- indicators/
|   `-- feed-indicators-latest.json
|-- state/
|   `-- ioc-store.db
|-- tests/
|   |-- fixtures/
|   |   `-- normalized-indicators.min.json
|   |-- run-smoke-tests.ps1
|   `-- test_ioc_store.py
|-- README.md
|-- codex-monitor.settings.example.json
|-- codex-monitor.settings.json
|-- codex_monitor_ui.py
|-- collect-security-baseline.ps1
|-- deep-research-report.md
|-- guidance.txt
|-- host-tripwire-config.json
|-- import-threat-feeds.ps1
|-- install-codex-monitor.ps1
|-- invoke-host-ioc.ps1
|-- invoke-host-tripwire.ps1
|-- ioc-monitor-locations.json
|-- ioc_store.py
|-- get-codex-monitor-status.ps1
|-- monitor-threat-rss.ps1
|-- run-hidden.vbs
|-- start-codex-monitor-ui.ps1
`-- start-codex-alert-helper.ps1
```

## Script inventory

- `invoke-host-ioc.ps1`
  - collects live Windows host observations
  - loads normalized indicators or STIX-derived indicators
  - produces evidence-rich IOC findings
- `import-threat-feeds.ps1`
  - downloads public IOC feeds
  - normalizes them into the internal schema
  - updates `ioc-monitor-locations.json`
  - loads indicators into the SQLite IOC store
- `ioc_store.py`
  - initializes the SQLite IOC database
  - imports normalized indicator JSON
  - exports scanner-ready normalized indicator JSON
  - reports IOC store statistics
- `invoke-host-tripwire.ps1`
  - baselines local system state
  - detects drift in accounts, tasks, autoruns, services, watched files, and IOC-derived locations
  - emits alert files on change
- `monitor-threat-rss.ps1`
  - polls threat-intel RSS feeds
  - raises advisory alerts
  - can trigger follow-up collection
- `start-codex-alert-helper.ps1`
  - processes pending alerts from the user session
  - surfaces them as interactive desktop popup windows
  - archives handled alerts
- `install-codex-monitor.ps1`
  - deploys scripts to a runtime location
  - writes settings
  - creates scheduled tasks when requested
- `get-codex-monitor-status.ps1`
  - summarizes current protection health
  - checks SQLite state, pending alerts, indicator freshness, and scheduled tasks
- `codex_monitor_ui.py`
  - serves the browser-based operations dashboard
  - reads the same settings, SQLite state, tasks, alerts, and reports as the scheduled monitor flow
- `start-codex-monitor-ui.ps1`
  - launches the dashboard without requiring manual Python resolution
- `run-hidden.vbs`
  - launches a hidden PowerShell command without console flicker
- `collect-security-baseline.ps1`
  - earlier broad security snapshot collector retained as a reference tool
- `tests\run-smoke-tests.ps1`
  - parses PowerShell entry points and runs Python unit tests
- `tests\test_ioc_store.py`
  - unit tests for SQLite IOC and app-state persistence

## Quick start

Run a baseline:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Baseline
```

Build a normalized indicator set from public feeds:

```powershell
powershell -ExecutionPolicy Bypass -File .\import-threat-feeds.ps1
```

Inspect IOC store stats:

```powershell
python .\ioc_store.py stats
```

Check monitor health:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
```

Launch the management UI:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-monitor-ui.ps1 -OpenBrowser
```

Run IOC matching:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC -IocPath .\examples\normalized-indicators.example.json
```

Run the RSS monitor once:

```powershell
powershell -ExecutionPolicy Bypass -File .\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch
```

Install to a protected runtime path:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -DataRoot "C:\ProgramData\CodexMonitor" -CreateSystemTasks -CreateUserNotifierTask
```

If Python is not already installed, the installer can bootstrap it first:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot "C:\Program Files\CodexMonitor" -DataRoot "C:\ProgramData\CodexMonitor" -InstallPythonIfMissing -CreateSystemTasks -CreateUserNotifierTask
```

The installer now resolves a real Python interpreter, rejects the Windows Store alias stub, and writes the resolved path into `codex-monitor.settings.json` as `PythonCommand`.

By default, the installer writes `codex-monitor.settings.json` into the runtime root so deployed scripts can resolve their operational paths without depending on the repo location.
The repository itself should remain a development workspace only; `C:\CodexTest` may be used as a development example, but it is not required and should not be treated as the live runtime or alert queue.

## Automated protection model

With scheduled tasks installed, the intended hands-off flow is:

1. `Codex Threat Feed Import`
   - runs daily
   - refreshes the normalized indicator export
   - updates the SQLite IOC store
2. `Codex IOC Daily Scan`
   - runs daily
   - screens the host against the latest normalized indicators
3. `Codex Host Tripwire`
   - runs hourly
   - checks for persistence and watched-file drift
4. `Codex Threat RSS Monitor`
   - runs hourly
   - detects relevant advisories and can trigger follow-up collection
5. `Codex Alert Notifier`
   - runs once per minute in the interactive user session
   - turns pending alerts into popup windows

## Outputs

Each script writes timestamped JSON and Markdown artifacts into its working directory.
In normal deployment, code lives under the protected runtime path while mutable alert files and state live under the data root.

Important patterns:

- `HOST_IOC_*.json/md`
- `HOST_TRIPWIRE_*.json/md`
- `THREAT_RSS_*.json/md`
- `<DataRoot>\alerts\pending\ALERT_*.json/md`
- `<DataRoot>\alerts\archive\ALERT_*.json/md`
- `indicators\feed-indicators-latest.json`

The notifier watches the `alerts\pending` inbox under the mutable data root and moves processed alert files into `alerts\archive`.

Tripwire scope now has two layers:

- `host-tripwire-config.json`
  - core tripwire behavior, including `PATH`-directory executable coverage
- `ioc-monitor-locations.json`
  - IOC-derived files and directories to watch and update as new campaigns or advisories are published

## Alert flow

1. `SYSTEM` tasks run tripwire and RSS collection from the configured runtime path.
2. Detection scripts write `ALERT_*.json`.
3. A user-context notifier task runs once per minute and reads those files from the configured inbox path.
4. The notifier shows an interactive desktop popup window and then archives handled alerts.

Popup behavior:

- `Open Alert`
  - opens the paired alert Markdown report
- `Open Folder`
  - opens the alert inbox/archive folder in Explorer
- `Dismiss`
  - closes the popup and acknowledges the alert

The notifier is intentionally one-shot:

- it runs once per minute
- processes all unseen pending alerts
- writes seen-state to SQLite
- moves handled alerts to `alerts\archive`
- exits

## Status notes

- The host/IOC/tripwire scripts are the primary supported pieces.
- The alert helper depends on running in the interactive user session.
- Alert delivery is implemented as a desktop popup window, not Notification Center toast delivery.
- Generated report files and local state files are intentionally excluded from version control by `.gitignore`.

## Threat-intel direction

The first-class path is:

- public feeds normalized into the internal indicator schema
- optional STIX bundle import
- Windows observation matching with evidence-rich findings

The feed ingestor currently targets:

- ThreatFox
- MalwareBazaar
- URLhaus
- Feodo Tracker
- CISA KEV

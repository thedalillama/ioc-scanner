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

### Screen a host against an indicator set

```powershell
powershell -ExecutionPolicy Bypass -File .\import-threat-feeds.ps1
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC
```

### Inspect the SQLite IOC store

```powershell
python .\ioc_store.py stats
python .\ioc_store.py export-json --output .\indicators\ioc-store-export.json
```

### Check monitor health

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
```

### Launch the management UI

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-monitor-ui.ps1 -OpenBrowser
```

The UI surfaces:

- overall health and paths from `get-codex-monitor-status.ps1`
- scheduled task state, actions, and triggers
- pending and archived alert files
- recent IOC, tripwire, and RSS reports
- SQLite indicator-store counts, ingest history, and app-state keys

From the task cards you can also trigger any installed Codex scheduled task on demand.

JSON output:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1 -AsJson
```

### Poll threat-intel feeds

```powershell
powershell -ExecutionPolicy Bypass -File .\monitor-threat-rss.ps1 -RunTripwireCheckOnMatch
```

## Alert files

The detection scripts write explicit alert artifacts:

- `alerts\pending\ALERT_HOST_TRIPWIRE_<timestamp>.json/md`
- `alerts\pending\ALERT_THREAT_RSS_<timestamp>.json/md`

The user-context notifier task scans `<DataRoot>\alerts\pending` once per minute.
After processing an alert, the notifier moves the alert JSON and matching Markdown file into `alerts\archive`.
It also records seen-alert state in SQLite so the same alert is not shown repeatedly.

The watch path is configurable by:

- `-WatchPath`
- `CODEX_MONITOR_WATCHPATH`
- `codex-monitor.settings.json`

Persistent monitor state now lives in SQLite:

- `state\ioc-store.db`
- namespace `host_tripwire` for the tripwire baseline
- namespace `threat_rss` for RSS dedupe state
- namespace `alert_helper` for seen alert state

The normalized indicator export is optional operator-sharing/offline evidence; the normal IOC scan reads active indicators from SQLite. Its default destination is:

- `indicators\feed-indicators-latest.json`

or at the path named by `IndicatorExportPath` in `codex-monitor.settings.json`.

Use `-IocPath <file>` only to run an explicit offline compatibility scan against a supplied JSON indicator set.

## Popup behavior

The notifier is a one-shot user-session popup helper, not a Notification Center toast sender.

When a pending alert is processed, the helper shows a desktop popup window with:

- `Open Alert`
  - opens the paired alert Markdown report
- `Open Folder`
  - opens the current alert folder in Explorer
- `Dismiss`
  - closes the popup

After the popup is handled, the alert JSON and matching Markdown file are moved from `alerts\pending` to `alerts\archive`.

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

Important refinement:

- low-severity drift does not create a popup alert
- self-managed `\Codex ...` scheduled tasks are treated as low severity
- likely system-managed Microsoft task-file churn is downgraded and retained in the report without raising an alert

## Common maintenance

### Update the tripwire baseline

After a known-good intentional change:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
```

When validating tripwire manually, run `Baseline` and `Check` sequentially.
Do not launch them in parallel, because `Check` can read the previous SQLite baseline before the new one is written.
If a baseline is already in progress, `Check` now refuses to run and prints a warning that includes the host, PID, and baseline start time.

### Add watched locations

Edit `host-tripwire-config.json` or use the example in `examples\host-tripwire-config.example.json`.

For IOC-derived monitoring scope, prefer updating `ioc-monitor-locations.json` instead of editing the script. The tripwire runner merges:

- `host-tripwire-config.json`
- `ioc-monitor-locations.json`

`import-threat-feeds.ps1` now also updates `ioc-monitor-locations.json` by merging any direct `file_path` indicators it ingests. It preserves existing curated entries and only adds new files or directories.

Recommended additions:

- selected `AppData` subtrees
- software-specific script/plugin directories
- line-of-business startup paths

### Add new indicator sets

Preferred inputs:

- a normalized indicator JSON file with an `Indicators` array
- a JSON array of normalized indicators
- a STIX bundle with `indicator` objects the parser understands

Use [normalized-indicators.example.json](../examples/normalized-indicators.example.json) as the starting shape.

## Automation defaults

Recommended scheduled protection tasks:

- `Codex Threat Feed Import`
  - daily
  - refreshes normalized indicators and updates SQLite
- `Codex IOC Daily Scan`
  - daily
  - screens the host against active SQLite indicators
- `Codex Host Tripwire`
  - hourly
  - checks persistence and watched-location drift
- `Codex Threat RSS Monitor`
  - hourly
  - checks for new relevant advisories
- `Codex Alert Notifier`
  - every minute
  - shows popup alerts in the interactive user session

## Troubleshooting

### Popup alerts do not appear

Test the notifier directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-alert-helper.ps1 -WatchPath .\alerts\pending -StateDbPath .\state\ioc-store.db
```

Check:

- a user is logged in interactively
- `Codex Alert Notifier` is running in the interactive user context
- alerts are landing in `alerts\pending`
- alerts are not already marked seen in SQLite

### Scheduled task creation is not visible in logs

Check:

```powershell
wevtutil gl Microsoft-Windows-TaskScheduler/Operational
auditpol /get /subcategory:"Other Object Access Events" /r
```

### Helper appears to do nothing

Validate the pipeline in order:

1. direct interactive `BurntToast`
2. `ALERT_*.json` creation
3. pending alert moves to `alerts\archive`
4. `python .\ioc_store.py stats` shows `app_state_count` increasing

If the popup path works but alerts are not consumed, the issue is usually with the scheduled user-session launch context or inbox-path configuration.

### Protection may be stale

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
```

The status script checks:

- whether the SQLite state database exists
- whether the normalized indicator export exists and is fresh
- whether tripwire baseline state is present
- whether RSS state is stale
- whether pending alerts are building up
- whether the scheduled tasks are installed and enabled

## Suggested repo hygiene

- commit scripts, examples, docs, and normalized indicator tooling
- ignore generated reports and local state
- keep the protected runtime copy and mutable data root out of the repository


---

# CSF Configuration Drift Workflow Operations

## Run posture check

Use tripwire check mode to detect observed configuration drift from the trusted baseline:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Check -StateDbPath .\state\ioc-store.db
```

The report summary may include CSF-aligned counters:

- `observed_posture_change_count`
- `expected_operational_change_count`
- `accepted_posture_change_count`
- `posture_review_count`
- `response_required_count`
- `guardrail_protected_count`

Interpretation:

- Observed posture changes are all detected differences from the trusted baseline.
- Response-required findings are the subset that should be worked in Respond.
- Accepted posture changes are exact reviewed changes recorded in SQLite.
- Expected operational changes remain recorded but usually do not require action.

## Accept one reviewed posture change

Use the accepted-drift helper only after reviewing a finding.

```powershell
.ccept-posture-drift.ps1 -ReportPath .\HOST_TRIPWIRE_CHECK_<timestamp>.json -FindingIndex 1 -Reason "Reviewed app update" -StateDbPath .\state\ioc-store.db
```

Or list candidates first:

```powershell
.ccept-posture-drift.ps1 -ReportPath .\HOST_TRIPWIRE_CHECK_<timestamp>.json
```

Rules:

- acceptance is exact-match only
- a reason is required
- only one finding is accepted at a time
- dangerous guardrail findings are refused
- accepted drift does not disable IOC matching or future drift detection

Accepted posture changes are stored in SQLite:

```text
state\ioc-store.db
accepted_posture_drift
```

## Respond vs Recover operational split

For a finding such as Firewall disabled:

```text
Detect:
Tripwire observes configuration drift from baseline.

Respond:
Review the finding and choose Mitigate. Re-enable Firewall.

Recover:
Rerun posture check. Confirm Firewall is enabled and the finding cleared.
```

Respond is where action is taken. Recover is where trusted operation is verified.

## Recover validation

Recover should validate confidentiality, integrity, and availability after response.

Suggested validation questions:

### Confidentiality

- Are Firewall and Defender protections enabled?
- Are there unexpected administrator additions?
- Are there unexpected shares or remote-access changes?
- Are there unauthorized Defender exclusions?

### Integrity

- Are trusted Windows tools intact?
- Are app scripts/profiles clean, accepted, or reviewed?
- Is `profiles\posture-drift-rules.json` loaded successfully?
- Is the SQLite accepted-drift registry loaded successfully?
- Are there suspicious services, tasks, autoruns, or command lines?

### Availability

- Are security services running?
- Are event logs available?
- Are Windows Update/BITS available?
- Did the latest posture check complete successfully?
- Are there unresolved response-required findings blocking normal operation?

## Create a new trusted baseline

Only create a new baseline after reviewing outstanding drift.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline -StateDbPath .\state\ioc-store.db
```

A new baseline means the current state is now trusted. Do not use baseline mode to hide unreviewed or suspicious findings.


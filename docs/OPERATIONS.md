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
```

### Explicit SQLite exports

Operational collectors and the UI use SQLite directly. Create a JSON artifact only
when an operator explicitly requests one, and always choose its destination:

```powershell
python .\ioc_store.py export-indicators --output <destination>\indicators.json
python .\ioc_store.py export-report --report-id <immutable-report-id> --output <destination>\report.json
python .\ioc_store.py export-alert --alert-id <immutable-alert-id> --output <destination>\alert.json
```

`export-json` remains a compatibility alias for `export-indicators`. These commands
do not create an automatic retention schedule: the operator owns the selected
destination and its retention. Existing migration evidence remains under the
operator-approved migration-backup retention policy beneath the configured data
root; do not use an operational export directory as a substitute for that archive.

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
- pending and acknowledged SQLite alerts
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

## Alert records

The detection scripts persist alert records in SQLite. The notifier claims pending records atomically, presents the interactive popup, and records delivery and acknowledgement in SQLite. Alert JSON/Markdown is available only through the explicit `export-alert` command.

### Monitor-generated PowerShell events

The IOC collector excludes only PowerShell Operational 4103/4104 events that
contain the exact `CODEX_MONITOR_SELF_EVENT` marker embedded in this monitor's
PowerShell source. It retrieves up to 200 candidate events before removing those
entries and retains up to 40 remaining events, so routine monitor operation does
not displace external PowerShell telemetry. The excluded count is retained in the
in-memory deep-collection `KeyEvents` summary for troubleshooting.

This is a volume-control exclusion, not a trust boundary: a third party could
copy the marker into a script. Do not use the marker in external scripts, and do
not rely on this exclusion to suppress a security investigation.

Persistent monitor state now lives in SQLite:

- `state\ioc-store.db`
- namespace `host_tripwire` for the tripwire baseline
- namespace `threat_rss` for RSS dedupe state
- namespace `alert_helper` for seen alert state

The normalized indicator export is optional operator-sharing/offline evidence;
the normal IOC scan reads active indicators from SQLite and does not create an
indicator JSON file unless an operator explicitly invokes an export command.

Use `-IocPath <file>` only to run an explicit offline compatibility scan against a supplied JSON indicator set.

## Popup behavior

The notifier is a one-shot user-session popup helper, not a Notification Center toast sender.

When a pending alert is processed, the helper shows a desktop popup window with:

- `Open Alert`
  - opens the immutable SQLite-backed alert detail in the local UI
- `Open Folder`
  - opens the configured data root for operator-requested exports and retained migration evidence
- `Dismiss`
  - closes the popup

After the popup is handled, the notifier records acknowledgement or a retryable delivery failure in SQLite. It does not move alert files because alert files are not part of the operational delivery path.

To prevent repeat popups, the notifier records a presentation marker for each immutable alert ID before displaying it. If the notifier is interrupted after a popup was presented, the same alert is suppressed for the configured repeat-suppression window rather than repeatedly reopening. A popup that cannot be presented remains retryable.

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
powershell -ExecutionPolicy Bypass -File .\start-codex-alert-helper.ps1 -StateDbPath .\state\ioc-store.db
```

Check:

- a user is logged in interactively
- `Codex Alert Notifier` is running in the interactive user context
- a pending alert record exists in SQLite
- the alert is not already claimed, acknowledged, or closed

### Scheduled task creation is not visible in logs

Check:

```powershell
wevtutil gl Microsoft-Windows-TaskScheduler/Operational
auditpol /get /subcategory:"Other Object Access Events" /r
```

### Helper appears to do nothing

Validate the pipeline in order:

1. a direct run of the interactive notifier against the configured SQLite store
2. creation of a pending SQLite alert/delivery record
3. notifier claim and popup display in the interactive session
4. acknowledgement or retryable failure recorded in SQLite

If the popup path works but alerts are not consumed, the issue is usually with the scheduled user-session launch context or SQLite-state permissions.

### Protection may be stale

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
```

The status script checks:

- whether the SQLite state database exists
- whether tripwire baseline state is present
- whether RSS state is stale
- whether pending SQLite alerts are building up
- whether the scheduled tasks are installed and enabled

## Suggested repo hygiene

- commit scripts, examples, docs, and normalized indicator tooling
- ignore generated reports and local state
- keep the protected runtime copy and mutable data root out of the repository

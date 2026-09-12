# Testing

This repository has two test layers:

- automated unit and smoke tests under `tests\`
- a manual end-to-end verification procedure for the Windows-specific workflows

## Test layout

```text
tests/
|-- fixtures/
|   `-- normalized-indicators.min.json
|-- run-smoke-tests.ps1
|-- test_codex_monitor_ui.py
`-- test_ioc_store.py
```

## Automated tests

### Python unit tests

These tests focus on the SQLite-backed IOC store and persistent app-state layer.

They verify:

- schema initialization
- normalized indicator import/export
- deduplication behavior
- SQLite `app_state` round-trips
- stats output including `app_state_count`
- UI settings resolution, alert parsing, and safe-path enforcement

Run them directly:

```powershell
python -m unittest discover -s .\tests -p "test_*.py" -v
```

### PowerShell smoke tests

The smoke runner checks:

- PowerShell scripts still parse
- required fixture files exist
- `ioc_store.py` compiles
- Python unit tests pass

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-smoke-tests.ps1
```

## Manual verification procedure

Run this sequence in the dev workspace before cutting a release or testing a fresh deployment.

### 1. Clean prerequisites

Confirm these paths exist:

- `alerts\pending`
- `alerts\archive`
- `state\ioc-store.db`

If `state\ioc-store.db` does not exist yet:

```powershell
python .\ioc_store.py init
```

### 2. IOC store verification

Import feeds:

```powershell
powershell -ExecutionPolicy Bypass -File .\import-threat-feeds.ps1
```

Validate:

```powershell
python .\ioc_store.py stats
python .\ioc_store.py export-indicators --output .\evidence\ioc-store-export.json
```

Expected:

- `indicator_count` is greater than `0`
- `ingest_run_count` increases
- `evidence\ioc-store-export.json` is created only because it was explicitly requested

To validate the record-specific exports after a collection produces immutable IDs:

```powershell
python .\ioc_store.py export-report --report-id <report-id> --output .\evidence\report.json
python .\ioc_store.py export-alert --alert-id <alert-id> --output .\evidence\alert.json
```

Expected:

- each command writes only the named SQLite record to its explicit destination
- an omitted or unknown immutable ID fails without creating a substitute export

### 2a. Status script verification

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1 -AsJson
```

Expected:

- the human-readable summary prints without error
- JSON output includes:
  - `Metadata`
  - `Paths`
  - `ScheduledTasks`
  - `State`
  - `HealthFindings`

### 3. IOC matching verification

Run a baseline:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode Baseline
```

Run a normalized-indicator match with the fixture set:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC -IocPath .\tests\fixtures\normalized-indicators.min.json
```

Expected:

- `HOST_IOC_*.json` and `HOST_IOC_*.md` are created
- the run completes without parser or import errors

### 4. Tripwire baseline and drift verification

Create a baseline:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
```

Confirm the baseline moved into SQLite:

```powershell
python .\ioc_store.py --db .\state\ioc-store.db state-get --namespace host_tripwire --key baseline
```

Expected:

- `"found": true`

Then run a check.

Important:

- run `Baseline` first
- wait for it to finish
- then run `Check`
- do not run `Baseline` and `Check` in parallel

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Check
```

Expected:

- `HOST_TRIPWIRE_CHECK_*.json` and `.md` are created
- the baseline remains stored in SQLite
- with no intentional change, `ChangeCount` should be `0`
- no `ALERT_HOST_TRIPWIRE_*.json/md` should be created for low-severity system or self-managed task churn
- if a baseline is already in progress, `Check` should refuse to run, print a warning, and exit with code `1`

### 5. RSS monitor verification

Run once:

```powershell
powershell -ExecutionPolicy Bypass -File .\monitor-threat-rss.ps1
```

Confirm RSS state moved into SQLite:

```powershell
python .\ioc_store.py --db .\state\ioc-store.db state-get --namespace threat_rss --key feed_state
```

Expected:

- `"found": true`
- `LastRunUtc` is populated

### 6. Alert helper verification

Drop a synthetic alert JSON into `alerts\pending` and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-alert-helper.ps1 -WatchPath .\alerts\pending -StateDbPath .\state\ioc-store.db
```

Expected:

- popup window appears
- popup offers:
  - `Open Alert`
  - `Open Folder`
  - `Dismiss`
- alert JSON and matching Markdown file move to `alerts\archive`
- alert helper state is visible in SQLite:

```powershell
python .\ioc_store.py --db .\state\ioc-store.db state-get --namespace alert_helper --key seen_alerts
```

### 6a. Management UI verification

Launch the UI:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-monitor-ui.ps1 -Port 8876
```

Then fetch or open:

```text
http://127.0.0.1:8876/
```

Expected:

- dashboard loads without error
- task cards show installed Codex tasks, actions, and triggers
- pending and archived alerts are listed
- indicator-store counts and ingest runs are visible
- `http://127.0.0.1:8876/api/snapshot` returns JSON

### 7. Installer verification

Use a fresh runtime and data root:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-codex-monitor.ps1 -RuntimeRoot .\deploy-runtime -DataRoot .\deploy-data
```

Validate:

- runtime scripts copied to `deploy-runtime`
- `ioc_store.py` copied to `deploy-runtime`
- `get-codex-monitor-status.ps1` copied to `deploy-runtime`
- `codex-monitor.settings.json` created
- `deploy-data\alerts\pending`
- `deploy-data\alerts\archive`
- `deploy-data\indicators`
- `deploy-data\state`

### 8. Final acceptance checks

Before signoff, confirm:

- automated tests pass
- SQLite state exists and is readable
- feed import succeeds
- IOC scan succeeds
- tripwire baseline and check succeed when run sequentially
- RSS monitor succeeds
- alert popup appears and archives alerts
- installer lays down the expected runtime/data split

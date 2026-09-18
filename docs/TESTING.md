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

These tests focus on the SQLite-backed Codex Monitor state store and persistent app-state layer.

They verify:

- schema initialization
- normalized indicator import/export
- deduplication behavior
- SQLite `app_state` round-trips
- stats output including `app_state_count`
- UI settings resolution, alert parsing, and safe-path enforcement
- CSF workspace fragment rendering, active-action state, and modal markup contracts
- official NIST CSF catalog integrity (six Functions, 22 current Categories, and 106 current Subcategories)
- CSF Explorer direct-URL selection, explicit unmapped-outcome state, and the centrally mapped `DE.CM` monitoring-task action contract
- advisory-only local CSF SQLite storage, `LOCAL.*` identifier generation, Function scoping, and rejection of orphaned local outcomes

Run them directly:

```powershell
python -m unittest discover -s .\tests -p "test_*.py" -v
```

### PowerShell smoke tests

The smoke runner checks:

- PowerShell scripts still parse
- required fixture files exist
- `codex_monitor_store.py` compiles
- Python unit tests pass

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\run-smoke-tests.ps1
```

## Manual verification procedure

### Fixed-workspace UI verification

At a 1024x1280 display baseline (with at least a 1000x1000 browser content viewport), open each CSF Function and confirm that the browser document has no vertical scroll bar. Confirm that long evidence and findings scroll within the workspace, the selected CSF action is dark blue, and direct URLs still render when JavaScript is disabled.

In DETECT, select `DE.CM` and confirm that the Category-level workspace lists only the reviewed monitoring tasks, each task's last/next run and health state, and its **Run now** control. Select `DE.CM-09` and confirm that it shows the official outcome text plus the explicit no-mapping state; it must not claim that the outcome is satisfied. Confirm that the direct URL preserves both selections: `/detect?csf_category=DE.CM&csf_subcategory=DE.CM-09`.

Open a SQLite report or alert from a list. Confirm that it opens in a centered modal, Escape and Close dismiss it, and Open full page preserves the direct record route.

Confirm that switching between CSF actions reuses the startup snapshot and is responsive. The visible **Refresh live PC snapshot** action is the only ordinary UI action that should trigger the slower full Windows inventory.

Run this sequence in the dev workspace before cutting a release or testing a fresh deployment.

### 1. Clean prerequisites

Confirm these paths exist:

- `alerts\pending`
- `alerts\archive`
- `state\codex-monitor.db`

If `state\codex-monitor.db` does not exist yet:

```powershell
python .\codex_monitor_store.py init  # initializes schema/profile content; retains operational records
```

### 2. Application state-store verification

Import feeds:

```powershell
powershell -ExecutionPolicy Bypass -File .\import-threat-feeds.ps1
```

Validate:

```powershell
python .\codex_monitor_store.py stats
python .\codex_monitor_store.py export-indicators --output .\evidence\codex-monitor-export.json
```

Expected:

- `indicator_count` is greater than `0`
- `ingest_run_count` increases
- `evidence\codex-monitor-export.json` is created only because it was explicitly requested

To validate the record-specific exports after a collection produces immutable IDs:

```powershell
python .\codex_monitor_store.py export-report --report-id <report-id> --output .\evidence\report.json
python .\codex_monitor_store.py export-alert --alert-id <alert-id> --output .\evidence\alert.json
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
python .\codex_monitor_store.py --db .\state\codex-monitor.db state-get --namespace host_tripwire --key baseline
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
python .\codex_monitor_store.py --db .\state\codex-monitor.db state-get --namespace threat_rss --key feed_state
```

Expected:

- `"found": true`
- `LastRunUtc` is populated

### 6. Alert helper verification

Use a pending SQLite alert/delivery record created by a supported collector test fixture, then run the helper against that disposable state database:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-alert-helper.ps1 -StateDbPath .\state\codex-monitor.db
```

Expected:

- popup window appears
- popup offers:
  - `Open Alert`
    - opens the immutable SQLite alert-detail route in the local UI
  - `Dismiss`
- dismissal records acknowledgement for the claimed delivery in SQLite
- no alert JSON or Markdown file is required or created
- alert/delivery state is visible in SQLite:

```powershell
python .\codex_monitor_store.py --db .\state\codex-monitor.db stats
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
- `codex_monitor_store.py` copied to `deploy-runtime`
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

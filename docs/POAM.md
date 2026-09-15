# POAM

This Plan of Action and Milestones captures the current next steps for the Codex monitor project.

## Objective

Move the project from a working prototype into an operationally trustworthy monitoring and exposure-management system.

## Canonical Source and Runtime Boundary

`C:\\CodexTestWork` is the sole canonical development workspace for source, tests, documentation, and release preparation.

`C:\\CodexTest` is a retained legacy runtime and rollback source only. Do not edit source files there. Its five Codex tasks were retargeted to the protected replacement on 2026-09-09; retain the directory until the release-retention gate below is approved.

Evidence from `C:\\CodexTest` validates only that legacy runtime's current operational behavior. It does not validate un-deployed changes in `C:\\CodexTestWork`.

### Legacy runtime retirement checklist

Before deleting `C:\\CodexTest`:

1. Release and validate the canonical workspace in its replacement protected runtime/data paths.
2. Preserve or migrate `C:\\CodexTest\\state\\ioc-store.db`, `C:\\CodexTest\\indicators\\feed-indicators-latest.json`, archived alerts, and `codex-monitor.settings.json` according to the approved data-retention plan.
3. Retarget all five Codex scheduled tasks away from `C:\\CodexTest`, then verify their actions and results against the replacement runtime.
4. Confirm no scheduled task, launcher, or running process references `C:\\CodexTest`.
5. Retain an archive of the legacy runtime until the replacement passes the release gates; only then remove the old directory.

As of 2026-09-09, no legacy-only root scripts or configuration files were found. The live state database, indicator export, archived alerts, settings, and task definitions remain migration inputs.

## Current Constraint

Do not move all JSON storage yet.

Scope guidance:

- keep JSON where it is still useful for reports, alerts, exports, and operator review
- keep SQLite for application state, normalized intelligence, and query-oriented data
- only migrate individual JSON-backed areas when there is a specific verified need and explicit approval

### Verified deployed storage layout (2026-09-09)

The project intentionally uses a hybrid storage model; it is not an all-SQLite system.

| Storage | Location | Purpose |
| --- | --- | --- |
| SQLite | `C:\\ProgramData\\CodexMonitor\\state\\ioc-store.db` | normalized indicators, ingest runs, app state, tripwire baseline/hash records, and normalized current/historical computer-state evidence snapshots used for IOC correlation |
| Indicator export | `C:\\ProgramData\\CodexMonitor\\indicators\\feed-indicators-latest.json` | portable current-feed export for scanners and operator inspection |
| Alerts | `C:\\ProgramData\\CodexMonitor\\alerts\\pending` and `alerts\\archive` | human-readable JSON/Markdown notification records |
| Configuration | `C:\\Program Files\\CodexMonitor\\*.json` | runtime settings, profile/rule catalogs, monitoring locations, and tripwire configuration |
| Reports | `C:\\Program Files\\CodexMonitor\\HOST_*.json`, `THREAT_RSS_*.json`, and Markdown peers | immutable, operator-readable collector output |
| Migration evidence | `C:\\ProgramData\\CodexMonitor\\migration-backup\\20260909` | legacy task/settings backup, preserved reports, and validation logs |

At the last validation, SQLite contained 169,052 indicators, 86 ingest runs, 4 application-state records, 4 baseline runs, 18,589 baseline hashes, and 83 evidence snapshots. During an IOC scan, the collector first saves its current normalized computer-state snapshot to SQLite, then uses the SQLite evidence-snapshot matcher and baseline-hash join to correlate it with SQLite indicators. Exact SQL-backed matching is preferred for hashes, IPs, domains, URLs, registry keys/values, services, tasks, and command-line patterns. A narrow in-memory fallback remains for indicator types not yet represented by the normalized snapshot schema (for example, filename, file-path, and certificate-thumbprint matching). The report/output JSON is retained as a readable artifact rather than duplicated wholesale into SQLite.

### Intended storage direction: SQLite-first operational runtime

The intended end state is for SQLite to be the sole operational store for computer-state observations, indicators, correlation results, report summaries, and alert records. The IOC scanner must query SQLite indicators directly and perform its correlations through SQLite joins; it must not require `feed-indicators-latest.json` to run. The UI and notifier must likewise read report and alert records from SQLite rather than requiring JSON/Markdown files.

JSON/Markdown may remain only as an explicit, optional export format for operator sharing, backup, or offline review. They must not be required inputs to scheduled collectors, the UI, or alert delivery. Configuration catalogs may remain JSON because they are deployment configuration rather than operational state. Migration and rollback evidence is governed by [MIGRATION_BACKUP_RETENTION.md](./MIGRATION_BACKUP_RETENTION.md): it remains in `C:\ProgramData\CodexMonitor\migration-backup`, is never automatically purged, and requires explicit post-gate disposal approval.

Do not delete the current JSON artifacts until the SQLite readers, database schema/migrations, retention policy, export command, regression coverage, and live scheduled-task verification are complete.

The staged implementation plan, schema direction, safety gates, and rollback requirements are in [SQLITE_FIRST_MIGRATION_PLAN.md](./SQLITE_FIRST_MIGRATION_PLAN.md). The first implementation slice is direct SQLite indicator lookup/matching with fixture parity tests.

## Project Progress

### 2026-09-09 - Test, packaging, and runtime migration

Completed:

- Installed and verified Python 3.12.10 for the development host.
- Added the missing installer runtime dependencies for accepted-posture-drift actions, posture-baseline collection, protection profiles, and persona/system/posture-drift rule profiles.
- Added a smoke assertion for each required installer-manifest target and included the root-level dependencies in the transfer-media builder.
- Fixed the Windows SQLite handle-retention failure in the tripwire-guardrails test.
- Corrected SYSTEM task registration to use the Windows ScheduledTasks API, avoiding the `schtasks.exe` quotation failure with the protected `Program Files` runtime path.
- Migrated the legacy SQLite state, indicator export, alerts, settings, and report evidence into `C:\\ProgramData\\CodexMonitor`; SQLite integrity and migrated record counts matched the source before cutover.
- Deployed the runtime to `C:\\Program Files\\CodexMonitor` and data to `C:\\ProgramData\\CodexMonitor`, then retargeted all five Codex tasks.

Verified:

- the formerly failing SQLite test passes twice in isolation;
- `tests\\run-smoke-tests.ps1` passes all 40 tests, PowerShell parser checks, Python compilation checks, and installer-manifest checks;
- the installer source assets required by the new manifest entries exist.
- a clean-runtime installer test completed successfully with disposable runtime and data roots under `tmp\\installer-verification-20260909`; it copied the required runtime files and profiles, initialized SQLite state, created the expected data directories, and wrote settings with the requested paths.
- after the successful SYSTEM tripwire verification, the operator confirmed that the interactive alert popup appeared; this validates the scheduled-check to pending-alert to user-session notification path.
- the final installer-led deployment completed successfully and all five task actions now point only to `C:\\Program Files\\CodexMonitor`; the four collectors run as `SYSTEM` at highest privilege and the notifier runs as the interactive user.
- a temporary direct SYSTEM diagnostic completed successfully after deployment and generated a protected-runtime Tripwire report from `C:\\ProgramData\\CodexMonitor\\state\\ioc-store.db`; the production hidden-wrapper `Codex Host Tripwire` task last returned `0` after its retargeting.
- the temporary diagnostic task was removed after validation. No Codex task action references `C:\\CodexTest`.
- a post-cutover process audit found no active Codex Monitor or legacy-runtime workers. The only path match during the audit was the one-shot inspection process itself.
- a direct SYSTEM validation refreshed the threat-feed export and SQLite store: 61,908 normalized feed records yielded 169,052 stored indicators across 86 ingest runs.
- production-task verification exposed a hidden-launcher defect: `run-hidden.vbs` passed a `.cmd` path under `Program Files` to Windows unquoted, allowing a scheduled task to return `0` without reliably starting its collector. The launcher now quotes its argument, and `tests\\run-smoke-tests.ps1` asserts that behavior.
- after deployment of that correction, the production RSS task returned `0` and wrote `THREAT_RSS_2026-09-09_17-27-52.json`; it processed two feeds with zero new items. The production IOC task returned `0`, wrote `HOST_IOC_IOC_2026-09-09_17-27-27.json`, and reported zero IOC findings.
- the normal Tripwire run at 2026-09-09 17:27 local time raised a High alert with nine alertable changes. Review confirmed that they were the removal of the temporary migration diagnostic task, re-registration of Codex task files during deployment, and a settings-file timestamp update with an unchanged SHA-256 value. Current task actions point only to the protected runtime, all five tasks last returned `0`, and the temporary diagnostic task is absent. These migration-era persistence findings remain visible; do not automatically accept or suppress them.
- the first normal unattended hourly cadence after cutover completed at 2026-09-09 18:27 local time. Task Scheduler recorded time-trigger launches for Tripwire and RSS; both returned `0` and wrote fresh protected-runtime reports (`HOST_TRIPWIRE_CHECK_2026-09-09_18-27-52.json` and `THREAT_RSS_2026-09-09_18-27-52.json`). The remaining cadence gate is the 02:00 feed import and 03:00 IOC scan.
- the remaining pre-deployment overnight cadence gate completed successfully on 2026-09-10. `Codex Threat Feed Import` ran at 02:00 local time with Scheduler result `0` and refreshed `C:\ProgramData\CodexMonitor\indicators\feed-indicators-latest.json` at 06:01:46Z; its metadata records five sources and 61,830 normalized indicators. `Codex IOC Daily Scan` ran at 03:00 local time with Scheduler result `0` and wrote `C:\Program Files\CodexMonitor\HOST_IOC_IOC_2026-09-10_03-00-01.json` at 07:01:33Z. That report records 61,830 loaded indicators, zero matches, and available evidence/baseline hash indexes. This proves the deployed JSON-compatible cadence is healthy and clears the pre-deployment observation gate. It does not validate the pending source-only SQLite-first collector or transactional-writer changes; those require a separately approved deployment followed by another scheduled-cadence verification.
- Phase 1 is operationally complete. A clean Phase 1-only candidate was validated before deployment: it returned active SQLite indicators from fixture data, filtered expired indicators, and failed closed when its SQLite path was unavailable; it contains no Phase 2 report-persistence code. Only `ioc_store.py` and `invoke-host-ioc.ps1` were copied to the protected runtime after backup to `C:\ProgramData\CodexMonitor\migration-backup\phase1-20260910-132627`. A separate one-time SYSTEM task ran the normal IOC launcher at 2026-09-10 13:42 local time, returned `0`, and wrote `HOST_IOC_IOC_2026-09-10_13-42-05.json`. The report records `IndicatorSource` `sqlite`, the default `C:\ProgramData\CodexMonitor\state\ioc-store.db`, 169,193 active indicators, zero matches, and available evidence/baseline hash indexes. The temporary task was removed; `Codex IOC Daily Scan` retains its normal 03:00 schedule. Full source validation passed 52 tests, PowerShell parser and smoke checks, Python compilation, and `git diff --check` before deployment.
- Phase 1 SQLite-first preparation now includes a source-only, read-only `ioc_store.py query-active-indicators` command with deterministic type filtering and host-UTC expiration handling. Its unit coverage passes, and the full suite passes 41 tests. It is not deployed or wired into the scheduled IOC scanner until the overnight cadence gate completes.
- a source-only read-only check of the Phase 1 query against the live SQLite database returned 169,052 active indicators without changing the deployed runtime or database. Normal source `-Mode IOC` now uses this SQLite query by default; explicit `-IocPath` remains an offline JSON compatibility override. This integration remains undeployed pending the cadence gate.
- Phase 1 command-contract coverage now invokes `ioc_store.py query-active-indicators --type url` against a temporary SQLite store and verifies its filtered JSON response. The full suite passes 42 tests, PowerShell parser/smoke checks pass, and `git diff --check` reports no whitespace errors. This remains source-only and has not altered the deployed protected runtime, scheduled tasks, or production database.
- The IOC collector's unused implicit `IndicatorExportPath` / `feed-indicators-latest.json` selection helper has been removed. JSON remains available only through the explicit `-IocPath` offline compatibility override, and smoke coverage fails if an implicit JSON fallback is restored. The source-only full suite remains green at 42 tests.
- Phase 1 fail-closed verification found that an unavailable SQLite path could previously be reported as an empty IOC scan because the collector's global permissive error setting allowed execution to continue. The SQLite active-indicator reader now emits a visible error and exits with code `1` before host collection or report output. Smoke coverage verifies the nonzero exit, error text, and absence of a generated IOC report with an isolated missing database path. The disposable probe reports created while identifying this defect were removed.
- Parallel pre-cadence work is complete in source only: Phase 1 parity coverage proves expiration filtering for the SQLite evidence-snapshot and baseline-hash joins; Phase 2 has an idempotent migration ledger plus additive `collector_runs`, `reports`, `findings`, `alerts`, and `alert_deliveries` schema/index foundation with no active runtime consumers; and the remaining UI JSON/report dependencies and their planned stable-ID query replacements are mapped in [SQLITE_UI_DEPENDENCY_MAP.md](./SQLITE_UI_DEPENDENCY_MAP.md). The reviewable change grouping is documented there. Full parser, smoke, Python compilation, and regression validation passes 44 tests with no whitespace errors. No source changes have been committed, pushed, deployed, or applied to production SQLite.
- The Phase 1 installer/task/documentation follow-through is complete in source: the generated `Codex IOC Daily Scan` launcher invokes `invoke-host-ioc.ps1 -Mode IOC` without `-IocPath`; smoke coverage enforces that contract. `IndicatorExportPath` remains only the optional feed-export location and status/UI display. Operations and installation documents now describe SQLite as the normal scanner input and label `-IocPath` as offline compatibility/test use. The full suite remains green at 44 tests; deployment and post-deployment cadence verification remain pending.
- Phase 2 source preparation now includes `persist_collector_run_report_findings`, a single SQLite transaction for one immutable collector run, report summary, and ordered normalized findings. The store enables foreign-key enforcement for new connections; tests prove successful normalized persistence and full rollback when the finding set violates its report-sequence constraint. No collector, UI, notifier, deployment, scheduled task, or production database uses this new writer yet.
- Phase 3 preparation has begun in source only: `list_persisted_reports` and `get_persisted_report` expose stable report-ID list/detail data, ordered findings, parsed summaries/evidence, collector context, and optional export paths from SQLite. Fixture tests cover ordering and missing reports. The UI remains on its existing JSON/Markdown readers until Phase 2 collector persistence is connected and parity fixtures are available.
- Phase 2 has advanced through a source-only IOC vertical slice: `ioc_store.py persist-collector-report` validates and atomically persists a JSON envelope; its CLI contract is covered by a subprocess test. `invoke-host-ioc.ps1` now creates that envelope from its existing completed report and writes its run/report/findings to SQLite after producing the JSON/Markdown exports. Smoke coverage asserts the source connection and all 48 tests pass. This has not run against a live host, been deployed, or changed production SQLite. Tripwire, RSS, and feed-import mappings remain pending.
- Phase 2 source-only Tripwire mapping is now present. After writing its existing exports, `invoke-host-tripwire.ps1` persists a `tripwire_check` report and ordered change findings through the same transactional CLI. It preserves severity, classification, CSF mapping, guardrail protections, rule details, and exact acceptance context. Parser and smoke coverage pass within the 48-test full suite. This mapping has not run live or been deployed; RSS and feed-import mappings remain pending.
- Phase 2 source mappings and parity fixtures are complete: IOC, Tripwire check, Tripwire baseline, RSS, and feed import all call the transactional collector-report writer. The baseline uses `tripwire_baseline`; the shared parity fixture covers all five report types and preserves a protected Tripwire finding. Full validation passes 49 tests. Phase 2 is not operationally complete until these undeployed mappings run through scheduled collectors and report/finding parity is verified against their real exports.
- Phase 2 is operationally complete. The deployed transactional writer and IOC, Tripwire, RSS, and feed-import mappings were backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase2-20260911-020455`; no UI or notifier code was deployed. The controlled normal-task runs all returned `0`. Feed import persisted `THREAT_FEED_IMPORT_2026-09-11T06-07-14-8961841Z` with zero findings; IOC persisted `HOST_IOC_IOC_2026-09-11_02-07-46` with zero findings; RSS persisted `THREAT_RSS_2026-09-11_02-13-57` with zero findings. The first live Tripwire parity check exposed an exported-ID defect: SQLite had fallback IDs but the JSON report had none. `invoke-host-tripwire.ps1` now assigns immutable IDs before it writes JSON and persists the report; the corrected runtime was backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase2-tripwire-id-20260911-021711`. The corrected check returned `0` and persisted `HOST_TRIPWIRE_CHECK_2026-09-11_02-17-11` with six Warning findings whose count, severity, and ordered IDs exactly match SQLite. The final database counts were two migration rows, five collector runs/reports, and 20 findings. The Phase 2 fixture suite covers baseline mapping without replacing the live trusted baseline. JSON/Markdown exports remain active; the UI and notifier remain on their current readers.
- Phase 3 is operationally complete. `ioc_store.py`, `codex_monitor_ui.py`, and `accept-posture-drift.ps1` were backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase3-20260911-022727` and deployed without changing the notifier. The live UI now lists SQLite reports, emits `/report?id=...` stable links, renders SQLite report detail, and uses SQLite as the primary Respond-queue source. The legacy path-based JSON/Markdown route remains live as rollback fallback. The acceptance helper now takes immutable `-ReportId` and exact `-FindingId` and reads persisted report/finding data; no wildcard selection is introduced. The live Tripwire report currently contains only non-eligible or guardrail-protected findings, so a persisted-ID request correctly made no production acceptance change. Source validation passed 52 tests, including active/accepted/guardrail/missing-report/export-fallback UI fixtures and exact-ID/wildcard/guardrail acceptance coverage. Live HTTP verification returned `200` for `/reports`, SQLite report detail, Respond, and the legacy export fallback.
- Phase 4 is operationally complete. The protected runtime backup is `C:\ProgramData\CodexMonitor\migration-backup\phase4-20260911-094011`; deployed files include `ioc_store.py`, `invoke-host-tripwire.ps1`, `start-codex-alert-helper.ps1`, `codex-alert-notifier.cmd`, and `run-hidden.vbs`. The notifier uses SQLite claim/complete commands rather than pending-directory polling; failed deliveries are retryable and an interrupted claim expires after five minutes. The interactive notifier identity has Modify access only to `C:\ProgramData\CodexMonitor\state`, including SQLite WAL/SHM sidecars; protected-runtime permissions remain unchanged. A normal Tripwire run persisted linked SQLite alerts, then the interactive notifier returned `0` after popup dismissal and recorded both validation deliveries as `delivered` with their alerts `acknowledged`. JSON/Markdown alert exports remain optional review artifacts. Full validation passes 55 tests, including source-link integrity, acknowledged-delivery duplicate prevention, failed-delivery retry, and interrupted-claim recovery.
- Installer follow-up (Phase 4 blocker): grant the configured interactive notifier identity the minimum required Modify access to `DataRoot\state` during installation, so it can update `ioc-store.db` and its SQLite WAL/SHM sidecars for atomic alert delivery claims and acknowledgements. Do not grant write access to the protected runtime. Record the granted identity and add a clean-install/notifier acknowledgement test before treating the Phase 4 task path as operationally complete.
- Phase 5 is operationally complete in the isolated clean candidate. The collectors retain operational JSON/Markdown only when explicitly requested with `-Export`; `ioc_store.py` supplies exact-ID `export-indicators`, `export-report`, and `export-alert` commands; and the UI reads alerts from SQLite by immutable `alert_id` rather than alert files. The clean candidate's five standard scheduled tasks each returned `0`, the dashboard and Respond routes returned HTTP `200`, and recursive inspection found zero operational `HOST_*`, `THREAT_*`, `ALERT_*`, feed-indicator JSON, or Markdown artifacts. The candidate's SQLite database contained persisted reports and acknowledged alerts with no pending alerts. Full regression validation passed 62 tests, including exact-ID acceptance, wildcard refusal, dangerous-finding guardrails, SQLite UI fixtures, and no-export collector contracts. Existing JSON/Markdown material remains available only as explicit exports or retained migration evidence; see `SQLITE_FIRST_MIGRATION_PLAN.md` for the detailed Task 1-8 record.
- local `main` and GitHub `origin/main` were confirmed at the same commit, `c85225e` (`Clean up runtime path assumptions`). The local worktree remains intentionally dirty with the pending Respond/UI, installer, documentation, test-reliability, and handoff/artifact changes; no commit or push was performed during this work.

Current release blockers:

- the completed source, test, and documentation changes remain uncommitted and must be separated into reviewable release slices before a production release candidate is prepared;
- the five verified candidate tasks target the isolated `C:\CodexTestWork\.phase5-task7-clean-runtime` / data roots, not the protected production runtime; a separately approved protected-runtime deployment remains required;
- legacy `C:\CodexTest` retention and production cutover remain separate release-management decisions.

Next management actions:

1. Separate the working tree into reviewable Respond/UI, installer, and test-reliability changes before any release candidate is prepared.
2. Observe the next normal scheduled cadence for RSS, feed import, IOC scan, and Tripwire; retain the generated reports and investigate any nonzero task result or missing output.
3. Design and test a baseline-refresh workflow that does not capture its own temporary SYSTEM task as scheduled-task drift. Preserve the existing guardrail rule; do not broadly suppress task-persistence changes.
4. Approve a retention period and then remove `C:\\CodexTest` only after the protected deployment has passed the remaining operational gates.
5. Only after those operational gates pass, begin vulnerability-intelligence ingestion and host-software matching.

### Proposed release slices

Do not combine these slices in one release candidate:

1. **Respond/UI**: `README.md`, `codex_monitor_ui.py`, `docs/CSF_WORKFLOW_AND_CONFIGURATION_DRIFT.md`, `docs/PC_Care_UI_Design_Document.md`, `docs/Product Description.md`, `docs/Product_Description_UPDATED.md`, `docs/TESTING.md`, and `tests/test_codex_monitor_ui.py`.
2. **Installer packaging**: `install-codex-monitor.ps1`, `tests/run-smoke-tests.ps1`, `tests/build-transfer-iso.ps1`, and `docs/INSTALL.md`.
3. **Test reliability and project record**: `tests/test_tripwire_guardrails.py` and `docs/POAM.md`.

Keep `CodexTest.zip`, `_ui_snapshot.html`, `ui-verify.png`, `winerror.h`, and generated evidence artifacts out of commits and release media. `PROJECT_TAKEOVER_NOTES.md` and `diagnose-codex-workspace.ps1` should be reviewed separately as handoff/diagnostic material.

## Backlog Items

### Make SQLite alert detail an operator-facing investigation view

Status: open; identified 2026-09-13 during live Tripwire alert validation.

`Open Alert` correctly resolves an immutable SQLite alert, but the current `/alert?id=...` page renders raw JSON metadata. An operator must manually copy the linked `report_id` and construct a `/report?id=...` URL to inspect the findings that caused the popup. This is not a reasonable investigation workflow.

Replace the raw alert-detail view with an operator-facing page that presents the alert summary, severity, lifecycle, collection time, linked report, and linked finding. Include an obvious `View report and findings` action using the immutable report ID; show a finding-focused action when the linked finding exists. Keep raw JSON available only through the existing explicit `export-alert` command. Add fixtures for a linked alert, an alert whose report or finding has been retained or is unavailable, and an alert with a guardrail-protected finding. Verify the desktop popup's `Open Alert` action reaches this investigation view end to end.

### Avoid self-generated scheduled-task drift during SYSTEM baseline refresh

Status: open; observed 2026-09-09.

Creating the one-time SYSTEM task needed to refresh the trusted tripwire baseline caused that task and its task-file removal to appear as Critical changes in the next check. The guardrail behavior is correct: the changes must not be automatically accepted. Design a dedicated SYSTEM baseline execution path that does not leave the bootstrap task in the captured scheduled-task snapshot, and add an end-to-end regression check.

### Define SQLite operational retention and controlled compaction

Status: open; identified 2026-09-11 after Phase 5 verification.

The SQLite-first runtime has no automatic pruning or compaction policy. Expired indicators are excluded from active matching, but their rows remain stored; collector observations, reports, findings, alerts, deliveries, evidence snapshots, and baseline records likewise have no configured retention window. The retained local database measured 412 MB with 167,487 indicators and multiple observation tables containing tens of thousands of rows.

Define approved, type-specific retention windows; implement transactional pruning that preserves the foreign-key relationships required for report, finding, alert, delivery, acceptance, and rollback auditability; and add an operator-invoked maintenance command that performs a verified SQLite `VACUUM` only after pruning. Do not add an unattended destructive cleanup task until retention periods, backup requirements, and rollback obligations are explicitly approved. Add fixture and live-maintenance tests proving expired rows are removed only within policy and that the database can be compacted safely.

### Investigate SQLite handle retention in the tripwire-guardrails test

Status: resolved 2026-09-09; verified on Windows with Python 3.12.10.

`tests/test_tripwire_guardrails.py::TripwireGuardrailTests.test_helper_creates_sqlite_acceptance_row_for_app_integrity_finding`
passes its assertions but fails while `TemporaryDirectory` removes its fixture because `state\\ioc-store.db` is still in use (`WinError 32`).

Reproduce with:

```powershell
python -m unittest tests.test_tripwire_guardrails.TripwireGuardrailTests.test_helper_creates_sqlite_acceptance_row_for_app_integrity_finding -v
```

Cause: the test's SQLite context manager committed or rolled back but did not close its read connection. `read_accepted_rows` now explicitly closes that connection in a `finally` block. The formerly failing test passes twice in isolation and the full 40-test smoke suite passes. This is not part of the installer-manifest change.

## Current Priorities

### 1. Stabilize Scheduled Task Outcomes

Goal:

- make routine scheduled execution clean and understandable

Work:

- inspect all Codex scheduled tasks with `LastResult != 0`
- determine for each task whether the result is:
  - a real bug
  - a harmless Windows status code
  - a path, permission, or runtime issue
- fix the failures one at a time
- verify each task with actual runtime output, not just task registration state

Success criteria:

- scheduled tasks are installed, enabled, and return expected status codes
- nonzero results are either eliminated or explicitly understood and documented

### 2. Revalidate Installer and Runtime Packaging

Goal:

- confirm that the packaged runtime still behaves correctly after the latest UI and status-script fixes

Work:

- verify the installer deploys the current runtime set
- verify the deployed UI launches cleanly
- verify the deployed scheduled tasks still point at the intended files
- verify the runtime state paths and SQLite DB paths are correct

Success criteria:

- install and deployed runtime remain aligned with the current repository state
- no stale launcher or task-definition behavior remains

### 3. Improve Detection Quality With Vulnerability Intelligence

Goal:

- move beyond raw IOC matching into exploit-aware exposure detection

Work:

- add vulnerability intelligence ingestion for:
  - CISA KEV
  - VulnCheck KEV
  - EPSS
  - CVE/NVD
  - key vendor advisory feeds
- normalize that data into SQLite
- store fields such as:
  - CVE
  - KEV status
  - due date
  - ransomware use
  - EPSS score
  - percentile
  - CVSS
  - affected product/version info

Success criteria:

- the system can answer:
  - whether the host is exposed to an actively exploited vulnerability
  - how urgent that exposure is
  - what source supports that assessment

### 4. Add Host Software and Version Matching

Goal:

- detect vulnerable installed software and running products on the host

Work:

- collect installed software and product version facts
- normalize software identity enough for CVE matching
- map host software to:
  - KEV
  - EPSS-ranked CVEs
  - vendor advisories
  - NVD/CVE affected ranges

Success criteria:

- the system can raise findings like:
  - exploited CVE present on host
  - high-EPSS vulnerable product present on host
  - crown-jewel product requires urgent patching

### 5. Surface Exposure and Operations Data in the UI

Goal:

- turn the UI into the primary operator console

Work:

- add UI views for:
  - exploited CVEs on host
  - KEV findings
  - EPSS-ranked exposures
  - vendor advisory queue
  - task execution issues
  - alert drill-down
- keep verification discipline:
  - fix
  - verify live output
  - then report completion

Success criteria:

- the UI is useful for both operations and triage
- key security posture questions can be answered from the UI directly

## Working Method

All work should follow the process in [HANDOFF.md](./HANDOFF.md), especially:

1. reproduce
2. fix
3. verify
4. notify

Do not mark tasks complete without verification of the actual runtime behavior or actual served output.

## Immediate Next Step

Observe the next normal scheduled cadence and preserve its reports.

Reason:

- all five tasks have been retargeted and manually exercised after migration
- one normal unattended cycle is the remaining evidence needed before legacy-runtime retirement can be considered
- any nonzero task result, missing report, or unexpected alert should be investigated before new capability is added

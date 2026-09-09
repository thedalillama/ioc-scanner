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

JSON/Markdown may remain only as an explicit, optional export format for operator sharing, backup, or offline review. They must not be required inputs to scheduled collectors, the UI, or alert delivery. Configuration catalogs may remain JSON because they are deployment configuration rather than operational state.

Do not delete the current JSON artifacts until the SQLite readers, database schema/migrations, retention policy, export command, regression coverage, and live scheduled-task verification are complete.

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
- local `main` and GitHub `origin/main` were confirmed at the same commit, `c85225e` (`Clean up runtime path assumptions`). The local worktree remains intentionally dirty with the pending Respond/UI, installer, documentation, test-reliability, and handoff/artifact changes; no commit or push was performed during this work.

Current release blockers:

- the worktree still combines uncommitted Respond/UI, installer, documentation, and test-reliability changes;
- The SYSTEM baseline refresh and a manually triggered `Codex Host Tripwire` check both returned `0`. The fresh check report was written in SYSTEM context. The other four expected Codex tasks last returned `0` at the time of review.
- The fresh tripwire report contains two Critical findings for removal of the one-time baseline-refresh task and its task file. These are expected maintenance artifacts from creating the SYSTEM baseline, but remain visible because guardrails intentionally prevent automatic acceptance of suspicious task persistence changes.

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

### Avoid self-generated scheduled-task drift during SYSTEM baseline refresh

Status: open; observed 2026-09-09.

Creating the one-time SYSTEM task needed to refresh the trusted tripwire baseline caused that task and its task-file removal to appear as Critical changes in the next check. The guardrail behavior is correct: the changes must not be automatically accepted. Design a dedicated SYSTEM baseline execution path that does not leave the bootstrap task in the captured scheduled-task snapshot, and add an end-to-end regression check.

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

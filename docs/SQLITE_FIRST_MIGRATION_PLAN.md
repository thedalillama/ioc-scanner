# SQLite-First Operational Storage Migration Plan

## Decision

SQLite will become the sole operational store for normalized indicators, computer-state observations, correlation results, collector reports, findings, alerts, and delivery state. JSON and Markdown may be generated only as optional exports. Deployment configuration remains JSON.

This is a design and migration plan. It does not authorize deleting existing JSON artifacts or changing the deployed runtime until each gate is passed.

## Current state

`state/ioc-store.db` already contains the `indicators` table, normalized evidence-snapshot tables, baseline hashes, accepted posture drift, and application state. The IOC scan saves its current evidence snapshot to SQLite and uses SQLite evidence and baseline-hash matching for supported indicator types.

The remaining operational JSON dependencies are:

| Consumer | Current JSON dependency | Required replacement |
| --- | --- | --- |
| IOC scan | `feed-indicators-latest.json` is loaded before matching | SQLite indicator query/matcher with validity filtering |
| Respond/UI | Tripwire and IOC report files are enumerated and parsed | report, finding, and report-summary queries |
| Alert helper/notifier | pending alert JSON/Markdown files are polled | pending alert query with delivery state |
| Accepted-drift helper | report JSON supplies the requested finding | finding lookup by immutable report/finding identifier |
| Operator sharing | JSON/Markdown reports and exports | explicit export command, not a runtime prerequisite |

## Target schema additions

Add additive, versioned schema migrations in `ioc_store.py`; do not repurpose existing evidence tables.

- `collector_runs`: one immutable row per Tripwire, RSS, feed-import, or IOC run; stores collector name/version, start/end, outcome, and operational summary.
- `reports`: report identity, collector-run reference, report type, collection timestamp, severity/overall status, structured summary JSON, and optional export paths.
- `findings`: normalized immutable findings linked to a report; stores finding identifier, category, severity, classification, evidence fields, CSF mapping, guardrail state, and response state.
- `alerts`: alert identity, source report/finding references, severity, summary, lifecycle state, and timestamps.
- `alert_deliveries`: delivery attempts keyed by alert and user/session channel, with atomic status transitions to prevent repeated popups.

Indexes must support current UI and scanner access paths: valid indicators by type/value, reports by collector/time, findings by report/severity/classification, alerts by lifecycle/severity, and undelivered alerts.

## Delivery sequence

### Phase 1: Direct SQLite indicator matching

1. Add an `ioc_store.py` command/API that streams valid indicators by type/value and performs supported exact correlations against the stored current snapshot.
2. Change `invoke-host-ioc.ps1 -Mode IOC` to use that API by default. Keep `-IocPath` only as an explicit offline/import compatibility mode.
3. Remove `IndicatorExportPath` as a required scanner setting; retain it only for an explicit export command.

Gate: regression tests prove the same supported matches from a fixture snapshot and fixture indicator set through the SQLite path, including expired-indicator filtering and baseline-hash joins.

Implementation status (operationally complete, 2026-09-10): the active-indicator command, default scanner lookup, explicit JSON override, expiration filtering, evidence-snapshot parity coverage, baseline-hash parity coverage, unavailable-store fail-closed smoke check, and SQLite-default installer launcher verification are implemented. Operations and install instructions now show the SQLite-default scheduled invocation; remaining `-IocPath` examples are explicitly labeled offline compatibility/test use. The pre-deployment 02:00 feed-import and 03:00 IOC cadence completed successfully on 2026-09-10. A Phase 1-only runtime candidate was then deployed, with the prior `ioc_store.py` and `invoke-host-ioc.ps1` retained at `C:\ProgramData\CodexMonitor\migration-backup\phase1-20260910-132627`. The one-time SYSTEM validation at 13:42 local time returned `0` and wrote `HOST_IOC_IOC_2026-09-10_13-42-05.json`; it records `IndicatorSource: sqlite`, the default state database, 169,193 active indicators, zero matches, and available evidence/baseline indexes. The temporary validation task was removed and the normal daily task remains scheduled for 03:00. This satisfies the Phase 1 operational gate.

#### Phase 1 API contract

Add a read-only `ioc_store.py query-active-indicators` command. It accepts optional repeated `--type` filters and returns a deterministic JSON payload with the normalized fields currently consumed by `invoke-host-ioc.ps1`: `indicator_id`, `type`, `value`, `source`, `confidence`, `severity`, `first_seen`, `last_seen`, `valid_until`, `reference_url`, and parsed `raw_source_record`.

The command excludes expired indicators by default using host UTC. `--include-expired` exists only for diagnostics and tests. Values are normalized using the same rules as `upsert_indicators`; results are ordered by `type`, `value`, and `source`. It performs no writes.

`invoke-host-ioc.ps1` will call this command for unsupported/in-memory indicator types only. Supported exact types continue to use the existing `evidence-snapshot-match` and `baseline-hash-match` SQLite joins. During the compatibility period, explicit `-IocPath` remains a test/offline override; normal scheduled `-Mode IOC` must not load `feed-indicators-latest.json`.

Required tests:

1. Active indicators are returned with the documented fields and deterministic order.
2. An expired indicator is excluded by default and present only with `--include-expired`.
3. Type filtering does not return other indicator types.
4. Fixture parity proves supported evidence-snapshot and baseline-hash joins are unchanged after the scanner stops loading the export JSON.
5. The scanner fails closed with a clear error if SQLite is unavailable; it does not silently revert to a stale export.

### Phase 2: Persist reports and findings

1. Add one writer API that persists a collector run, report summary, and normalized findings in a single SQLite transaction.
2. Make Tripwire, RSS, feed import, and IOC call that writer after collection.
3. Keep JSON/Markdown dual-write only as optional export output during the transition.

Gate: report/finding counts, severities, and identifiers match between SQLite and a temporary export for representative baseline, check, RSS, and IOC fixtures.

Implementation status (operationally complete, 2026-09-11): additive `schema_migrations`, `collector_runs`, `reports`, `findings`, `alerts`, and `alert_deliveries` tables plus access-path indexes are deployed. `persist_collector_run_report_findings` atomically writes one immutable collector run, report, and ordered findings; success and rollback behavior are tested. Its `persist-collector-report` CLI envelope is tested. IOC, Tripwire baseline/check, RSS, and feed import map completed JSON/Markdown exports into that contract; Tripwire preserves classification, severity, exact guardrail/acceptance context, and CSF mapping. The protected runtime was backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase2-20260911-020455` before deploying only `ioc_store.py` and the IOC, Tripwire, RSS, and feed-import collectors. The first live Tripwire parity run found that fallback IDs were not written to its JSON export; the collector was corrected, backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase2-tripwire-id-20260911-021711`, and revalidated. Final normal-task runs returned `0`: feed import persisted `THREAT_FEED_IMPORT_2026-09-11T06-07-14-8961841Z` (zero findings), IOC persisted `HOST_IOC_IOC_2026-09-11_02-07-46` (zero findings), Tripwire persisted `HOST_TRIPWIRE_CHECK_2026-09-11_02-17-11` (six Warning findings with exact exported IDs), and RSS persisted `THREAT_RSS_2026-09-11_02-13-57` (zero findings). Export-to-SQLite count, severity, and identifier parity passed for all four live collector types; the representative baseline mapping remains covered by the passing fixture suite and was not rerun live because doing so would replace the trusted baseline. JSON/Markdown outputs remain live and the UI/notifier do not yet read these tables.

### Phase 3: Move UI and acceptance flows to SQLite

1. Replace report-directory enumeration and JSON parsing in the UI with report/finding queries.
2. Replace path-based report URLs with stable report IDs; retain read-only legacy file links only while exports exist.
3. Change accepted-drift actions to select an immutable SQLite finding ID, preserving exact-match and guardrail constraints.

Gate: UI tests cover missing report, active findings, accepted findings, guardrail-protected findings, and legacy-export fallback. Acceptance tests prove wildcard/pattern acceptance remains refused.

Implementation status (operationally complete, 2026-09-11): the UI now uses SQLite `reports`/`findings` as its primary report list, Respond queue, and `/report?id=<immutable-report-id>` detail source. The legacy `/report?path=...` route remains read-only fallback for JSON/Markdown exports. The protected UI was backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase3-20260911-022727` before deployment and was verified live on localhost: `/reports` emits stable-ID links, the SQLite detail route returns the persisted Tripwire report, and the legacy export route remains available. `accept-posture-drift.ps1` now accepts `-ReportId` plus exact `-FindingId`, reads the persisted report through `get-persisted-report`, and preserves its existing guardrail/exact-match restrictions. The current live Tripwire report has no acceptance-eligible findings, so its persisted-ID request correctly refused without changing production state; the full test suite covers exact-ID acceptance, guardrail refusal, wildcard refusal, active/accepted/protected fixtures, missing reports, and export fallback. JSON/Markdown exports remain retained for rollback and operator review.

### Phase 4: Move alert delivery to SQLite

1. Write alerts and lifecycle state transactionally with their report/finding records.
2. Change the notifier to atomically claim and mark alert delivery in `alert_deliveries`.
3. Retire directory polling as the delivery mechanism; retain optional alert exports for operator review.

Gate: tests prove a notifier restart does not duplicate an acknowledged delivery, failed delivery is retryable, and alert severity/source links remain intact.

Implementation status (operationally complete, 2026-09-11): `persist-collector-report` now accepts optional alert records and writes each alert plus its interactive delivery row in the same SQLite transaction as the collector run, report, and findings. `claim-alert-deliveries` atomically claims only pending or failed rows for one channel/recipient; interrupted claims are recovered only after a five-minute lease. `complete-alert-delivery` records either acknowledgement or a retryable failure. The notifier now exclusively uses those commands as its delivery queue and uses the persisted source-report export link only for operator review. The legacy pending-alert directory is no longer polled or archived by the notifier; collectors may retain JSON/Markdown alert exports. The protected runtime was backed up to `C:\ProgramData\CodexMonitor\migration-backup\phase4-20260911-094011` before deployment. The interactive notifier identity was granted Modify access only to `C:\ProgramData\CodexMonitor\state`, including SQLite WAL/SHM sidecars; protected runtime permissions were not broadened. A normal Tripwire task returned `0` and persisted alert records with exact source report/finding links. The final interactive notifier run returned `0` and changed both queued validation alerts to `alert.lifecycle_state=acknowledged` and `alert_deliveries.delivery_state=delivered`. Full regression passes 55 tests, proving source-link integrity, no duplicate claim after acknowledgement, retry after failure, and interrupted-claim recovery.

Installer requirement: installation must grant the configured interactive notifier identity minimum Modify access to `DataRoot\state` (including SQLite WAL/SHM sidecar creation) while retaining protected-runtime read-only behavior. This must be clean-install tested before Phase 4 can be declared operationally complete.

### Phase 5: Retire JSON as an operational dependency

1. Remove required `IndicatorExportPath`, alert inbox/watch paths, and mandatory report-file parsing from runtime code.
2. Provide explicit `export-indicators`, `export-report`, and `export-alert` commands with documented destination and retention behavior.
3. Retain existing JSON/Markdown only under the approved migration-backup retention policy.

Gate: a clean runtime install, all five scheduled tasks, UI, acceptance workflow, and notifier operate with no report/alert/indicator JSON present. Configuration JSON remains supported.

Implementation status (in progress, 2026-09-11): the installer now grants the configured interactive notifier identity Modify access only to `DataRoot\state` when it creates the notifier task, covering SQLite WAL/SHM sidecars without broadening protected-runtime access. Smoke coverage enforces the installer contract and the full suite passes 55 tests. No existing JSON/Markdown export or migration evidence has been removed.

Phase 5 implementation inventory: `invoke-host-ioc.ps1`, `invoke-host-tripwire.ps1`, `monitor-threat-rss.ps1`, and `import-threat-feeds.ps1` still write operational JSON/Markdown by default. `codex_monitor_ui.py` still calls `list_alert_records` for filesystem alert views and falls back from SQLite report queries to `list_recent_reports`. These paths must be converted to explicit export-only operations or removed from active runtime flows before the clean no-operational-JSON gate can run.

Task 1 status (complete in source, 2026-09-11): normal IOC, RSS, and Tripwire report paths now require explicit `-Export` for retained report artifacts; feed import retains an indicator file only with `-Export` or explicit `-OutputPath`. The Respond view no longer parses a latest Tripwire JSON file when SQLite has no report; it reports the missing persisted record instead. Full parser/smoke validation passes 55 tests. Remaining Phase 5 work is explicit report/alert export commands, the Tripwire baseline/alert artifact path, and the clean no-operational-JSON gate.

Task 2 status (complete in source, 2026-09-11): `ioc_store.py` provides explicit `export-indicators`, `export-report --report-id`, and `export-alert --alert-id` commands. Each writes only to the caller-provided destination; report and alert exports require their immutable SQLite identifier. `export-json` remains an indicator-export compatibility alias. Unit coverage verifies indicator, report, and alert export payloads end to end. Operator destination and retention behavior is documented in `docs/OPERATIONS.md`; existing migration evidence remains subject to the approved migration-backup retention policy.

Task 3 status (complete in source, 2026-09-11): [MIGRATION_BACKUP_RETENTION.md](./MIGRATION_BACKUP_RETENTION.md) defines `C:\ProgramData\CodexMonitor\migration-backup` as the sole migration-evidence retention boundary. It prohibits automatic cleanup, requires timestamped deployment backups, keeps retained evidence out of operational reader paths, and requires an explicit post-gate approval before disposal. No existing JSON/Markdown evidence was deleted, moved, or deployed as part of this task.

Checklist item 4 status (complete in source, 2026-09-11): IOC, RSS, Tripwire, and feed-import artifact output is opt-in through `-Export` (or the feed-import's explicit `-OutputPath`). IOC, RSS, and Tripwire persist report records with blank export paths by default. Tripwire baseline indexing serializes to a temporary file only when no export is requested and deletes it after indexing; Tripwire alert JSON/Markdown is also export-only. Feed import uses temporary serialization for SQLite ingestion and deletes it even when ingestion fails. `tests/test_phase5_export_contract.py` protects the default no-export contract for all four collectors. Runtime deployment and the clean no-operational-JSON gate remain pending.

Checklist item 5 status (complete in source, 2026-09-11): `export-report --report-id <immutable-report-id>` and `export-alert --alert-id <immutable-alert-id>` are available through `ioc_store.py`. Both require an exact persisted SQLite identifier and caller-provided output path; missing records fail without a substitute export. The end-to-end export test verifies report, finding, alert, and linked report identifiers in the resulting JSON payloads.

Checklist item 6 status (complete in source, 2026-09-11): the UI no longer accepts alert inbox/archive paths, enumerates alert JSON files, or exposes `/alert?path=...`. It reads SQLite alerts by immutable `alert_id`, renders SQLite-backed pending and recorded alert rows, and exposes a record-specific `export-alert` instruction rather than a file-reader route. Fixture coverage verifies the SQLite alert reader, immutable link, and explicit export guidance; the Phase 5 contract test rejects reintroduction of active alert-file readers or paths. The legacy report-file fallback remains outside this checklist item and is not used for alerts.

Checklist item 7 status (complete, 2026-09-11): a clean candidate was installed without task registration or initialization at `C:\CodexTestWork\.phase5-task7-clean-runtime` and `C:\CodexTestWork\.phase5-task7-clean-data`. The data root contains only `state\ioc-store.db`; the runtime contains deployment configuration JSON only. Recursive artifact validation found zero `HOST_*`, `THREAT_*`, `ALERT_*`, `feed-indicators*.json`, or Markdown operational artifacts. SQLite `stats` succeeded with zero indicators, runs, baseline hashes, and evidence snapshots. This proves the installer can lay down a clean no-operational-JSON state; Task 8 separately verifies the five tasks, UI, acceptance flow, and notifier.

Task 8 status (complete, 2026-09-11): the clean candidate registered the five standard monitor tasks because none existed on the host. Feed import, IOC, Tripwire, RSS, and notifier each completed with Scheduler result `0`; Tripwire required a correction to the extra quote pair in `run-hidden.vbs`, followed by candidate redeployment and a successful rerun. The candidate UI returned HTTP `200` for both `/` and `/respond`, including the SQLite `alert_id` response route. Its SQLite store contains persisted reports and acknowledged alerts with no pending alerts, while recursive artifact validation still finds zero `HOST_*`, `THREAT_*`, `ALERT_*`, `feed-indicators*.json`, or Markdown operational artifacts. The one-time SYSTEM baseline task used during validation was removed, leaving only the five standard tasks. Full regression coverage passes `62` tests, including exact immutable-ID acceptance, wildcard refusal, and dangerous-finding guardrails. The candidate UI process was stopped after verification.

## Rollback and safety

- Every schema migration is additive and idempotent; record a schema version in SQLite.
- During phases 1–4, retain JSON export and read fallback until parity tests and a normal scheduled cadence pass.
- Never auto-accept, suppress, or delete guardrail-protected findings during migration.
- Follow [MIGRATION_BACKUP_RETENTION.md](./MIGRATION_BACKUP_RETENTION.md) for all migration evidence; do not automatically delete any backup set.
- Do not delete `C:\\CodexTest` as part of this work.

## First implementation slice

Implement Phase 1 only: direct SQLite indicator lookup/matching plus fixture parity tests. It has the smallest operational surface area, removes the scanner's hard dependency on `feed-indicators-latest.json`, and does not require changing UI or alert delivery.

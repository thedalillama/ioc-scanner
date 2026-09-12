# UI JSON Dependency Map

Status: source-only migration inventory, 2026-09-09.

This map records the remaining UI dependencies on JSON/Markdown runtime artifacts. It is a migration checklist, not authorization to change the deployed UI.

| UI area | Current dependency | Current code path | SQLite replacement | Phase |
| --- | --- | --- | --- | --- |
| Alert queues | `alerts\\pending\\ALERT_*.json` and `alerts\\archive\\ALERT_*.json` | `list_alert_records`, `build_alert_record` | `alerts` joined to `alert_deliveries`; query lifecycle/severity and expose delivery state | 4 |
| Recent reports | `HOST_IOC_*.json`, `HOST_TRIPWIRE_*.json`, `THREAT_RSS_*.json` under the runtime root | `list_recent_reports` | `reports` ordered by `collection_time_utc`, with `summary_json` for the existing table fields | 3 |
| Latest Tripwire response queue | latest Tripwire report path from status, then `HOST_TRIPWIRE_CHECK_*.json` discovery and parsing | `find_latest_tripwire_check_report`, response-queue builders | latest `reports` row for `report_type=tripwire_check`, joined to immutable `findings` | 3 |
| Detection detail | latest IOC report path from status, then JSON parse | `build_detection_snapshot_detail` | latest IOC `reports` row plus linked `findings` and summary fields | 3 |
| Report detail link | filesystem path passed to `/report?path=...` | `render_report_row`, request handler | `/report?id=...` served from `reports`/`findings`; optional file link remains export-only during transition | 3 |
| Accepted posture drift | report path and finding array index passed to helper | `build_acceptance_helper_command` | immutable `finding_id` and `report_id`; exact-match/guardrail policy remains in SQLite | 3 |

## Migration constraints

- Do not remove file parsing until the equivalent SQLite query has parity tests and one normal scheduled cadence has passed.
- Keep report and alert JSON/Markdown as explicit, operator-readable exports during Phases 2–4.
- Preserve file-link support only as an export convenience; runtime decisions must use stable database identifiers.
- Guardrail-protected findings must never gain an acceptance action merely because the UI data source changes.

## Reviewable change grouping

The dirty worktree should be split without staging unrelated user artifacts:

1. `feat(sqlite-indicators)`: active-indicator command, IOC SQLite default, expiration-safe joins, and store tests.
2. `feat(sqlite-schema)`: additive Phase 2 schema ledger/tables/indexes and schema tests.
3. `test(ioc-fail-closed)`: unavailable-store smoke regression.
4. `docs(sqlite-migration)`: migration plan, UI dependency map, and POAM updates.

The existing UI/Respond and installer changes remain separate review items. Do not commit, push, or deploy any group until the project owner approves the reviewed diff and the overnight cadence gate has been assessed.

## Phase 3 inactive cutover contract

`list_sqlite_reports_preview`, `get_sqlite_report_detail_preview`, stable `/report?id=<report_id>` link construction, SQLite-row rendering, and immutable-finding acceptance previews are source-only helpers. No current route calls them, and `live_action_enabled` remains false. Rollback is therefore immediate: keep the existing JSON/Markdown readers and do not enable these helpers until deployed Phase 2 records and export parity are verified.

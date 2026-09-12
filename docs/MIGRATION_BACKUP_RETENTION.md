# Migration-backup retention policy

## Purpose and boundary

`C:\ProgramData\CodexMonitor\migration-backup` is the sole retention location
for migration and rollback evidence. It is not an operational report, alert, or
indicator directory. Scheduled collectors, the UI, acceptance workflow, and the
notifier must use SQLite and must not read this directory during normal operation.

Configuration JSON remains outside this policy because it is deployment
configuration, not operational evidence.

## What is retained

Retain an immutable, timestamped backup directory before each runtime deployment
or migration that changes collector, UI, notifier, acceptance, installer, or
database behavior. Each directory must contain only the files needed to restore
or audit that change, plus any associated validation log or explicitly preserved
JSON/Markdown evidence.

Existing operational JSON/Markdown generated before the SQLite cutover may be
preserved only by placing a copy in this directory. New JSON/Markdown artifacts
are allowed only when an operator invokes an explicit export command and chooses
the destination; they are not automatically copied into migration backup.

## Retention and disposal

There is no automatic age-based deletion, scheduled cleanup task, or installer
cleanup of `migration-backup`. Retain each backup at least until all of the
following are true:

1. The Phase 5 clean no-operational-JSON gate has passed.
2. The replacement runtime has passed the documented release and rollback gates.
3. An operator explicitly approves disposal of the named backup set.

Disposal is a separate, manual change. Before approving it, record the exact
backup directory, its deployment/validation evidence, and confirmation that no
rollback obligation or retention requirement still applies. Never delete
`C:\CodexTest` as part of this policy; it has its own release-retention gate in
`docs/POAM.md`.

## Verification

The no-operational-JSON validation must run with report, alert, and indicator
JSON absent from their normal runtime locations while `migration-backup` remains
intact. A successful validation proves that retained evidence is not an active
dependency; it does not authorize its deletion.

# POAM

This Plan of Action and Milestones captures the current next steps for the Codex monitor project.

## Objective

Move the project from a working prototype into an operationally trustworthy monitoring and exposure-management system.

## Current Constraint

Do not move all JSON storage yet.

Scope guidance:

- keep JSON where it is still useful for reports, alerts, exports, and operator review
- keep SQLite for application state, normalized intelligence, and query-oriented data
- only migrate individual JSON-backed areas when there is a specific verified need and explicit approval

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

All work should follow the process in [HANDOFF.md](C:/CodexTest/docs/HANDOFF.md), especially:

1. reproduce
2. fix
3. verify
4. notify

Do not mark tasks complete without verification of the actual runtime behavior or actual served output.

## Immediate Next Step

Start with scheduled task outcome review.

Reason:

- this is the fastest path to operational trust
- the UI now makes task state visible
- fixing task result issues will reduce uncertainty before adding more capability

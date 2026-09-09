# Local Windows NIST CSF Posture Audit

This project is a local Windows NIST CSF posture/control audit module. It verifies Windows-native protections, detects configuration drift from a trusted baseline, classifies findings with local explainable rules, records accepted posture changes in SQLite, and reports results in NIST CSF language.

Windows remains the protection layer. This app verifies, explains, records evidence, and guides review.

## What This App Does

- Reviews local Windows security posture.
- Establishes and compares against trusted baselines.
- Detects observed posture changes and configuration drift.
- Classifies expected operational changes, accepted posture changes, needs-review findings, and response-required findings.
- Preserves evidence in local JSON and Markdown reports.
- Stores accepted posture changes locally in the SQLite state database.
- Uses NIST CSF language for Govern, Identify, Protect, Detect, Respond, and Recover.
- Supports personas from Home User to Technician.

## What This App Is Not

This app is not:
- an antivirus replacement
- an EDR
- a SIEM
- a cloud security service
- a fleet-management platform
- an enterprise GPO or Intune replacement
- a replacement for Windows Defender, Firewall, Windows Update, BitLocker, Secure Boot, or UAC

## CSF Workflow

The app translates the NIST CSF lifecycle into a local PC workflow:

1. Govern - Set the plan
2. Identify - Know this PC
3. Protect - Check safeguards
4. Detect - Detect configuration drift
5. Respond - Handle findings
6. Recover - Confirm trusted operation

Detect records observed configuration drift. Respond is where findings are reviewed, classified, accepted, mitigated, escalated, or left open. Recover validates that trusted operation has been restored after response.

## Configuration Drift

Configuration drift means the current system state differs from the trusted baseline. Not every observed change is an alert. Some changes are expected operational changes, some are accepted posture changes, and some require review or response.

The app uses these user-facing labels:

- Observed posture changes
- Expected operational changes
- Accepted posture changes
- Needs review
- Response required
- Guardrail protected

## Accepted Posture Changes

Accepted posture changes are exact, reviewed changes recorded locally in SQLite. They are not deleted, hidden, or broadly suppressed. They remain part of the audit trail and do not override dangerous guardrails.

Accepted posture changes are stored in the local SQLite state database.

## Personas

- Home User - plain-language status and safe guidance
- Advanced User - evidence summaries and reports
- NIST CSF Native - CSF function and category framing with mappings
- Analyst - findings, evidence interpretation, and posture review
- Technician - diagnostics, raw paths, helper scripts, and technical evidence

## Documentation Map

- `README.md` - project overview and product positioning
- `docs/Product_Description_UPDATED.md` - canonical product intent and policy direction
- `docs/CSF_WORKFLOW_AND_CONFIGURATION_DRIFT.md` - workflow and state-machine definition for configuration drift handling
- `docs/PC_Care_UI_Design_Document.md` - UI presentation and interaction direction
- `docs/OPERATIONS.md` - day-2 operational usage and troubleshooting
- `docs/TESTING.md` - verification procedures

## Current Implementation Status

The app already includes local posture collection, baseline comparison, IOC matching, alerting, scheduled monitoring, a browser UI, and SQLite-backed accepted posture change records.

The app currently surfaces posture findings through Detect and Reports, with ongoing work to make Respond a fuller interactive finding queue.

Recover confirms trusted operation after response. Planned recovery views include confidentiality, integrity, and availability validation panels.

## Runtime and Deployment

The app can run from any local runtime folder. Wrapper scripts resolve paths relative to their own location or the configured runtime root. `C:\CodexTest` may be used as a development example but is not required.

## Repository Layout

```text
<repo-root> (development workspace example)
|-- alerts/
|   |-- pending/
|   `-- archive/
|-- docs/
|-- examples/
|-- indicators/
|-- state/
|-- tests/
|-- codex-monitor.settings.example.json
|-- codex-monitor.settings.json
|-- codex_monitor_ui.py
|-- get-codex-monitor-status.ps1
|-- import-threat-feeds.ps1
|-- install-codex-monitor.ps1
|-- invoke-host-ioc.ps1
|-- invoke-host-tripwire.ps1
|-- ioc_store.py
|-- monitor-threat-rss.ps1
|-- run-hidden.vbs
|-- start-codex-alert-helper.ps1
`-- start-codex-monitor-ui.ps1
```

## Core Components

- `invoke-host-tripwire.ps1`
  - creates trusted baselines and checks for observed posture changes
- `invoke-host-ioc.ps1`
  - collects local evidence and checks it against normalized threat indicators
- `import-threat-feeds.ps1`
  - imports public threat intelligence and updates the local SQLite store
- `ioc_store.py`
  - manages the local SQLite state and indicator store
- `monitor-threat-rss.ps1`
  - monitors relevant threat and advisory feeds
- `start-codex-alert-helper.ps1`
  - turns pending alerts into user-session popup notifications
- `get-codex-monitor-status.ps1`
  - summarizes local posture, task health, and evidence state
- `codex_monitor_ui.py`
  - serves the local persona-aware management UI
- `install-codex-monitor.ps1`
  - deploys the runtime and optional scheduled tasks

## Quick Start

Create or refresh a trusted baseline:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Baseline
```

Import threat intelligence:

```powershell
powershell -ExecutionPolicy Bypass -File .\import-threat-feeds.ps1
```

Run a posture check:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-tripwire.ps1 -Mode Check
```

Run IOC matching:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC -IocPath .\examples\normalized-indicators.example.json
```

Check local monitor health:

```powershell
powershell -ExecutionPolicy Bypass -File .\get-codex-monitor-status.ps1
```

Launch the management UI:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-codex-monitor-ui.ps1 -OpenBrowser
```

## Scheduled Monitoring Model

With scheduled tasks installed, the intended local monitoring flow is:

1. `Codex Threat Feed Import`
   - refreshes the normalized indicator export
   - updates the SQLite state database
2. `Codex IOC Daily Scan`
   - checks local evidence against the latest indicators
3. `Codex Host Tripwire`
   - checks for observed posture changes from the trusted baseline
4. `Codex Threat RSS Monitor`
   - detects relevant advisories and can trigger follow-up collection
5. `Codex Alert Notifier`
   - turns pending alerts into popup windows in the interactive user session

## Evidence and Outputs

The app writes timestamped JSON and Markdown artifacts into the runtime folder or configured data root.

Important output patterns:

- `HOST_IOC_*.json/md`
- `HOST_TRIPWIRE_*.json/md`
- `THREAT_RSS_*.json/md`
- `<DataRoot>\alerts\pending\ALERT_*.json/md`
- `<DataRoot>\alerts\archive\ALERT_*.json/md`
- `<DataRoot>\state\ioc-store.db`
- `<DataRoot>\indicators\feed-indicators-latest.json`

## Product Principle

The guiding principle is:

> Make the Windows PC governable, observable, explainable, and auditable.

The app does not promise perfect threat detection. It creates a local, evidence-backed posture record and helps the user understand what changed, what needs review, and what should happen next.

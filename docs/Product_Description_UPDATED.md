# Product Description: Local Windows NIST CSF Control and Audit Module

## 1. Product Definition

This product is a local Windows security control, evidence, and audit module.

It is designed to make an individual Windows PC governable, observable, explainable, and auditable using the language and structure of the NIST Cybersecurity Framework.

The application is not a replacement for Microsoft Defender, Windows Firewall, Windows Update, BitLocker, Family Safety, or other Windows-native protections.

Instead, the application provides a local control layer that:

* defines the intended security posture
* inventories the PC
* verifies Windows-native protections
* collects local evidence
* compares evidence against threat intelligence
* detects drift and policy violations
* guides response
* validates recovery
* produces a NIST CSF-aligned security posture report

The product's core value is not simply protecting the PC. Its value is documenting whether the PC is being governed, protected, monitored, and recoverable according to the NIST CSF workflow.

---

# 2. Product Positioning

The product should be described as:

> A local NIST CSF control and audit module for Windows PCs.

The product makes a home, small-office, or individually managed Windows PC auditable.

It answers:

* What is this PC?
* What security policy applies to it?
* What users and administrators exist?
* What protections are required?
* Are those protections enabled?
* What evidence was collected?
* What threat indicators were checked?
* What was detected?
* What changed?
* What was fixed?
* What exceptions were accepted?
* Is the PC currently aligned with its governed security posture?

The product should produce a repeatable security posture record, not just a one-time status screen.

---

# 3. NIST CSF Operating Model

The product follows the NIST Cybersecurity Framework 2.0 function order:

```text
Govern -> Identify -> Protect -> Detect -> Respond -> Recover
```

For plain-language users, these functions may be shown as:

```text
Set the rules -> Know this PC -> Turn on protections -> Watch for problems -> Help fix problems -> Confirm recovery
```

For Advanced User, NIST CSF Native, Analyst, and Technician users, the product should expose the official CSF-style function codes:

```text
GV - Govern
ID - Identify
PR - Protect
DE - Detect
RS - Respond
RC - Recover
```

The application should map posture items, evidence, controls, and findings to CSF categories wherever practical.

---

# 4. CSF-Coded Reporting for Advanced Personas

Advanced User, NIST CSF Native, Analyst, and Technician users should be able to generate reports using CSF-style terminology.

The report should use function/category labels such as:

```text
GV.OC - Organizational Context
GV.RM - Risk Management Strategy
GV.RR - Roles, Responsibilities, and Authorities
GV.PO - Policy
GV.OV - Oversight
GV.SC - Cybersecurity Supply Chain Risk Management

ID.AM - Asset Management
ID.RA - Risk Assessment
ID.IM - Improvement

PR.AA - Identity Management, Authentication, and Access Control
PR.AT - Awareness and Training
PR.DS - Data Security
PR.PS - Platform Security
PR.IR - Technology Infrastructure Resilience

DE.CM - Continuous Monitoring
DE.AE - Adverse Event Analysis

RS.MA - Incident Management
RS.AN - Incident Analysis
RS.CO - Incident Response Reporting and Communication
RS.MI - Incident Mitigation
RS.IM - Incident Response Plan Improvement

RC.RP - Incident Recovery Plan Execution
RC.CO - Incident Recovery Communication
RC.IM - Incident Recovery Plan Improvement
```

The product does not need to claim formal certification or compliance. It should say that local evidence and controls are mapped to CSF outcomes for posture reporting and auditability.

---

# 5. Plain-English Reporting for Home Users

Home users should not be forced to read framework codes.

For Home User persona, the same evidence should be translated into plain language.

Example:

```text
Security status: Good

The firewall is on.
Microsoft Defender is on.
Windows security updates were checked.
No known warning signs were found in the information checked on this PC.
No unexpected administrator accounts were found.
A recovery baseline is available.
```

The report may still be internally mapped to CSF, but the UI should hide framework labels unless the persona allows them.

---

# 6. Persona-Based Reporting Layers

The same underlying evidence should support multiple report styles.

The intended reporting ladder is:

```text
Home User -> Advanced User -> NIST CSF Native -> Analyst -> Technician
```

This is a UI and reporting sophistication ladder, not a strict access-control boundary.

Persona and managed account type are different concepts and must remain separate.

* Persona answers:
  * Who is using the app?
  * How much security, audit, and technical detail should the UI show?

* Managed account type answers:
  * What kinds of Windows accounts exist on this PC?
  * What protections, restrictions, or exceptions apply to them?

Examples of personas:

* Home User
* Advanced User
* NIST CSF Native
* Analyst
* Technician

Examples of managed account types:

* administrator
* standard user
* child
* teen
* guest

Example distinction:

* A parent may use the app with the Home User persona while the governed PC policy includes child, teen, and guest account rules.
* A security professional may use the app with the Analyst persona while the governed PC policy still includes guest restrictions and administrator controls.

## Home User

Plain language.

Avoid:

```text
IOC
baseline hash corpus
SQLite
CSF subcategory
GV.RM
DE.CM
```

Use:

```text
No known warning signs were found.
The firewall is on.
Your PC has a saved recovery baseline.
```

## Advanced User

Simple security terms plus light technical evidence.

Example:

```text
No known threat indicators matched this PC's latest security check.
```

Advanced users should be comfortable with terms such as:

```text
IOC
snapshot
baseline
service
scheduled task
```

They should see:

* plain security findings
* evidence summaries
* report links
* threat-intelligence freshness
* high-level recovery readiness

## NIST CSF Native

Formal framework-first view for people who want the app framed in NIST CSF terminology.

NIST CSF Native users should see:

* formal CSF labels
* evidence-backed posture summaries
* reports and evidence links
* plain-language summaries when helpful

## Technician

Full host and network technical detail.

Example:

```text
DE.CM - Continuous Monitoring
Evidence tables: process, service, scheduled task, DNS, network connection, file
Matched field: remote_address
Matched value: 203.0.113.10
Matched local port: 445
Matched remote port: 49830
```

Technician users should be comfortable with:

* services
* scheduled tasks
* command lines
* ports and listeners
* evidence snapshots
* raw report artifacts
* diagnostics and observation counts

## Analyst

The most complete security and audit view.

Analyst users should be comfortable with:

* NIST CSF function and category language
* risk statements
* evidence scope and trust
* open risks
* accepted exceptions
* recovery and validation status
* the technical evidence needed to support conclusions

Example:

```text
DE.CM - Continuous Monitoring
Status: Pass
Evidence: IOC snapshot HOST_IOC_IOC_...
Result: No IOC matches were found in the indexed evidence snapshot or latest baseline hash inventory.
SnapshotId: HOST_IOC_IOC_2026-...
StateDbPath: .\state\ioc-store.db
BaselineId: HOST_TRIPWIRE_BASELINE_...
MatchCount: 0
ProcessHashesChecked: 310
BaselineHashesChecked: 4607
FindingCount: 0
Open risks: RC.RP backup status unknown
```

---

# 7. Govern Function

Govern is the control plane.

Govern defines:

* persona
* skin/control surface
* managed account types and account policy
* automation authority
* required protections
* accepted exceptions
* evidence retention
* allowed users
* administrator policy
* child/guest policy
* remote access policy
* threat-intelligence sources
* reporting level
* privacy rules
* safe automation boundaries

Govern answers:

```text
What security posture is intended for this PC?
Who is using the app and at what reporting depth?
What account types on this PC are being governed?
Who is allowed to change it?
What should be automatic?
What requires approval?
What risks are accepted?
What evidence must be preserved?
```

Possible CSF mapping:

```text
GV.OC - local context for this PC
GV.RM - risk strategy and tolerance
GV.RR - roles and authorities
GV.PO - local security policy
GV.OV - oversight of posture and changes
GV.SC - trust of feeds, scripts, tools, and dependencies
```

---

# 8. Identify Function

Identify inventories what exists on the PC.

Identify should collect:

* hostname
* manufacturer and model
* Windows edition/version/build
* current user
* local users
* local administrators
* installed software
* services
* scheduled tasks
* autoruns
* network adapters
* listening ports
* shared folders
* baseline scope
* security-relevant configuration inventory

Identify answers:

```text
What assets, users, software, services, and exposure points exist on this PC?
```

Possible CSF mapping:

```text
ID.AM - Asset Management
ID.RA - Risk Assessment
ID.IM - Improvement
```

Example report item:

```text
ID.AM - Asset Management
Control: Local users, administrators, installed software, services, scheduled tasks, autoruns, network adapters, listening ports, and shared folders were inventoried.
Status: Pass
Evidence: Identify snapshot
```

---

# 9. Protect Function

Protect verifies and manages the controls required by Govern.

Protect should use Windows-native protections wherever possible.

Examples:

* Microsoft Defender Antivirus
* Windows Firewall
* Windows Update
* BitLocker
* Secure Boot
* Controlled Folder Access
* Smart App Control, AppLocker, or WDAC if available
* account separation
* standard user vs administrator
* Family Safety
* app permissions
* browser and web restrictions where available

Protect answers:

```text
Are the required protections actually enabled?
```

Possible CSF mapping:

```text
PR.AA - Identity Management, Authentication, and Access Control
PR.AT - Awareness and Training
PR.DS - Data Security
PR.PS - Platform Security
PR.IR - Technology Infrastructure Resilience
```

Example report item:

```text
PR.PS - Platform Security
Control: Microsoft Defender Antivirus is enabled.
Status: Pass
Evidence: Windows Security status
```

Example firewall item:

```text
PR.IR - Technology Infrastructure Resilience
Control: Windows Firewall is enabled for required profiles.
Status: Pass
Evidence: Firewall profile status
```

---

# 10. Detect Function

Detect collects local evidence, monitors changes, and compares evidence against threat intelligence.

Detect should include:

* evidence snapshots
* IOC matching
* baseline drift checks
* security-control tampering checks
* suspicious service/task/autorun detection
* suspicious command-line detection
* listening-port evidence
* DNS and URL evidence
* KEV/CVE exposure checks
* report generation

Detect answers:

```text
Was anything suspicious, unexpected, vulnerable, or policy-violating observed?
```

Possible CSF mapping:

```text
DE.CM - Continuous Monitoring
DE.AE - Adverse Event Analysis
```

Example report item:

```text
DE.CM - Continuous Monitoring
Control: Local evidence snapshot was collected and checked against threat intelligence.
Status: Pass
Evidence: IOC snapshot HOST_IOC_IOC_...
Result: No known threat indicators matched the collected evidence.
```

Example technical item:

```text
DE.AE - Adverse Event Analysis
Finding: Suspicious local listener
Evidence: TCP listener, local port, owning process, process path, process hash
Status: Review Required
```

---

# 11. Respond Function

Respond guides triage and action after something is detected.

Respond should support:

* finding explanation
* evidence review
* recommended action
* acknowledgement
* investigation status
* marking expected or unexpected
* exporting evidence
* documenting decisions
* escalation
* safe guided remediation where allowed by Govern

Respond answers:

```text
What should be done about this finding?
Was the response documented?
```

Possible CSF mapping:

```text
RS.MA - Incident Management
RS.AN - Incident Analysis
RS.CO - Incident Response Reporting and Communication
RS.MI - Incident Mitigation
RS.IM - Incident Response Plan Improvement
```

Example report item:

```text
RS.AN - Incident Analysis
Finding: IOC match against local evidence
Status: Investigating
Evidence: Finding ID, snapshot ID, matched field, matched value
Recommended action: Review process, verify file hash, run Defender scan
```

---

# 12. Recover Function

Recover validates that the PC has returned to its governed state.

Recover should include:

* last known-good baseline
* recovery baseline availability
* rollback evidence
* post-remediation verification
* control restoration checks
* new trusted baseline only after recovery is confirmed
* recovery report

Recover answers:

```text
Is the PC back to the expected governed state?
```

Possible CSF mapping:

```text
RC.RP - Incident Recovery Plan Execution
RC.CO - Incident Recovery Communication
RC.IM - Incident Recovery Plan Improvement
```

Example report item:

```text
RC.RP - Incident Recovery Plan Execution
Control: Required protections were rechecked after response.
Status: Pass
Evidence: Post-response validation snapshot
```

---

# 13. NIST CSF Security Posture Report

The product should generate a NIST CSF Security Posture Report.

Recommended sections:

```text
1. Executive Summary
2. Govern
3. Identify
4. Protect
5. Detect
6. Respond
7. Recover
8. Open Risks
9. Accepted Exceptions
10. Evidence Appendix
```

For Advanced User, NIST CSF Native, Analyst, and Technician users, the report should include CSF function/category codes.

For Home users, the report should use plain language while preserving the internal CSF mapping.

---

# 14. Example Report Summary

## Plain-English Summary

```text
Security posture: Good

This PC has a defined security policy.
The main Windows protections are enabled.
The PC inventory was collected.
No known threat indicators matched the latest collected evidence.
No unexpected administrator accounts were found.
A recovery baseline is available.

Open items:
- BitLocker status should be reviewed.
- Backup status is unknown.
```

## Advanced CSF Summary

```text
GV.PO - Local security policy defined: Pass
ID.AM - Local asset inventory collected: Pass
PR.PS - Platform protections verified: Pass
PR.IR - Firewall and resilience controls verified: Pass
DE.CM - Evidence snapshot collected and analyzed: Pass
DE.AE - No adverse IOC matches found in collected evidence: Pass
RS.AN - No active findings requiring incident analysis: Pass
RC.RP - Recovery baseline available: Pass

Open Risks:
PR.DS - BitLocker status requires review
RC.RP - Backup status unknown
```

---

# 15. Audit Trail Requirements

The product should preserve an audit trail of posture checks and control actions.

Audit records should include:

* timestamp
* function
* CSF mapping
* control or evidence item
* before state
* after state
* action taken
* automation authority
* user/persona context
* report ID
* snapshot ID
* finding ID, if applicable

Example:

```text
Timestamp: 2026-06-20 09:15
CSF: PR.IR
Control: Windows Firewall
Before: Disabled
After: Enabled
Action: Auto-enabled under Home User safe automation policy
Evidence: Firewall status check
Result: Pass
```

---

# 16. Product Safety Rules

The product must not duplicate Microsoft Defender or become a malware-removal engine.

The application should not:

* replace antivirus scanning
* replace real-time protection
* replace firewall enforcement
* remove malware automatically
* delete files without explicit advanced approval
* kill processes automatically
* disable services automatically
* modify high-risk Windows settings without proper policy and approval

The application should:

* verify controls
* explain findings
* preserve evidence
* recommend action
* automate low-risk governed controls
* escalate risky actions
* document everything

---

# 17. Product Principle

The product's guiding principle is:

> Make the Windows PC governable, observable, explainable, and auditable.

Its strongest value is not that it finds every threat.

Its strongest value is that it creates a defensible local security posture record using NIST CSF language.

The product should always be able to answer:

```text
What did we intend?
What did we check?
What did we find?
What changed?
What did we do?
What evidence proves it?
What still needs attention?
```


---

# 18. Configuration Drift and CSF Workflow Clarification

The product should use the industry-standard term **configuration drift** for a setting, file, service, task, control, or evidence item that differs from the saved trusted baseline.

Plain-language user-facing wording may also use **observed posture change**.

Recommended wording:

```text
Observed configuration drift: this item differs from the trusted baseline.
```

The product should not treat every configuration drift item as an alert. The CSF-aligned workflow is:

```text
Detect = discover observed configuration drift
Respond = handle the finding and decide/action what to do
Recover = verify trusted operation was restored after response
```

## 18.1 CSF-Aligned Drift Counters

The product should prefer these user-facing counters:

```text
observed_posture_change_count
expected_operational_change_count
accepted_posture_change_count
posture_review_count
response_required_count
guardrail_protected_count
```

Meanings:

* **Observed posture changes**: all detected differences from the trusted baseline.
* **Expected operational changes**: known normal OS/app maintenance activity.
* **Accepted posture changes**: exact reviewed changes stored in the local accepted-drift registry.
* **Needs review**: changes that are not accepted or expected but are not necessarily urgent.
* **Response required**: findings that should be surfaced for user action.
* **Guardrail protected**: findings that cannot be downgraded or accepted as routine because they affect important security controls.

Older technical counters may remain for compatibility, but the UI should prefer CSF-aligned labels.

## 18.2 Respond vs Recover

Respond and Recover are separate phases.

```text
Respond = handle the finding.
Recover = confirm trusted operation.
```

Respond includes:

* triage
* validation
* evidence review
* severity/status decision
* mitigation
* containment
* escalation
* communication/export
* accepting an exact reviewed safe posture change

Recover includes:

* rerunning checks after response
* confirming the finding cleared or changed status
* validating that the PC is back to trusted operation
* confirming confidentiality, integrity, and availability
* creating a new trusted baseline only after review

If recovery validation fails, the workflow returns to Respond.

```text
Detect -> Respond -> Recover -> if validation fails, return to Respond
```

Example:

```text
Detect:
Firewall changed from enabled to disabled.

Respond:
Review evidence, classify as response required, choose Mitigate, and re-enable Firewall.

Recover:
Rerun posture check and confirm Firewall is enabled, the finding cleared, and trusted operation is restored.
```

The action of re-enabling the Firewall is Respond. The verification that the Firewall is restored and remains in the trusted state is Recover.

## 18.3 Recover and CIA Validation

Recover should explicitly validate trusted operation across:

```text
Confidentiality
Integrity
Availability
```

Recommended Recover panels:

### Confidentiality restored

Verifies that protections against unauthorized access are in place after response.

Examples:

* Firewall enabled
* Defender protections enabled
* no unexpected Defender exclusions
* no unexpected local administrator additions
* no unexpected shared folders
* Remote Desktop not newly enabled unless accepted/expected

### Integrity restored

Verifies that important settings, trusted tools, app files, and persistence points remain trustworthy after response.

Examples:

* trusted Windows tools intact
* app integrity baseline clean, accepted, or reviewed
* posture rules loaded successfully
* accepted posture change registry loaded successfully
* no suspicious scheduled task/service/autorun persistence
* no unsigned or invalid trusted tool finding

### Availability restored

Verifies that normal safe use and monitoring remain available after response.

Examples:

* Windows security services running
* event logs available
* PowerShell/Defender/Security logs available where expected
* Windows Update/BITS available
* latest posture check completed successfully
* no unresolved response-required finding blocking normal operation

## 18.4 Accepted Posture Changes

Accepted posture changes are governance/audit records, not evidence deletion.

Accepted posture changes should be stored in SQLite as the system of record:

```text
state\ioc-store.db
accepted_posture_drift
```

The accepted-drift registry should remain exact-match only unless a future explicit design approves a broader scope.

Acceptance must not override dangerous guardrail findings such as:

* Defender disabled
* Firewall disabled
* logging weakened or unavailable
* trusted Windows tool missing or invalidly signed
* suspicious persistence from Temp, Downloads, or unusual AppData
* encoded PowerShell or remote payload startup command

## 18.5 Recommended UI Workflow Labels

Use this workflow language:

```text
Govern: Set the plan
Identify: Know this PC
Protect: Check safeguards
Detect: Detect configuration drift
Respond: Handle findings
Recover: Confirm trusted operation
```

The Home page should summarize the workflow in plain language, for example:

```text
This PC has 10 observed posture changes.
2 findings require response.
2 findings are guardrail protected.
No accepted posture changes are currently recorded.
```


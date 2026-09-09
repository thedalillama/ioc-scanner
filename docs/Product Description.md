# Product Description: Local Windows NIST CSF Posture and Control Audit Module

## 1. Product Definition

This product is a local Windows NIST CSF posture/control audit module.

It is designed to make an individual Windows PC governable, observable, explainable, and auditable using the language and structure of the NIST Cybersecurity Framework.

The application is not a replacement for Microsoft Defender, Windows Firewall, Windows Update, BitLocker, Family Safety, or other Windows-native protections. It is also not an antivirus replacement, an EDR, a SIEM, a fleet-management tool, a cloud security service, or an enterprise GPO or Intune replacement.

Instead, the application provides a local control and evidence layer that:

* defines the intended security posture
* inventories the PC
* verifies Windows-native protections
* collects local evidence
* compares evidence against threat intelligence
* detects configuration drift and posture violations
* guides response
* validates recovery
* produces a NIST CSF-aligned security posture record

Windows remains the protection layer. The app verifies, explains, records evidence, and guides review.

---

# 2. Product Positioning

The product should be described as:

> A local Windows NIST CSF posture/control audit module.

The product makes a home, small-office, or individually managed Windows PC auditable.

It answers:

* What is this PC?
* What security policy applies to it?
* What users and administrators exist?
* What protections are required?
* Are those protections enabled?
* What evidence was collected?
* What threat indicators were checked?
* What observed posture changes were detected?
* Which findings need review or response?
* What accepted posture changes are recorded?
* Is the PC currently aligned with its governed security posture?

The product should produce a repeatable security posture record, not just a one-time status screen.

---

# 3. NIST CSF Operating Model

The product follows the NIST Cybersecurity Framework 2.0 function order:

```text
Govern -> Identify -> Protect -> Detect -> Respond -> Recover
```

The product should use this plain-language workflow wording:

```text
Govern: Set the plan
Identify: Know this PC
Protect: Check safeguards
Detect: Detect configuration drift
Respond: Handle findings
Recover: Confirm trusted operation
```

For Home User persona, the app may present the same workflow in simpler narrative language. For Advanced User, NIST CSF Native, Analyst, and Technician users, the product should expose the official CSF-style function codes:

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

## Analyst

Security analysis and posture review view.

Analyst users should be comfortable with:

* NIST CSF function and category language
* risk statements
* evidence scope and trust
* observed posture changes and findings
* accepted posture changes
* recovery and validation status
* the technical evidence needed to support conclusions

## Technician

Full host and technical detail.

Technician users should be comfortable with:

* services
* scheduled tasks
* command lines
* ports and listeners
* evidence snapshots
* raw report artifacts
* diagnostics and observation counts

---

# 7. Configuration Drift and Accepted Posture Changes

The product should describe differences from the trusted baseline as configuration drift or observed posture changes.

Not every observed posture change is an alert. The preferred user-facing vocabulary is:

```text
Observed posture changes
Expected operational changes
Accepted posture changes
Needs review
Response required
Guardrail protected
```

Accepted posture changes are exact, reviewed changes recorded locally in the SQLite state database. They remain in the audit trail and must not override dangerous guardrail findings.

---

# 8. Respond and Recover Distinction

Respond and Recover are related but different phases.

```text
Respond = handle findings.
Recover = confirm trusted operation.
```

Respond includes triage, investigation, evidence review, mitigation, escalation, and exact acceptance of reviewed safe changes.

Recover verifies that trusted operation was restored after response and is the place for confidentiality, integrity, and availability validation.

The current product already surfaces findings through Detect and Reports, while the fuller Respond finding queue and Recover CIA validation panels are still being developed.

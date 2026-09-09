# CSF Workflow and Configuration Drift Model

## Purpose

This document defines how the product should guide a user through configuration drift and recovery using NIST CSF-aligned language.

The product is a local Windows NIST CSF posture/control audit module. It does not replace Windows security controls. It verifies local posture, detects configuration drift, guides response, validates recovery, and preserves an audit trail.

## NIST CSF framing

NIST CSF 2.0 organizes cybersecurity outcomes into six Functions:

```text
Govern -> Identify -> Protect -> Detect -> Respond -> Recover
```

The product translates those Functions into a local Windows PC workflow:

```text
Set the plan -> Know this PC -> Check safeguards -> Detect configuration drift -> Handle findings -> Confirm trusted operation
```

The product should not describe CSF as a step-by-step playbook. CSF is the framework of outcomes. The app provides a local workflow that follows the CSF lifecycle.

## Configuration drift terminology

The generally accepted cybersecurity term for a setting or component that differs from the approved baseline is:

```text
configuration drift
```

User-facing language may also use:

```text
observed posture change
```

Recommended product wording:

```text
Observed configuration drift: this item differs from the trusted baseline.
```

CSF-style translation:

```text
Detect records observed configuration drift from the trusted baseline. Some observed changes are expected operational changes, some are accepted posture changes, and some require review or response.
```

## Baseline, current state, and gaps

The product's baseline/current-state model should be treated as a local version of the CSF Current Profile / Target Profile idea:

| Product concept | CSF-aligned concept |
|---|---|
| Trusted baseline | Target or trusted posture |
| Current scan | Current posture |
| Difference between current and baseline | Configuration drift / observed posture change / gap |
| Expected operational change | Normal maintenance activity |
| Accepted posture change | Reviewed and governed exception/change |
| Response-required finding | Finding that requires action |
| New baseline | New trusted state after review |

## Counter names and meanings

Use these CSF-aligned counters in reports and UI:

| Counter | Meaning |
|---|---|
| `observed_posture_change_count` | All detected changes from the saved trusted baseline. |
| `expected_operational_change_count` | Changes classified as known normal operating-system or trusted application maintenance. |
| `accepted_posture_change_count` | Exact changes reviewed and accepted into the local SQLite registry. |
| `posture_review_count` | Changes that are not accepted or expected, but are review-level rather than urgent. |
| `response_required_count` | Findings that should appear as active response items. |
| `guardrail_protected_count` | Findings where security guardrails prevented downgrade or acceptance. |

Old technical counters may remain for compatibility, but user-facing UI should prefer CSF-aligned labels.

## Detect intent

Detect answers:

```text
What changed from the trusted baseline?
```

Detect should show:

- observed configuration drift
- expected operational changes
- accepted posture changes
- posture changes needing review
- findings requiring response
- guardrail-protected findings

Detect should clearly state:

```text
Not every observed posture change is an alert. Expected operational changes and accepted posture changes remain in the audit trail, while response-required findings are the subset that should be surfaced for action.
```

## Respond intent

Respond answers:

```text
What should we do about this finding?
```

Respond is the case-management, decision, and mitigation phase. It includes:

- triage
- validation
- severity/status decision
- evidence review
- acceptance of exact reviewed safe changes
- mitigation
- containment
- escalation
- export/communication of evidence
- leaving a finding open for further review

Respond is where the user chooses statuses such as:

- Needs review
- Investigating
- Expected operational change
- Accepted posture change
- Mitigate
- Escalate
- False positive / not applicable
- Resolved

Dangerous guardrail findings must not be casually accepted as routine. For example:

- Firewall disabled
- Defender protection disabled
- Defender exclusion added
- trusted Windows tool missing or invalidly signed
- suspicious scheduled task from Temp, Downloads, or unusual AppData
- encoded PowerShell persistence

For these, Respond should guide mitigation or investigation rather than routine acceptance.

## Recover intent

Recover answers:

```text
Are trusted operations restored after the response action?
```

Recover does not replace Respond. Recover verifies the outcome of Respond.

Use this mental model:

```text
Respond = handle the finding.
Recover = confirm trusted operation.
```

If Recover fails, the workflow returns to Respond:

```text
Detect -> Respond -> Recover -> if validation fails, return to Respond
```

## Firewall example

```text
Detect:
Firewall changed from enabled to disabled.

Respond:
Review the evidence.
Classify as response required.
Choose Mitigate.
Re-enable the Firewall.

Recover:
Rerun posture check.
Confirm Firewall is enabled.
Confirm no related response-required finding remains.
Confirm trusted operation is restored.
```

The action of re-enabling the Firewall belongs primarily to Respond. The verification that the Firewall is back on and the PC is trusted again belongs to Recover.

## Recover and CIA validation

Recover should explicitly validate trusted operation across the three CIA dimensions:

```text
Confidentiality
Integrity
Availability
```

### Confidentiality restored

Purpose:

```text
Verifies that protections against unauthorized access are in place after response.
```

Example evidence:

- Firewall enabled
- Defender protections enabled
- no unexpected Defender exclusions
- no unexpected local administrator additions
- no unexpected shared folders
- Remote Desktop not newly enabled unless accepted/expected
- no response-required network exposure finding

### Integrity restored

Purpose:

```text
Verifies that important settings, trusted tools, app files, and persistence points remain trustworthy after response.
```

Example evidence:

- trusted Windows tools intact
- app integrity baseline clean, accepted, or reviewed
- posture-drift-rules.json loaded successfully
- accepted_posture_drift SQLite registry loaded successfully
- no suspicious scheduled task/service/autorun persistence
- no unsigned/invalid trusted tool finding
- no response-required app-integrity finding unless accepted/reviewed

### Availability restored

Purpose:

```text
Verifies that normal safe use and monitoring remain available after response.
```

Example evidence:

- Windows security services running
- event logs available
- PowerShell/Defender/Security logs available where expected
- Windows Update/BITS available
- latest posture check completed successfully
- no unresolved response-required finding blocking normal operation

## Recover status model

Each Recover panel may show:

- Restored
- Needs review
- Response required
- Unknown

Suggested logic:

- If related warning/critical or response-required findings exist, show Response required.
- If related review-level findings exist, show Needs review.
- If evidence is missing or not collected, show Unknown.
- If no related issues are present, show Restored.

## Accepted posture changes

Accepted posture changes are governance records, not evidence deletion.

The product now stores accepted posture changes in SQLite:

```text
state\ioc-store.db
accepted_posture_drift
```

Accepted changes are exact-match only and should include:

- AcceptanceId
- Section
- ItemName
- ItemType
- Field
- accepted current value/hash
- baseline value where available
- matched rule ID where available
- reason
- accepted by
- accepted UTC
- expiration where applicable
- source report path/ID
- CSF mapping where available

Important rule:

```text
Accepted posture change records cannot override dangerous guardrail findings.
```

## UI workflow summary

The UI should guide the user like this:

1. **Govern - Set the plan**
   - review persona, rules, accepted changes, automation authority, and baseline policy

2. **Identify - Know this PC**
   - review users, admins, services, tasks, software, listening ports, and trusted tools

3. **Protect - Check safeguards**
   - verify Defender, Firewall, Windows Update, BitLocker, Secure Boot, UAC, logging, and related controls

4. **Detect - Detect configuration drift**
   - compare current state to trusted baseline and classify observed changes

5. **Respond - Handle findings**
   - triage, investigate, mitigate, accept exact reviewed changes, or escalate

6. **Recover - Confirm trusted operation**
   - validate confidentiality, integrity, and availability; rerun checks; create a new trusted baseline only after review

## Recommended UI labels

Main workflow labels:

```text
Govern: Set the plan
Identify: Know this PC
Protect: Check safeguards
Detect: Detect configuration drift
Respond: Handle findings
Recover: Confirm trusted operation
```

Detect summary labels:

```text
Observed posture changes
Expected operational changes
Accepted posture changes
Needs review
Response required
Guardrail protected
```

Recover validation labels:

```text
Confidentiality restored
Integrity restored
Availability restored
```

## Report wording

Use this language in reports:

```text
NIST CSF view: Detect records observed configuration drift from the trusted baseline. Respond focuses attention on findings that require action. Govern records reviewed and accepted posture changes. Recover verifies that trusted operation has been restored and may establish a new trusted baseline after review.
```

Use this language for Recover:

```text
Recover verifies that confidentiality, integrity, and availability have been restored or remain intact after the response action.
```

## References

- NIST Cybersecurity Framework 2.0, CSWP 29, 2024: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
- NIST CSF 2.0 Profiles: https://www.nist.gov/cyberframework/profiles
- NIST CSF 2.0 Implementation Examples: https://www.nist.gov/document/csf-20-implementations-pdf
- NIST SP 800-61r3 Computer Security Incident Handling Guide: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf

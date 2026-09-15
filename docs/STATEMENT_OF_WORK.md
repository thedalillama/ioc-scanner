# Codex Monitor Statement of Work

## 1. Purpose

Codex Monitor is a local Windows cybersecurity learning and posture-monitoring application. It uses the NIST Cybersecurity Framework (CSF) 2.0 as the user-facing model for understanding cybersecurity risk on one PC.

The product must help a CSF Analyst understand:

- what the Framework outcome means in plain English;
- what local evidence exists for that outcome;
- whether the evidence needs attention; and
- which safe, reviewable action is appropriate.

The software is not an antivirus product, a security operations center, or a claim of full NIST CSF implementation or compliance. It is a local evidence and learning platform that maps supported monitoring and review workflows to selected CSF outcomes.

## 2. Product Scope

### In scope

- SQLite-first storage for indicators, reports, findings, alerts, collector runs, evidence snapshots, baselines, and approved local configuration state.
- Local monitoring through the existing feed-import, IOC, RSS, Tripwire, and notifier workflows.
- A browser-based CSF Analyst interface that presents the six CSF Functions as selectable **modes**: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, and RECOVER.
- A versioned, read-only NIST CSF 2.0 catalog of Functions, Categories, and Subcategories.
- A stacked CSF Explorer: Function/mode, Category, Subcategory/outcome, evidence, and actions.
- Plain-English explanations, evidence state, attention hints, and action state for each outcome.
- Centrally implemented, reviewed mappings from supported CSF outcomes to local evidence and safe product actions.
- User-authored, advisory-only local extensions under a selected CSF mode.
- Explicit exports, immutable identifiers, exact-match acceptance controls, and existing guardrail restrictions.

### Out of scope

- A claim that the product implements every NIST CSF outcome or establishes compliance.
- Automatic remediation, unrestricted command execution, or generic script generation from the UI.
- User-authored scripts, executable links, task invocations, forms, evidence queries, or action buttons.
- Remote fleet management, cloud telemetry, or external transmission of local evidence unless separately approved.
- Replacing the established elevation, confirmation, immutable-ID, or guardrail controls for protected operations.

## 3. Terminology

- **Mode:** a selected NIST CSF Function in the top map.
- **Category:** an official CSF Category or a clearly marked local extension under a mode.
- **Subcategory/outcome:** an official CSF Subcategory or a clearly marked local outcome under a local category.
- **Evidence:** local, inspectable data that supports or does not support an outcome.
- **Action:** a concrete user-initiated operation. An action is not a NIST-defined command; it is a reviewed product capability that supports a CSF outcome.
- **Local extension:** advisory user content in the `LOCAL.*` namespace. It is never official NIST content.

## 4. Single-PC CSF Profile and Evidence Model

The product shall define and use a **Single-PC CSF 2.0 Profile**: a scoped application of NIST CSF 2.0 to a standalone Windows Home or Pro endpoint. The Profile is the bridge between a NIST outcome and the local evidence shown to an analyst. It does not claim full CSF implementation or compliance.

For each supported Subcategory, the product mapping shall follow this traceable model:

```text
CSF Subcategory
  -> applicable NIST implementation examples and informative references
  -> single-PC interpretation
  -> Windows-local evidence and user attestations
  -> product assessment and attention state
  -> plain-English analyst wording
```

NIST defines outcomes and provides implementation examples and informative references; it does not generally prescribe a Windows evidence checklist. Product wording shall therefore state that the application collects local Windows evidence that helps evaluate an outcome. It shall not state or imply that NIST requires a particular registry value, event log, PowerShell result, account list, or other local artifact.

The Profile is governed primarily in **GOVERN** and used across every mode:

- **GOVERN:** defines endpoint scope, target posture, applicability rules, risk tolerance, exceptions, and user attestations.
- **IDENTIFY:** inventories applicable local assets, identities, software, services, and dependencies.
- **PROTECT:** evaluates protections against the Profile's target posture.
- **DETECT:** monitors for evidence changes and drift relevant to the Profile.
- **RESPOND:** opens and guides review of findings that differ from the Profile.
- **RECOVER:** evaluates whether the endpoint can safely return to its intended state.

Each Profile-backed outcome shall declare one of these applicability/evidence states: applicable with local evidence, applicable with partial evidence, user-attested, not applicable with rationale, planned mapping, or out of scope. A missing product mapping is never evidence that an outcome is satisfied.

### Assessment method and Profile state

The product shall keep **how an outcome is assessed** separate from **the outcome's current Profile state**. This mirrors the distinction between NIST SP 800-53A assessment methods and CSF Organizational Profile assessment.

Assessment method is product metadata that explains how the learner should gather support for an outcome:

- **Evidence:** automated examination or testing of Windows-local state.
- **Attestation:** an owner, administrator, or other knowledgeable person confirms information the PC cannot observe.
- **Review:** the learner examines supporting records and records a documented judgment or decision.
- **Hybrid:** local evidence is considered together with an owner or administrator confirmation.

Assessment method is not itself a CSF implementation result. Every subcategory assessment uses the same Current Profile response state:

- **Fully implemented** (Yes)
- **Partly implemented**
- **Not implemented** (No)
- **Not applicable**, with rationale

Tile 4 shall first explain the outcome for a novice CSF learner. The learner then researches the outcome and records the Profile response state. Review and hybrid assessments require a short supporting-evidence or decision note; evidence and attestation assessments may also retain a note when helpful. A radio response is not a substitute for evidence.

### Generated subcategory foundation

The shipped SQLite Profile foundation shall contain one language-tagged product record for each active official CSF 2.0 Subcategory. It shall contain the product-authored plain-English explanation, assessment method, learner research guidance, and whether a supporting note is required. The current foundation covers all 106 active Subcategories in `en-US`.

Official outcome statements and implementation examples remain read-only content from the vendored NIST catalog. The product may display them with clear source attribution, but shall keep them separate from product-authored guidance. SP 800-53 references and executable Windows-evidence mappings are separate, source-verified mappings; an absent mapping must display as unavailable rather than inferred.

### Initial profile mapping: PR.AA Identity Management, Authentication, and Access Control

`PR.AA` is an endpoint-focused interpretation, not enterprise identity governance. Its core question is whether this PC has a clear, controlled, and reviewable access model for the person using it, built-in accounts, services, remote access paths, and privileged actions.

The initial profile shall support these interpretations:

- `PR.AA-01`: inventory accounts, credentials, service identities, and device identities.
- `PR.AA-02`: confirm each account has a known person or intended function; this is primarily user-attested.
- `PR.AA-03`: evaluate strong sign-in and authentication for users, services, remote access, and hardware where applicable.
- `PR.AA-04`: ordinarily not applicable unless federation, SSO, Entra ID, domain sign-in, or external identity assertions are detected.
- `PR.AA-05`: review and limit permissions, especially administrative memberships, services, scheduled tasks, shares, and remote access.
- `PR.AA-06`: assess physical-access posture partly through BitLocker, screen lock, inactivity timeout, and user attestation.

Reviewed local evidence may include local users and administrative membership; account/password policy; Windows Hello availability; auto-logon and UAC posture; RDP, WinRM, and Remote Assistance state; service and scheduled-task identities; local shares; credential-exposure metadata without secret values; and recent logon or administrative events where auditing supports them. Identity proofing, no-shared-credential assurance, cloud MFA, SSO/federation, physical security, and separation of duties must be shown as partial, user-attested, or not applicable when a standalone PC cannot establish them automatically.

NIST SP 800-53 informative references may provide a deeper control vocabulary where available. For `PR.AA`, likely reference families include Access Control (`AC`), Identification and Authentication (`IA`), and Physical and Environmental Protection (`PE`). Such references inform the explanation; they do not turn the application into a claim of SP 800-53 compliance.

## 5. CSF Explorer User Experience

The interface shall use a fixed-height workspace at the 1024x1280 display baseline. The browser page does not scroll at that baseline; long content scrolls inside its assigned list or detail region.

The Explorer is vertically stacked:

```text
Function/mode
  -> internally scrolling Category table
  -> internally scrolling Subcategory table
  -> outcome workspace with explanation, evidence, and actions
```

Selecting a mode filters the Category table. Selecting a Category opens the Subcategory table below it. Selecting a Subcategory opens the outcome workspace below both lists. Selection updates in place while preserving a direct URL and normal browser Back/Forward behavior.

Each outcome workspace shall show:

1. CSF identifier and official title.
2. Official NIST implementation example(s), shown as plain text for one example and a bulleted list when several are provided.
3. Available local evidence, or an explicit no-evidence state.
4. Relevant actions, or an explicit evidence-only, planned, or out-of-scope state.
5. A plain-English explanation of why each available action supports the selected outcome.

## 6. NIST Content and Local Extensions

The official catalog is read-only, versioned NIST CSF 2.0 content. Official identifiers and titles are not editable.

The product shall allow multiple local categories under any selected mode and multiple local subcategories/outcomes under each local category. Each local extension must record:

- parent mode;
- local identifier in a separate namespace, for example `LOCAL.DE.01` and `LOCAL.DE.01.01`;
- title;
- plain-English objective;
- optional advisory evidence description; and
- optional advisory recommended-action description.

Local extensions are teaching and documentation content only. They must not create or attach executable scripts, shell commands, task invocations, executable links, evidence queries, forms, or action buttons. Only centrally implemented and reviewed product mappings may expose actual evidence retrieval or an executable action.

## 7. Evidence, Attention, and Actions

Evidence and actions are mapped centrally, not authored dynamically. Each mapping must declare its CSF identifier, implementation status, evidence source, action safety boundary, and plain-English explanation.

The first production mapping shall be:

```text
DE.CM — Continuous Monitoring
```

It shall present relevant monitoring-task history, including last run, next run, outcome, and freshness, and may present reviewed **Run now** actions for applicable local monitoring tasks.

Attention hints guide the analyst without treating every condition as a security incident:

- **Red:** credible security event or response-required finding.
- **Amber:** review needed, such as stale evidence, a failed task, a control gap, or unclassified posture drift.
- **Blue/gray:** no current evidence or no product mapping.
- **Green:** current evidence supports the outcome.

Every hint shall state what needs review, why it matters, and the relevant outcome or action. A generic alert count is not a substitute for a direct link to the relevant Category/Subcategory.

## 8. Safety and Auditability Requirements

- Preserve SQLite as the operational system of record.
- Preserve immutable report, finding, and alert identifiers.
- Preserve exact-match and guardrail restrictions for posture-drift acceptance.
- Keep explicit export behavior; do not restore operational JSON/Markdown dependencies.
- Require existing elevation, confirmation, durable reason, and audit evidence for protected operations such as a trusted baseline refresh.
- Make action state visible before a user initiates an operation.
- Keep custom extensions non-executable and visually distinct from official NIST content.
- Do not represent a missing mapping as evidence that a CSF outcome is satisfied.

## 9. Delivery Slices

1. **Catalog foundation:** add the versioned read-only CSF 2.0 catalog and tests for official hierarchy integrity.
2. **Explorer shell:** implement the stacked mode, Category, and Subcategory selection experience with direct URL state and no-evidence/action states.
3. **Profile foundation:** define the SQLite-backed Single-PC CSF Profile, applicability states, target posture, exceptions, attestations, and traceable evidence-mapping contract.
4. **Continuous-monitoring vertical slice:** map `DE.CM` to task history and reviewed collection actions.
5. **Local extensions:** add SQLite-backed advisory-only local categories and local outcomes, including validation and clear `LOCAL.*` labeling.
6. **Outcome mappings:** incrementally map supported IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER, and GOVERN evidence/actions; begin `PR.AA` only after its Profile fields and evidence boundaries are reviewed.
7. **Validation and release preparation:** add unit, route, fixture, UI, safety, and clean-install regression coverage; update user, operations, and handoff documentation before any deployment decision.

## 10. Acceptance Criteria

The work is accepted when:

- The official NIST catalog is complete for the selected CSF 2.0 version and remains read-only.
- The Explorer supports the stacked navigation flow at the supported display baseline without outer-page scrolling.
- Every selected outcome clearly shows its tag, official title, plain-English meaning, evidence state, and action state.
- Every implemented outcome mapping identifies its Single-PC Profile applicability state and clearly distinguishes automated local evidence from user-attested, partial, and not-applicable evidence.
- Product wording does not claim that NIST requires a particular Windows-local evidence artifact or that the product proves CSF or SP 800-53 compliance.
- `DE.CM` displays real local monitoring-task evidence and only reviewed task actions.
- Multiple local categories and local outcomes can be created under a chosen mode, use `LOCAL.*` identifiers, and remain advisory-only.
- No locally authored content can create an executable control, query, command, or script.
- Attention hints are evidence-linked, explainable, and do not conflate posture drift with a confirmed security incident.
- Existing SQLite-first collector, report, finding, alert, export, acceptance, and guardrail behavior remains covered by regression tests.
- Source validation, served-UI verification, and deployment/clean-install evidence are kept distinct; source-only completion is not represented as deployment readiness.

## 11. Governing Sources

- [NIST Cybersecurity Framework (CSF) 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [NIST SP 1301: Creating and Using Organizational Profiles](https://csrc.nist.gov/pubs/sp/1301/final)
- [NIST SP 800-53A Rev. 5: Assessing Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final)
- [PC Care & Security UI Design Document](./PC_Care_UI_Design_Document.md)
- [Plan of Action and Milestones](./POAM.md)

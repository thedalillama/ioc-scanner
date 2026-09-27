# CSF Analyst Design Decisions: Contexts and Control Libraries

**Purpose:** Preserve the product direction agreed during early CSF Analyst design. This is a design reference, not official NIST guidance and not a compliance claim.

## Product intent

CSF Analyst is being developed first as a teaching and posture-audit tool for a single Windows PC. Its long-term design must also support small local environments, cloud workloads, hybrid environments, and organization-wide use.

The app uses the NIST Cybersecurity Framework (CSF) 2.0 to explain cybersecurity outcomes. It uses mapped control libraries, including NIST SP 800-53, to help users explore possible approaches for advancing those outcomes. It must not imply that a mapping, a control, or an app action alone establishes CSF compliance.

## Core teaching model

```text
CSF Subcategory = the outcome to pursue
Control mapping = a relevant candidate approach
Context + Profile + tailoring = the decision about applicability
Action + evidence = the record of progress toward the outcome
```

The product teaches outcomes first. A learner should consider what would make an outcome true in the selected context before considering mapped controls. Mapped controls are candidate supports, not automatic requirements or proof that an outcome is achieved.

## Environment contexts

Contexts change the explanation, suggested action, expected evidence, and authority model. They do not change the official CSF catalog or the official mapping source.

### Single PC

One individually managed Windows PC. Evidence is primarily local settings, logs, accounts, installed software, configuration state, and baseline comparisons. The teaching focus is distinguishing what a device can prove from what requires human confirmation.

### Small Local Environment

A small number of devices, users, and local services. Evidence can include endpoint records, local-network settings, account records, backup records, and inventory. The teaching focus is consistent practices across several devices.

### Cloud Workload

An application, data store, service, or tenant hosted primarily by a cloud provider. Evidence can include identity-provider records, cloud audit logs, cloud configuration policies, inventories, and provider documentation. The teaching focus is customer and provider responsibilities.

### Hybrid Environment

Connected local endpoints, networks, and cloud services. Evidence comes from multiple systems and owners. The teaching focus is establishing boundaries, ownership, and complete evidence coverage.

### Organization-Wide Environment

An environment with multiple systems, teams, suppliers, and formal governance. Evidence can include policies, risk records, assessments, architecture records, contracts, inventories, and operational logs. The teaching focus is connecting technical safeguards with governance, risk, privacy, and business decisions.

## Context is not a Profile, Tier, baseline, or tailoring

| Concept | Meaning |
| --- | --- |
| Context | Where and how the outcome is being applied. |
| CSF Profile | The selected/prioritized outcomes and their Current and Target states. |
| CSF Tier | The degree to which cybersecurity risk-management practices are integrated, repeatable, adaptive, and risk-informed. |
| SP 800-53B baseline | A starting set of controls for an information system. |
| Control tailoring | The documented decision to select, modify, inherit, supplement, or mark controls not applicable. |

The app may initially expose the complete CSF catalog for learning. Visibility does not mean that every Subcategory or mapped control applies to the user. Later context, Profile, risk, and tailoring decisions reduce and prioritize what is presented.

## Required context information

Each context should be capable of recording:

1. System boundary
2. Responsible roles
3. Evidence sources
4. Available action authority
5. Data and service importance
6. Dependencies and suppliers
7. Regulatory and contractual constraints
8. Assumptions and unknowns

## Control-library explorer

Users should be able to choose zero, one, or multiple control libraries from a dedicated page. Library selection controls which mappings are shown; it is not itself a decision to adopt or implement the library.

### Selection behavior

| Selection state | Expected behavior |
| --- | --- |
| No libraries selected | Show CSF outcomes, local guidance, and evidence without mapped controls. Explain that libraries can be selected to explore candidate approaches. |
| One library selected | Show mappings from that library. |
| Multiple libraries selected | Show mappings from every selected library, grouped by library and never merged as equivalent controls. |

The user's library selection may be saved as an exploration preference for the selected context and Profile.

### Library metadata

Each library should display its publisher, name, version, release date, intended scope, number of mapped CSF outcomes, mapping source, retrieval date, license/use restrictions, and provenance status.

Provenance must be visible:

- Official NIST mapping
- Publisher-provided mapping
- Community mapping
- Local teaching guidance

### Mapping presentation

For each CSF outcome, mappings must be grouped by library. The app must not imply that controls from different libraries are interchangeable or that a selected library is implemented.

```text
CSF outcome
  NIST SP 800-53 Rev. 5.2.0
    Candidate controls
  Cloud control library
    Candidate controls
  Local teaching guidance
    Context-specific action and evidence suggestions
```

When a selected library has no published mapping for an outcome, say so explicitly. Do not imply the outcome is unimportant or unsupported.

## Teaching-quality requirements for mapping guidance

Each control mapping should distinguish the official relationship from product-authored explanation. Good guidance should state:

1. How the control can support the specific CSF outcome in the selected context
2. A proportionate action that begins with a clear verb
3. The evidence, attestation, review, or hybrid method needed
4. The authority or responsible role needed to act
5. The mapping scope: direct support, partial support, indirect support, or context only
6. What remains unproven or outside the selected context

Unreviewed mapping text should be presented as official control context or an unreviewed mapping relationship, not as a recommended action. It should not be labeled as teaching guidance until it has context-appropriate explanation, action, evidence, and confidence information.

For a Single PC, the app should be comfortable saying:

> This outcome requires a conversation, a policy decision, a cloud record, or organization-wide evidence that this PC cannot provide by itself.

## Design implications

- Preserve official source catalogs and mappings as versioned, read-only content.
- Keep locally authored explanations separate from official NIST text.
- Treat library filtering, candidate-control consideration, tailored-control selection, and implemented-control evidence as separate states.
- Maintain clear scope boundaries as the app expands from one PC to cloud, hybrid, and organization-wide contexts.
- Favor worked examples that contrast direct technical, indirect governance, and hybrid evidence-and-judgment mappings.

## Open design questions

- Which control libraries will be included in the first multi-library release?
- How will the app identify and display library version changes and mapping updates?
- What minimum review standard is required before product-authored guidance is labeled as reviewed?
- How should Profile and tailoring decisions be stored, approved, and compared across contexts?
- Which contexts and features are appropriate for each release phase?

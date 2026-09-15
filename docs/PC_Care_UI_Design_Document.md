# PC Care & Security UI Design Document

## Purpose

Redesign the current Windows security app so it feels like a beautiful consumer website, not a technical dashboard, antivirus console, or enterprise security tool.

The app should make security feel like part of a healthy digital lifestyle: calm, clean, useful, reassuring, and visually refined.

The app is still a local Windows NIST CSF posture/control audit module, but those concepts should be presented in a human, intuitive way.

This document is a presentation and interaction specification. It should not be read as a claim that every planned Respond or Recover experience is already complete in code.

---
## CSF Analyst Interaction Model

The management interface has one user-facing role: **CSF Analyst**. It teaches the NIST Cybersecurity Framework through the work itself; it is not a set of personas that change the meaning of findings or the user's authority.

Authority remains separate from the interface role. Protected actions such as authorizing a trusted baseline refresh still require the appropriate elevation, explicit confirmation, reason, and durable evidence.

The top of every route presents the six CSF Functions in a fixed, clickable action map:

```text
Govern -> Identify -> Protect -> Detect -> Respond -> Recover
```

The row teaches the conceptual order but does not lock the analyst into a linear wizard. Each Function is always selectable. In this product, a selected CSF Function is called a **mode**; a concrete operation the analyst initiates is called an **action**. Do not use "action" for the top-row CSF selections.

The top workspace has a persistent masthead with the product title and UI version. Action-map buttons show only the Function name. Hovering or keyboard-focusing a mode previews short guidance below the map:

- its purpose
- the evidence and decisions that belong there

The directional arrows between modes communicate the conceptual relationship; they do not require a rigid sequence. For example, Detect records an observed change or IOC signal. The analyst may then move to Protect for configuration-baseline review, Identify for risk assessment and exception tracking, Govern for authority and policy decisions, or Respond when the evidence suggests a credible security incident.

Notifications are attention mechanisms, not the primary operating model. The interface should lead with CSF evidence, open reviews, and guided decisions rather than a generic alert count.

### CSF Explorer: approved target for the selected-mode workspace

The selected-mode workspace is a vertically stacked, horizontal CSF Explorer. It teaches the Framework through the user's workflow:

```text
Function/mode -> Category -> Subcategory/outcome -> Local evidence -> User action
```

**Implementation status (2026-09-14):** the source and local development preview implement the read-only official catalog shell, direct Category/Subcategory URL selection, and explicit unmapped-outcome state. The first reviewed evidence/action mapping is the `DE.CM` Continuous Monitoring Category, which displays the existing monitoring-task history and reviewed **Run now** controls. SQLite storage for advisory-only local Categories and outcomes is implemented and tested, but its authoring UI is not yet wired. Broader outcome mappings and deployment validation remain future slices; this source status is not a production-deployment claim.

At the top of the explorer is a fixed-height, internally scrolling Category table for the selected Function. A selected Category opens a second fixed-height, internally scrolling Subcategory table below it. Selecting a Subcategory opens the full-width outcome workspace beneath both tables. The page itself remains fixed at the 1024x1280 baseline; each list and the outcome detail area scroll internally as needed.

The outcome workspace shows, in this order:

1. NIST CSF identifier and official title.
2. Official NIST implementation example(s): plain text for one example and a bulleted list when NIST provides several.
3. Available local evidence, including an explicit no-evidence state when no mapping exists.
4. The product actions that genuinely support that outcome.
5. A clear action-state label: active, evidence-only, planned, or out of scope.

Do not turn every CSF Category or Subcategory into an enabled button. The complete NIST CSF 2.0 catalog is a learning and navigation source; the app enables only actions it can perform safely and auditably. An action can support one or more CSF outcomes, but the interface must not imply that a local product action is itself prescribed by NIST.

For example, the Detect outcome `DE.CM — Continuous Monitoring` presents the plain-English purpose, the monitoring-task log (last run, next run, outcome, and freshness), and the applicable **Run now** actions. `DE.AE — Adverse Event Analysis` presents the resulting evidence and classification/review actions. Scheduled collection belongs primarily in Detect; Govern oversees whether the monitoring program is adequate.

#### NIST content and local extensions

NIST CSF 2.0 Functions, Categories, Subcategories, identifiers, and official titles are versioned read-only catalog content. Local custom categories are permitted only as clearly labeled extensions. A local extension must record its parent Function, custom title, plain-English objective, optional local outcomes, and optional descriptive evidence and action guidance. It must use a separate identifier namespace such as `LOCAL.GV.01`; it must never reuse a NIST identifier or appear to be official NIST content.

Local extensions are advisory only. They may describe relevant evidence and recommended human actions, but they must not create scripts, shell commands, executable links, task invocations, evidence queries, forms, or action buttons. Only centrally implemented and reviewed product mappings may expose an evidence query or executable action in the outcome workspace. This keeps locally authored learning content from becoming an unreviewed execution surface.

#### Attention hints

Attention hints guide review without treating every condition as an incident. They appear at the mode, Category, Subcategory, and outcome-workspace levels and link directly to the supporting outcome.

- **Red:** credible security event or response-required finding.
- **Amber:** review needed, such as stale evidence, a failed task, a control gap, or unclassified posture drift.
- **Blue/gray:** no current evidence or no product mapping for the outcome.
- **Green:** current evidence supports the outcome.

Each hint explains the condition in plain English and offers the relevant action when one is available. A single "next recommended review" may appear in the masthead or mode map, but it must link to the specific Category/Subcategory rather than present a generic alert count.

### Fixed-workspace behavior

At a **1024x1280 display baseline**, the app is a fixed-height CSF workspace: the browser document does not scroll. The CSS activates at a 1000x1000 content viewport to allow for normal browser chrome at that display size. The action map, the selected Function, and the current condition remain visible; long findings, evidence, and activity records scroll only inside their assigned work area.

Selecting a CSF Function updates that workspace in place while preserving a direct URL and normal browser Back/Forward behavior. Direct routes remain usable without JavaScript.

The app collects the full live PC snapshot once at startup. Ordinary CSF navigation reuses that snapshot; Detect, Respond, Recover, Reports, and the overview additionally refresh their small SQLite-backed evidence views. A visible **Refresh live PC snapshot** action deliberately performs the slower full Windows inventory when current live machine state is required.

Report, alert, and evidence links open a centered, keyboard-dismissible detail modal. The modal is an inspection surface only: it preserves the direct record URL and does not bypass export, elevation, immutable-ID, or guardrail controls. Below the supported content-viewport threshold, normal page scrolling is permitted so content remains readable.

---
## Design Principle

The product should feel like:

> A beautiful way to understand and care for your PC.

Not:

> A virus scanner dashboard.

Security should be presented as care, maintenance, confidence, and readiness.

Avoid fear. Avoid cyber-war imagery. Avoid generic antivirus tropes.

---

## Emotional Tone

The interface should feel:

- calm
- premium
- human
- trustworthy
- clean
- warm
- reassuring
- lifestyle-oriented
- intuitive
- elegant

The app should make the user feel:

> My PC is being looked after.

Not:

> Something dangerous is happening.

---

## Visual Direction

Use a light, airy website style.

Preferred aesthetic:

- warm white and soft stone backgrounds
- muted sage, blue, cream, sand, and soft amber accents
- elegant typography
- generous whitespace
- soft cards
- subtle shadows
- editorial composition
- lifestyle imagery
- calm illustrations
- simple, friendly motion if used

Avoid:

- dark hacker themes
- black cyber dashboards
- red-heavy warning panels
- glowing threat maps
- terminal aesthetics
- shield/checkmark cliches everywhere
- generic antivirus branding
- dense tables on the main screen
- too many equally weighted cards

---

## Status as Lifestyle Mood

Status should be communicated through mood, color, background, and language.

### Good / Healthy

Visual mood:

- clear morning light
- calm room or landscape
- soft green/blue accents
- relaxed spacing

Language examples:

- Your PC is steady today.
- Everything important is running.
- Your system is in good shape.

### Needs Review

Visual mood:

- warm amber light
- gentle maintenance tone
- calm checklist framing

Language examples:

- A few things need care.
- Two settings are ready for review.
- Your PC is protected, but a few improvements are available.

### Serious / Action Needed

Visual mood:

- stronger contrast
- focused action area
- restrained red/orange only when necessary

Language examples:

- Action is needed.
- A security setting changed unexpectedly.
- Review this before continuing.

Even serious states should feel controlled and clear, not frightening.

---

## Product Language

Use human language first. Technical language should appear only when the persona allows it or the user drills into details.

Prefer:

- Today
- What changed
- What needs care
- Protection
- Recovery readiness
- Evidence saved
- Care plan
- Recent activity

Avoid on the home page:

- IOC
- baseline hash corpus
- SQLite
- task internals
- scheduled task diagnostics
- raw collector output
- threat intelligence jargon

Persona-aware examples:

Home:

> No known warning signs were found in the latest check.

Advanced:

> No threat indicators matched the latest scan results or baseline evidence.

Technician:

> MatchCount 0. No indicators matched the current evidence snapshot or latest baseline hash corpus.

---

## Information Architecture

The app should remain route-based, but each route should feel like a section of one coherent product.

Existing routes to preserve:

- `/`
- `/govern`
- `/identify`
- `/protect`
- `/detect`
- `/detect/evidence-snapshot`
- `/respond`
- `/recover`
- `/reports`
- `/diagnostics`
- `/report`
- `/alert`

The home page should be the lifestyle-oriented overview. It should not expose raw internals.

Diagnostics should remain available for Technician users but should not dominate the product experience.

---

## Home Page Design

The home page should answer four questions:

1. How is my PC today?
2. What changed?
3. What needs care?
4. What should I do next?

Recommended home page sections:

### 1. Hero Status Area

A large beautiful hero section with atmospheric background imagery.

Example headline:

> Your PC is steady today.

Example subtext:

> Everything important is being watched, and your core protections are running.

The hero should include:

- overall posture
- last check time
- selected persona
- primary action button

Example primary actions:

- Run a gentle check
- Review what changed
- Improve readiness
- See what needs care

### 2. Today

A simple summary of the current system condition.

Examples:

- Protection is on
- Windows is up to date
- No known warning signs found
- Recovery baseline available

### 3. What Changed

Summarize recent events in plain language.

Examples:

- Quick scan completed
- Threat feeds updated
- Baseline verified
- Windows update installed
- App installed or removed

### 4. What Needs Care

Show only the top few items requiring attention.

Examples:

- Backup status is unknown
- Secure Boot should be reviewed
- BitLocker is off
- Restore points are limited

### 5. Care Journey / NIST CSF

Show the NIST functions as a care journey, not as compliance boxes.

Possible labels:

- Govern -> Set the plan
- Identify -> Know this PC
- Protect -> Keep it guarded
- Detect -> Watch for changes
- Respond -> Handle issues
- Recover -> Get back to steady

For Advanced User, NIST CSF Native, Analyst, and Technician personas, show CSF labels as secondary text:

- GV - Govern
- ID - Identify
- PR - Protect
- DE - Detect
- RS - Respond
- RC - Recover

### 6. Recovery Readiness

Recovery should feel reassuring, like an insurance or preparedness feature.

Examples:

- Recovery baseline is available
- Restore points are available
- Backup status needs review
- Recovery confidence: 92%

---

## Page-by-Page Direction

### Govern

This page should feel like setting digital household rules.

It should include:

- persona selection
- automation level
- policy preferences
- accepted exceptions
- reporting level
- security posture intent

Plain-language framing:

> Choose how hands-on the app should be and what kind of care plan this PC should follow.

### Identify

This page should present the PC as a known environment.

It should include:

- device identity
- Windows edition/version
- user/admin summary
- software summary
- services/tasks summary
- network exposure summary
- baseline scope
- optional deep inventory

Plain-language framing:

> This is what makes up your PC and what the app is watching.

### Protect

This page should show the Windows protections that are enabled, missing, or need review.

It should include:

- Defender
- Firewall
- Windows Update
- BitLocker
- Secure Boot
- TPM
- Controlled Folder Access
- Smart App Control
- UAC
- account protections

Plain-language framing:

> These are the protections that help keep your PC safe.

### Detect

This page should explain what the app is watching and whether anything suspicious was observed.

It should include:

- latest evidence snapshot
- threat indicator check
- baseline drift
- control drift
- threat feed freshness
- recent findings

Plain-language framing:

> The app watches for changes and known warning signs.

Important wording:

- "Observed during the latest check"
- "No known indicators were found in the information checked"
- Avoid implying the PC is guaranteed clean

### Respond

This page should guide the user through active findings.

It should include:

- what happened
- why it matters
- what to do next
- evidence links
- response status
- action history

Plain-language framing:

> If something needs attention, this is where the app helps you handle it.

### Recover

This page should feel reassuring and practical.

It should include:

- recovery baseline
- restore readiness
- backup readiness
- post-fix validation
- recovery recommendations

Plain-language framing:

> These tools help your PC get back to a steady state if something goes wrong.

### Reports

Reports should feel like clear health records, not raw logs.

It should include:

- posture reports
- evidence summaries
- NIST CSF reports for Advanced / Technician users
- export options

Plain-language framing:

> Clear records of what was checked, what changed, and what still needs care.

### Diagnostics

Diagnostics can remain technical and detailed, but should be hidden from the default Home experience.

It may include:

- raw task health
- report paths
- snapshot IDs
- collector internals
- debug information

---

## Persona Rules

The app supports personas:

- Home User
- Advanced User
- NIST CSF Native
- Analyst
- Technician

### Home User

Design for comfort and clarity.

- plain language
- no raw diagnostics in main navigation
- no jargon on overview
- only the most important actions
- avoid technical tables

### Advanced User

Design for clarity with more detail.

- show reports
- show evidence links
- allow CSF labels
- explain technical concepts when needed

### NIST CSF Native

Design for framework-first review.

- show formal CSF labels
- show reports and evidence links
- keep raw diagnostics tucked away by default
- preserve auditability

### Analyst

Design for evidence interpretation and posture review.

- show reports and evidence links
- show findings, posture summaries, and trends
- show CSF framing where helpful
- avoid defaulting to raw diagnostics
- preserve auditability

### Technician

Design for full access.

- show diagnostics
- show raw evidence
- show snapshot IDs
- show technical details
- preserve auditability

---

## Layout System

Use reusable UI sections/components:

- page shell
- lifestyle hero
- status mood banner
- primary action panel
- care journey cards
- summary cards
- recent activity list
- recommendation cards
- evidence summary panel
- recovery readiness panel
- persona-aware text helper
- technical details expander

Each page should follow this hierarchy:

1. Status
2. Meaning
3. Recommended action
4. Evidence
5. Technical details

Do not lead with technical details unless the persona is Technician.

---

## NIST CSF Presentation

Keep the NIST structure, but make it human.

Home labels:

- Set the plan
- Know this PC
- Keep it guarded
- Watch for changes
- Handle issues
- Get back to steady

Advanced User / NIST CSF Native / Analyst / Technician labels:

- GV - Govern
- ID - Identify
- PR - Protect
- DE - Detect
- RS - Respond
- RC - Recover

The product should still be able to generate NIST CSF-style reports, but the UI does not need to look like a compliance tool. README and product docs should describe Respond as partially implemented and Recover CIA panels as planned until those workflows are fully built.

---

## Functional Constraints

This redesign should not change security engine behavior.

Do not change:

- IOC matching logic
- evidence snapshot logic
- scan logic
- report generation logic except for presentation
- PowerShell collectors
- scheduled tasks
- remediation behavior
- Windows settings

Preserve existing routes and behavior.

This is a UI/UX redesign first.

---

## Implementation Guidance for Codex

Focus on `codex_monitor_ui.py` unless another small static/profile file is needed.

Recommended implementation steps:

1. Create a cleaner shared page shell.
2. Redesign `/` as the lifestyle-oriented Overview page.
3. Add reusable render helpers for hero/status/care cards.
4. Update page titles and ledes to use human language.
5. Make persona-aware wording more visible.
6. Keep technical detail available but progressively disclosed.
7. Keep Diagnostics technical and separate.
8. Preserve all existing routes.
9. Run compile and route-render verification.

---

## Success Criteria

The redesigned UI should:

- feel beautiful and premium
- feel calm rather than scary
- not resemble McAfee, Norton, or a generic antivirus dashboard
- not resemble a SOC/NOC dashboard
- make app functionality more intuitive
- make the user feel their PC is being cared for
- preserve NIST CSF structure without making the UI feel bureaucratic
- support Home User, Advanced User, NIST CSF Native, Analyst, and Technician personas
- remain auditable for advanced use
- keep security details available without forcing them into the default experience

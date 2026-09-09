# PC Care & Security UI Design Document

## Purpose

Redesign the current Windows security app so it feels like a beautiful consumer website, not a technical dashboard, antivirus console, or enterprise security tool.

The app should make security feel like part of a healthy digital lifestyle: calm, clean, useful, reassuring, and visually refined.

The app is still a local Windows NIST CSF posture/control audit module, but those concepts should be presented in a human, intuitive way.

This document is a presentation and interaction specification. It should not be read as a claim that every planned Respond or Recover experience is already complete in code.

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


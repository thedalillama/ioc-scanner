# CSF Information-Flow and Capability Maps Reference

## Purpose and status

This document records the product-authored work that connects NIST CSF 2.0 Subcategory outcomes into two complementary maps:

1. an **information-flow map** of records, findings, decisions, and other information that one outcome can make available to another; and
2. a **capability map** of capabilities that must exist, substantially exist, or support another outcome.

This is a CSF Analyst product-design reference. It is not an official NIST dependency map, a required implementation sequence, or a compliance interpretation. The official CSF catalog remains unchanged in `profiles/nist-csf-2.0-catalog.json`.

At the time of writing, all 106 CSF 2.0 Subcategories appear in at least one map. The development SQLite database contains 42 information items, 64 information sources, 124 information uses, and 27 capability-dependency edges. Ninety-three Subcategories appear in the information-flow map and 31 appear in the capability map; many appear in both.

## Why two maps exist

The CSF Core defines outcomes. It does not prescribe one mandatory order for implementing them. A relationship can still be useful for planning, but it must say what kind of relationship it is.

| Map | Question answered | Edge meaning |
| --- | --- | --- |
| Information flow | “What does this outcome make available, and who uses it?” | A concrete record, finding, decision, requirement, alert, or similar information is produced and later used. |
| Capability | “What needs to exist before this outcome can be truthfully claimed as achieved?” | A prerequisite, partial prerequisite, or supporting capability affects the dependent outcome. No record is assumed to move between the two. |

For example, `GV.OC-02` produces stakeholder cybersecurity and privacy needs. `GV.SC-05` uses those needs when forming supplier and purchasing requirements. That is an information flow.

By contrast, `PR.AA-03` authentication is a hard capability prerequisite for `PR.AA-05` access permissions. Authentication is not a record handed from one outcome to the other.

## Product rules used to synthesize the maps

The maps were produced through a deliberate reading pass over the official CSF outcome statements and examples, then reviewed against the product’s single-PC teaching context. The following rules governed the work:

1. **Do not invent an official NIST sequence.** Each edge is labeled `product-authored-v1` in SQLite. The app must not present it as a NIST-mandated order.
2. **Require a specific handoff for an information-flow edge.** A source must plausibly produce a named item such as a mission statement, supplier risk record, alert, role assignment, requirement, assessment result, or recovery status.
3. **Describe the downstream use narrowly.** The `use_reason` states why the recipient needs that item; it does not claim the source outcome alone satisfies the recipient.
4. **Keep flows separate from capability dependencies.** A shared topic, such as “risk,” is not enough. Information edges describe a usable record. Capability edges describe an enabling condition.
5. **Use capability strengths conservatively.**
   - `hard_gate`: a fully implemented claim for the dependent outcome is not credible without the prerequisite.
   - `partial_gate`: the prerequisite limits the claim in contexts where it applies, but both outcomes may mature together.
   - `supporting_capability`: useful for planning and assessment context, but not a completion blocker.
6. **Do not force every outcome into both maps.** Some outcomes are naturally information producers/consumers; others are primarily capabilities. The completion criterion was representation in either map, not artificial symmetry.
7. **Keep the maps independent of control libraries.** A control may later produce, consume, or enable information in the map, but importing or changing a control mapping must not rewrite the CSF-to-CSF relationships.
8. **Keep a single-PC context in view without making it a constraint on the CSF.** A record may be created by the PC owner, a responsible person, or an equivalent existing record. The graph does not require a specific organization structure or tool.

## Data model and implementation

The source catalogs are deliberately readable Python data files:

- `csf_information_flows.py`
  - `INFORMATION_ITEMS`: stable ID, title, and plain-language definition of a reusable information item.
  - `INFORMATION_SOURCES`: the outcome or external source that can provide that item and the source guidance.
  - `INFORMATION_USES`: the outcome that uses the item, the dependency type, and a narrowly stated use reason.
- `csf_capability_dependencies.py`
  - `CAPABILITY_DEPENDENCIES`: prerequisite outcome, dependent outcome, strength, and rationale.
- `csf_catalog.py`
  - `SUBCATEGORY_SHORT_DESCRIPTIONS`: product-authored short labels, such as `GV.OC-01: Mission statement`, used consistently in the graph UI.

SQLite stores a seeded copy of those catalogs. Schema migration 19 added the information-flow tables; migration 20 added capability dependencies.

| SQLite table | Purpose |
| --- | --- |
| `csf_information_items` | Canonical information item definition. |
| `csf_subcategory_information_sources` | Outcome or external source that can provide an item. |
| `csf_subcategory_information_uses` | Outcome that uses an item and why. |
| `csf_subcategory_capability_dependencies` | Prerequisite/dependent capability relationship and strength. |

`codex_monitor_store.py` upserts the product-authored catalogs every time the development database is initialized. The source catalogs remain the authoritative editable form; SQLite is the runtime copy.

### Exact source boundaries

| Source | Authority | Allowed use |
| --- | --- | --- |
| `profiles/nist-csf-2.0-catalog.json` | Official NIST CSF catalog, vendored unchanged | Outcome statements and implementation examples only. Do not edit it to express a product relationship. |
| `csf_catalog.py` | Product adapter around the official catalog | Shared short descriptions only; these labels must not rewrite the official outcome. |
| `csf_information_flows.py` | Product-authored source catalog | The complete, editable information-flow map. |
| `csf_capability_dependencies.py` | Product-authored source catalog | The complete, editable capability map. |
| SQLite `state/codex-monitor.db` | Runtime/development copy | Rebuilt from source; never make a database-only map change. |
| NIST workbook and SP 800-53 catalog under `reference-data/NIST/` | Official reference inputs | Control import and provenance; they do not determine CSF-to-CSF edge direction. |

The full edge inventory is intentionally maintained as executable source in the two Python catalog files, rather than duplicated as a fragile prose table here. A scratch implementation can reproduce the exact map by copying those files, importing them in `codex_monitor_store.py`, and running the initialization commands below.

Key behavior to preserve:

- Information source and use tables use composite primary keys, so a relationship is idempotent.
- The information source may be an `External:` source label; all other source and consumer IDs must be official CSF Subcategory IDs.
- The capability table uses the prerequisite/dependent pair as its primary key. Each row has an explicit rationale and a `product-authored-v1` source label.
- Migrations 19 and 20 in `init_db()` must be retained for existing databases.
- Seeding uses `INSERT ... ON CONFLICT ... DO UPDATE`, so edits to source definitions, rationale, or use text replace the corresponding runtime row at initialization.

### Repeatable rebuild procedure

Starting with a fresh checkout and development database:

```powershell
Set-Location C:\CodexTestWork
py -3.12 -m py_compile csf_information_flows.py csf_capability_dependencies.py codex_monitor_store.py
py -3.12 .\codex_monitor_store.py --db .\state\codex-monitor.db stats
py -3.12 -m unittest tests.test_csf_catalog tests.test_ioc_store
powershell -ExecutionPolicy Bypass -File .\start-codex-monitor-ui.ps1 -OpenBrowser
```

`stats` opens/initializes the database, applies schema migrations, and seeds the product-authored catalog data. If the database was created before this work, the same command upgrades it in place.

After any map update, use this query to confirm every catalog Subcategory is represented in at least one map:

```powershell
py -3.12 -c "import sqlite3; from csf_catalog import load_official_catalog; db=sqlite3.connect('state/codex-monitor.db'); c=load_official_catalog(); ids=[s['id'] for f in c['functions'] for cat in f['categories'] for s in cat['subcategories']]; flow={x[0] for x in db.execute('select source_subcategory_id from csf_subcategory_information_sources where source_subcategory_id not like ? union select consumer_subcategory_id from csf_subcategory_information_uses', ('External:%',))}; caps={x[0] for x in db.execute('select prerequisite_subcategory_id from csf_subcategory_capability_dependencies union select dependent_subcategory_id from csf_subcategory_capability_dependencies')}; print([i for i in ids if i not in flow and i not in caps])"
```

Expected result for the current catalog: `[]`.

## Information-flow vocabulary

The current dependency kinds are:

| Kind | Meaning |
| --- | --- |
| `required_input` | The receiving outcome normally needs the information to be performed coherently. |
| `planning_input` | The receiving outcome uses the information to select, prioritize, plan, or improve work. |
| `event_input` | The receiving outcome uses the information during detection, analysis, response, recovery, or another event-driven process. |

Examples of synthesized flows include:

- `GV.OC-01` mission and objectives inform risk objectives, asset criticality, risk analysis, and recovery priorities.
- `GV.OC-02` stakeholder cybersecurity and privacy needs inform supplier and purchasing requirements in `GV.SC-05`.
- `GV.OC-03` turns external legal, regulatory, and contractual sources into requirements used by policy, supplier, incident, and recovery outcomes.
- `GV.OV-03` turns risk-management measures and performance results into review findings used by organization-wide oversight, strategy adjustment, and policy updates.
- `GV.SC-03` uses supply-chain program direction from `GV.SC-01` and supplier lifecycle results from `GV.SC-07`; it produces integrated supply-chain risk records for `GV.RM-03`.
- `ID.RA-07` uses the risk assessment method and produces documented change and exception risk records for `ID.RA-06` risk response.
- `PR.PS-06` produces secure-development performance results that `ID.IM-01` can evaluate for improvements.
- `DE.AE-06` produces authorized adverse-event alerts, tickets, and tool inputs used for incident declaration and incident-report triage.

External sources are included only when the information begins outside a CSF Subcategory, for example legal/regulatory/contractual sources, operational measurement and evidence records, and vulnerability disclosure sources.

### Edge-review checklist

Before adding an information-flow edge, answer all of these questions:

1. What named information item is created, maintained, received, or made available?
2. Which exact official outcome and example support treating that item as an output or input?
3. Which exact downstream outcome uses that item, and for what decision, planning, or event activity?
4. Can the relationship be stated without claiming the source outcome completes the downstream outcome?
5. Is the item actually information? If it is a technology, condition, authority, or practice instead, it belongs in the capability map or may have no edge.
6. If the source is not a CSF outcome, should it be recorded as an `External:` source instead of inventing an upstream CSF node?

Reject an edge when the only rationale is that two outcomes share a keyword, are in the same category, or are both useful cybersecurity practices.

## Capability-map examples

Examples illustrate the intended level of caution:

- `PR.AA-01` identity and credential management → `PR.AA-05` access permissions is a `hard_gate`.
- `PR.AA-03` authentication → `PR.AA-05` access permissions is a `hard_gate`.
- `GV.RM-03` enterprise risk integration → `GV.SC-03` supply-chain risk integration is a `partial_gate`: the two can mature together, but meaningful enterprise integration needs an integration process.
- `PR.AA-05` access permissions → `PR.DS-10` data in use is a `supporting_capability`: access control helps protect in-use data from other users or processes, but in-use protection includes other safeguards.
- `PR.IR-02` environmental protection → `PR.IR-03` resilience mechanisms is a `supporting_capability`, not a hard gate.

Future assessment UX may use `hard_gate` and `partial_gate` to explain why “Fully implemented” is not currently supportable. It must not block the user from planning actions, recording evidence, or selecting a lower assessment level.

### Capability-edge review checklist

Before adding a capability edge, answer these questions:

1. Does the dependent outcome require the prerequisite capability for a fully implemented claim to be credible?
2. Is the relationship unconditional (`hard_gate`), context-sensitive (`partial_gate`), or useful but non-blocking (`supporting_capability`)?
3. Could the dependent outcome be met through a different mechanism? If yes, do not use a hard gate.
4. Is this truly a capability relationship, rather than a record or decision handoff? If it is a handoff, use the information-flow map instead.
5. Can the rationale name the limitation in one direct sentence?

## UI and visualization work

Tile 3 displays a short “Why this matters” statement based on the selected outcome’s downstream flow. The **Information flow** button opens a small one-hop graph showing the selected outcome, its incoming information, and its outgoing information. The popup uses shared short descriptions rather than repeating only CSF IDs.

When an outcome has only inputs or only outputs, the popup shows the applicable side. When it has both, it shows both under the same **Information flow** label.

Supporting artifacts are in `visualizations/`:

- `full-information-flow-catalog.html` and `full-information-flow-catalog-view.html`: complete catalog views.
- `full-information-flow-catalog.mmd`: Mermaid source.
- `subcategory-information-flow.html`: focused flow example.
- `information-flow-modal-demo.html`: modal design prototype.
- `build-information-flow-catalog.mjs`: generator for the catalog visualization.

### UI integration details

The map data is read from SQLite rather than embedded in browser JavaScript:

1. `get_sqlite_csf_information_flow()` in `codex_monitor_ui.py` retrieves a selected outcome's one-hop inputs and outputs.
2. The selected-outcome snapshot includes that object as `csf_information_flow`.
3. Tile 3 renders the `Why this matters` summary and an **Information flow** button only when the selected outcome has a flow.
4. The button opens the `csf-information-flow-template` modal. It can display upstream, downstream, or both sections using `data-information-flow-direction`.
5. The graph uses `SUBCATEGORY_SHORT_DESCRIPTIONS` for readable labels and shows source guidance plus the use reason alongside each arrow.

Capability dependencies are stored and tested but are deliberately not yet rendered or used to gate assessment buttons. A future assessment UX may use hard or partial gates to explain an assessment limitation; it must not quietly turn a `supporting_capability` into a blocker.

## Verification performed

The implementation was verified with:

```powershell
py -3.12 -m py_compile csf_information_flows.py csf_capability_dependencies.py codex_monitor_store.py
py -3.12 -m unittest tests.test_csf_catalog tests.test_ioc_store
py -3.12 .\codex_monitor_store.py --db .\state\codex-monitor.db stats
```

The focused suite passed with 34 tests after the final map updates. A SQLite coverage query confirmed no CSF Subcategory is absent from both maps.

## Relationship to the SP 800-53 work

### Source and import state

The project stores the original NIST sources used by the importer under `reference-data/NIST/`:

- `csf-2.0-informative-references.xlsx`: official CSF 2.0 informative-reference workbook.
- `NIST_SP-800-53_rev5_catalog.json`: SP 800-53 Rev. 5.2.0 catalog used to supply control titles and statements.
- `README.md`: provenance notes.

The importer in `codex_monitor_store.py` created a local control library containing 1,196 catalog controls, 210 mapped controls, and 737 CSF/control mapping records. It treats the workbook references as informative mappings, not implementation directions. It skips the workbook values `CP`, `IR`, and `PT` because they are control-family references rather than a specific catalog control identifier that can be linked reliably.

The SQLite control-layer tables are intentionally separate from the maps:

- `csf_reference_frameworks`
- `csf_reference_controls`
- `csf_subcategory_control_mappings`
- `csf_reviewed_action_control_links`

The mapping table can store product-authored interpretation text, suggested action text, field-specific action examples, a confidence note, source label, and update timestamp. Existing guidance remains exploratory and requires review; it should not be treated as finished teaching guidance.

### What the batch experiments taught us

Several batch prompts and Astra/Terra comparison artifacts were created during exploration. The useful conclusions were:

1. A flat informative mapping does **not** establish whether a control produces the CSF outcome, consumes it, enables it, or is only indirectly relevant.
2. Generated prose became generic or misleading when asked to make every control “satisfy” the outcome.
3. Governance controls often consume information produced by a CSF outcome. For example, `GV.OC-02` stakeholder needs may inform a security and privacy strategy; a strategy does not automatically identify local stakeholders.
4. A person who owns an enterprise strategy may not know the local facts about a PC. Guidance must identify who knows the local use and affected information, then describe a realistic handoff to the person who supplies direction, translates requirements, or approves a decision.
5. The guidance needs to distinguish a true prerequisite from an equivalent existing record or a custom action. A user should be told to obtain missing required information first, but not forced to use one named control to obtain it.
6. Concise, high-school-level text is more useful than dense NIST-style prose. Placeholder examples should guide thought, not become copy-and-paste answers.

### Reproducing the prompt experiments

The project contains prompt-building scripts, but it intentionally does not commit Batch request or response JSONL artifacts. Those files were local research artifacts, not application data. A developer can reproduce the experiment by:

1. Importing the official workbook and SP 800-53 catalog into a development SQLite database.
2. Selecting a small review set from `csf_subcategory_control_mappings`, such as the controls mapped to `GV.OC-02`.
3. Building one request per mapping for a single model. A Batch file cannot mix models.
4. Keeping the request schema and Batch endpoint consistent. Use a matching `/v1/responses` endpoint with Responses-shaped requests, or a matching `/v1/chat/completions` endpoint with chat-completions-shaped requests. The original failed submissions mixed endpoint shapes and models.
5. Supplying the official control statement, official CSF outcome, selected context, assessment method, relevant information-flow inputs/outputs, and the v4 instructions below.
6. Comparing outputs manually before importing anything. Do not overwrite reviewed mapping text with a bulk result.

The Astra/Terra comparison using controls mapped to `GV.OC-02` showed that model quality alone did not solve the relationship-direction problem. The mapping classification in the deferred next step remains necessary before another large run.

### Canonical experimental prompt: v4 role-specific

The latest working experiment is implemented in `create-csf-mapping-guidance-prompt-v2-sample.mjs`. It creates a seven-control, Astra-only `GV.OC-02` batch input but does not upload it. The current prompt is reproduced here so the reasoning is preserved even if scripts later change.

```text
You are writing product-authored guidance for one informative mapping between NIST CSF 2.0 and a control framework.

Context: This guidance applies to one managed Windows PC. The app user is responsible for that PC. People may be affected by how the PC stores, uses, or provides access to information.

Given the provided context, explain how the supplied control can help advance the supplied CSF outcome.

Jobs:
1. Keep the mapping accurate and context-specific.
- Before writing, decide whether the supplied control offers direct support, partial support, indirect support, or no practical support for the CSF outcome in the provided context.
- Let that decision determine the guidance. Keep the exact CSF outcome at the center, include only control topics that directly matter, and do not force an action merely because an official mapping exists.
- Do not imply that the control requires an activity or document unless its official statement says so. State the mapping's limits, and do not claim that the action satisfies the control or the CSF outcome.
- If there is no practical support, say so plainly in confidence_note and leave the action-example fields empty rather than inventing an action.

2. Keep the guidance understandable.
- Write at a high-school reading level using plain, everyday words and short, direct sentences.
- Use concrete descriptions of people, needs, and decisions. Keep each field short and avoid repeating ideas.

3. Make the action practical in the provided context.
- Give the app user one realistic next step. Name another person only when needed, describe that person by their responsibility in the provided context, and state what they contribute.
- When an action needs more than one responsibility, state the handoff clearly: who identifies the need, who translates it into a technical or security requirement, and who uses or approves that requirement. One person may perform more than one responsibility in a small organization.
- Do not assume the person responsible for the supplied control knows local PC facts. Identify who is closest to the PC's use or affected information for those facts. Consult the control, policy, or strategy owner only for the direction, requirement, approval, or specialized knowledge their responsibility reasonably provides.
- When identifying affected people, describe how the asset, service, data, or process in the provided context is used.
- Decide whether the action should identify and record affected people, involve them directly, or both. When it records people or needs, state how the record will be used to support the CSF outcome.
- When Information-flow data is provided, use it. If this outcome produces information used downstream, say what later decision or activity will use the record and include only the details needed to make that use possible. Do not turn the action into work for the downstream outcome.
- If Information-flow data identifies information this action needs, name the prerequisite and explain how the action will use it. Tell the user to confirm or obtain it first when it is missing. Do not assume a particular control produced it: the named CSF outcome, an equivalent existing record, or a custom action may supply it.
- Do not assume job titles, organization structure, formal governance, or tools that the context does not establish.

Examples of responsibility-based wording:
- For a security and privacy strategy, name the person who maintains that strategy.
- For a privacy plan, name the person who handles privacy questions or personal information.
- For buying hardware, software, or services, name the person who approves the purchase.
- For a supplier or service review, name the person who manages or reviews that provider.
- For supplier notices, name the person who receives the notices and decides who needs to know.

4. Avoid generic guidance.
- Make the action, responsible person, and examples fit this specific control, outcome, and context.
- Use the context to choose what evidence, conversation, review, or decision is useful. Do not fall back to vague phrases or generic risk-management language.
- Before responding, check whether the response fulfills all four jobs. Revise it if it does not.
```

The prompt also supplies two worked examples:

- `PM-11` × `GV.OC-01`, where the mission record is produced for downstream risk, asset, impact, and recovery decisions.
- `PM-09` × `GV.OC-02`, where stakeholder needs must be identified locally and can later be compared with security/privacy strategy direction and used for supplier requirements.

The full examples, batch row construction, and information-flow context block remain in the script. Prior batch JSONL request and output files are local research artifacts and are intentionally not part of the committed application source.

### Complete worked-example data supplied with v4

The prompt's two examples demonstrate different directions of support.

**PM-11 x GV.OC-01: information produced for later work**

| Field | Value supplied to the model |
| --- | --- |
| Framework/control | NIST SP 800-53 Rev. 5.2.0, PM-11 - Mission and Business Process Definition |
| Outcome | `GV.OC-01`: The organizational mission is understood and informs cybersecurity risk management. |
| Information flow | Produces organizational mission and objectives for `GV.RM-01`, `ID.AM-05`, `ID.RA-04`, and `RC.RP-04`. |
| Downstream purpose | Set risk objectives, prioritize assets, estimate risk-scenario impact, and set recovery priorities. |
| Acceptable sources | Current mission statement, service strategy, or equivalent record. |

The expected action asks the person who defines or communicates the mission to confirm it, then records and shares it for those later decisions. It does not claim PM-11 alone achieves `GV.OC-01`.

**PM-09 x GV.OC-02: control direction consumes locally gathered needs**

| Field | Value supplied to the model |
| --- | --- |
| Framework/control | NIST SP 800-53 Rev. 5.2.0, PM-09 - Risk Management Strategy |
| Outcome | `GV.OC-02`: Internal and external stakeholders are understood, and their cybersecurity risk-management needs and expectations are understood and considered. |
| Supplemental context | Needs can include data protection, privacy, service availability, incident response, regulatory compliance, and disruption communications. |
| Information flow | Produces stakeholder cybersecurity and privacy needs for `GV.SC-05`. |
| Downstream purpose | Translate known needs into supplier and purchasing requirements. |
| Acceptable sources | A `GV.OC-02` record, an equivalent existing record, or a custom action. |

The expected action first identifies how the PC is used and who relies on its information, then records their needs and compares them with strategy direction. It explicitly identifies PM-09 as indirect because the control requires a security and privacy risk strategy, not a stakeholder list.

### Deferred next step for the control layer

Do not mass-generate additional control guidance yet. First classify each informative mapping relative to the relevant CSF flow/capability relationship:

| Classification | Meaning for product guidance |
| --- | --- |
| Produces | The control’s work can create information or capability the CSF outcome needs. |
| Consumes | The control relies on information produced by the CSF outcome. The guidance should make the prerequisite and handoff clear. |
| Enables | The control makes the outcome easier or safer to carry out but does not produce the outcome’s result. |
| Context only | The official informative mapping is broad or indirect in the selected context; show official context, not an invented action. |

This classification must remain product-authored and reviewable. It is the missing structural step that should precede a new batch prompt or a large guidance run.

## Change control

When changing either map:

1. Update the readable source catalog, not SQLite alone.
2. State why the relationship is an information handoff or a capability dependency.
3. Keep source text and use rationale specific enough for a user to understand the relationship.
4. Do not change official CSF catalog content or the official informative-reference import to make an edge fit.
5. Reinitialize the development database, run the focused tests, and confirm graph coverage.
6. Record significant design changes in this document or the design-decisions reference.

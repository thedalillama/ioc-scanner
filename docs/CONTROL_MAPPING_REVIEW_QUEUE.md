# Control-Mapping Review Queue

Status: working review queue

This queue records AI-assisted draft classifications of already official-mapped control-to-outcome pairs that need a human product decision. It does not contain AI-derived mappings, is not an official NIST interpretation, and is not an approval record.

## Tracking boundary

- `csf_subcategory_control_mappings` contains 737 imported NIST SP 800-53 informative mappings.
- `csf_control_mapping_relationships` contains 8 human-reviewed, product-authored relationship records.
- Batch output files are not yet imported into SQLite as drafts. Their JSONL files are the source artifacts for the test runs; no model classification should be treated as reviewed solely because it appears here.

When an output importer is added, it must stage each valid model result with `review_status = 'draft'`, retain its model, prompt version, batch artifact, and source provenance, and never overwrite a reviewed record.

## Active review queue

Source artifact: `reference-data/NIST/batches/batch_6ab9e5fbdd688190b9473b47e2b7cc64_output.jsonl` (v7 mappings 000–099)

| Queue ID | Control mapping | Sol v7 draft | Review question |
|---|---|---|---|
| CM-001 | CA-07 → DE.AE-02 | `produces_outcome_information`, `partial`, `monitoring_findings` | Does ongoing monitoring and analysis produce information the adverse-event analysis outcome needs, even though CA-07 does not require analysis of associated activities? |
| CM-002 | SC-07 → DE.CM-01 | `enables_outcome_capability`, `partial` | Does monitoring communications at managed interfaces materially support monitoring networks and services *for potentially adverse events*, when the control does not require adverse-event detection? |
| CM-003 | CM-10 → DE.CM-03 | `produces_outcome_information`, `partial`, `monitoring_findings` | Do license-use tracking and peer-to-peer-use documentation produce findings materially useful for monitoring technology usage for potentially adverse events, or are they only license-management context? |
| CM-004 | CM-11 → DE.CM-03 | `enables_outcome_capability`, `partial` | Does monitoring compliance with user software-installation policy materially support adverse-event monitoring, or is it only configuration-management context? |
| CM-005 | AU-12 → DE.CM-09 | `produces_outcome_information`, `partial`, `log_records` | Do generated audit records count as information the broader component-monitoring outcome needs, or should a control also require their monitoring or analysis? |
| CM-006 | CM-06 → DE.CM-09 | `enables_outcome_capability`, `partial` | Does monitoring configuration-setting changes and deviations materially support finding potentially adverse events, or is it only configuration-management context? |
| CM-007 | PL-02 → ID.AM-08 | `produces_outcome_information`, `partial`, `asset_inventory` | Does a system security and privacy plan that describes components and information types create an asset inventory, or is it only planning context? |
| CM-008 | PM-11 → RC.RP-04 | `produces_outcome_information`, `partial`, `organizational_mission` | Mission and business-process definition may inform restoration goals, but is that relationship necessarily `indirect` rather than `partial`? |
| CM-009 | IR-05 → RS.MA-04 | `enables_outcome_capability`, `partial` | Does tracking and documenting incidents materially perform escalation, or is it only a supporting condition and therefore `context_only`? |

## Decisions made

| Queue ID | Decision | Product-authored rationale | Decision date |
|---|---|---|---|
| CM-001 | Accepted: `produces_outcome_information`, `monitoring_findings`, `partial` | CA-07 produces monitoring and assessment information that DE.AE-02 can analyze, but it does not require the outcome's full adverse-event and associated-activity analysis. | 2026-09-28 |
| CM-002 | Accepted: `enables_outcome_capability`, `partial` | SC-07 requires monitoring communications at managed network boundaries, but it does not require adverse-event detection across all networks and network services. | 2026-09-28 |
| CM-003 | Changed: `context_only`, empty information ID, `indirect` | CM-10 tracks licensing and peer-to-peer use for copyright and contract compliance, not for identifying cybersecurity-relevant potentially adverse events. | 2026-09-28 |
| CM-004 | Changed: `context_only`, empty information ID, `indirect` | CM-11 monitors compliance with user software-installation policy, a configuration-management activity rather than monitoring to identify potentially adverse events. | 2026-09-28 |
| CM-005 | Accepted: `produces_outcome_information`, `log_records`, `partial` | AU-12 directly generates audit records that continuous monitoring can use, but it does not itself identify potentially adverse events. | 2026-09-28 |
| CM-006 | Accepted: `enables_outcome_capability`, empty information ID, `partial` | CM-06 establishes secure settings, identifies deviations, and monitors configuration changes, directly covering part of DE.CM-09's configuration-deviation monitoring example. | 2026-09-28 |
| CM-007 | Accepted: `produces_outcome_information`, `asset_inventory`, `partial` | PL-02 requires documented system components and information types, producing partial asset-inventory information. This classification remains limited to the official NIST PL-02 → ID.AM-08 mapping. | 2026-09-28 |
| CM-008 | Changed: `produces_outcome_information`, `organizational_mission`, `indirect` | PM-11 directly produces mission and business-process information, but using it to identify critical functions and establish post-incident operational norms requires product interpretation. | 2026-09-28 |
| CM-009 | Accepted: `enables_outcome_capability`, empty information ID, `partial` | IR-05 requires tracking incidents, directly covering part of the RS.MA-04 example, but does not validate status, decide on escalation, or coordinate escalation. | 2026-09-28 |

## Review decision record

For each queue item, record:

- accepted role, information ID, and scope;
- a one-sentence product-authored rationale grounded in the official source text;
- reviewer and review date; and
- whether the decision adds a reusable prompt example, counterexample, or test assertion.

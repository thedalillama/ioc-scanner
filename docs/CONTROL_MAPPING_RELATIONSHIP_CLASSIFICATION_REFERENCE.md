# Control-Mapping Relationship Classification Reference

Status: working method, version 1

This document records the product-authored method for classifying the relationship between a control in any supported control framework and an outcome in NIST CSF 2.0. It is intentionally framework-neutral. SP 800-53 is the first source framework used to test the method; it does not define the method or give NIST authority to the resulting classifications.

## Purpose and provenance

An official informative-reference mapping says that a control and a CSF outcome are related. It does not, by itself, say whether the control produces information the outcome needs, consumes information from the outcome, enables a capability, or is only broadly related. This method records a careful, product-authored interpretation of that relationship. The official mapping is NIST-sourced and remains unchanged; AI is used only to assist with proposing a classification of that existing mapped pair.

The control statement and the CSF outcome are the evidence for each classification. Product-authored information-flow and capability maps may supply context, but they do not establish a relationship or its direction. Every output is a draft until reviewed.

## COBIT-adjacent design principles

The product uses COBIT-adjacent assurance concepts as a design influence. It does not claim COBIT conformance, reproduce COBIT content, or treat COBIT terminology as an authority over NIST sources.

- Keep outcomes, practices, information items, evidence, actions, and capability or effectiveness conclusions separate.
- Treat information flows and information items as first-class records, rather than as incidental notes attached to a control.
- Assess whether a practice is performed and effective separately from whether its evidence supports an outcome.
- Preserve a risk- and context-based scope: a relationship may be relevant without being complete or equally important in every organization.
- Keep target expectations, current assessment, improvement actions, and the supporting evidence trail distinct and reviewable.

## Relationship roles

Each mapping has exactly one role.

| Role | Meaning |
|---|---|
| `produces_outcome_information` | The official control statement expressly requires work that creates a listed information item materially needed for the CSF outcome. |
| `consumes_outcome_information` | The official control statement expressly requires a listed information item as an input to the control's required work, and the item is materially relevant to the CSF outcome. |
| `enables_outcome_capability` | The control expressly performs a material part of the CSF outcome, but does not create or consume a listed information item. |
| `context_only` | The official mapping is broad, or the control statement lacks evidence of a material relationship to the outcome. |

## Relationship scope

Each mapping also has one scope. Choose scope in this order:

1. `direct` — the statement expressly performs the relevant outcome action or creates or uses the relevant information without a material gap.
2. `partial` — the statement expressly performs a material part of the outcome but omits another material part.
3. `indirect` — a bounded product interpretation is needed to explain a material relationship.

Indirect reasoning cannot supply a missing material verb or object. It is never a substitute for uncertain relevance. A relationship that is merely adjacent, topical, or broadly beneficial is `context_only`, not `indirect`.

## Classification safeguards

- Do not infer direction because both items concern risk, privacy, security, suppliers, policy, or compliance.
- An information-flow candidate is not proof that a control produces or consumes it. Use an `information_id` only when the control statement expressly creates, requires, receives, evaluates, or uses that information.
- An `information_id` must exactly match a supplied candidate. It must be empty for `enables_outcome_capability` and `context_only`.
- A general reference to laws, regulations, policies, standards, guidelines, risk, or privacy is not evidence that a control consumes legal, regulatory, contractual, stakeholder, or other requirements.
- A related policy, plan, program, assessment, monitoring activity, or shared subject is not an enabler unless the control expressly performs a material verb-and-object action required by the outcome.
- For an organization-wide policy outcome, a policy limited to one control family or operational domain is `context_only` unless the control statement expressly requires that policy to be based on the organization's cybersecurity strategy, risk-management context, or priorities. Establishing, communicating, reviewing, or updating a domain policy alone does not establish the organization-wide policy outcome.
- A control may be `partial` when it expressly performs one material part of an outcome while omitting another. For example, a control that expressly requires supplier assessment may partially support supplier due diligence even if it does not specify when the assessment occurs.
- Capability context describes relationships among CSF outcomes; it is not evidence that a specific control enables an outcome.
- The rationale must accurately restate a verb and object from the supplied control statement. It must not import a mechanism or fact from another control.

## Canonical batch prompt

The current implementation of this prompt is in `create-control-mapping-relationship-batch.mjs`. Keep the document and implementation synchronized when either changes.

```text
You classify one product-authored relationship between a control-framework control and a NIST CSF 2.0 Subcategory outcome.

The official informative mapping only says the two are related. It does not establish direction or implementation order. Do not claim NIST requires the classification.

Choose exactly one relationship_role:
- produces_outcome_information: the official control statement expressly requires work that creates a listed information item materially needed for the CSF outcome.
- consumes_outcome_information: the official control statement expressly requires using a listed information item as an input to the control's required work, and that item is materially relevant to the CSF outcome.
- enables_outcome_capability: the control expressly performs a material part of the CSF outcome, but does not create or consume a listed information item.
- context_only: the official mapping is broad or the supplied control statement lacks evidence of a material relationship to this outcome.

Choose relationship_scope:
- direct: the official statement expressly performs the relevant outcome action or creates or uses the relevant information without a material gap.
- partial: the official statement expressly performs a material part of the outcome but omits another material part. Use partial instead of direct whenever there is a material gap.
- indirect: a bounded product interpretation is needed to explain a material relationship, but the interpretation may not supply a missing material verb or object and is not a substitute for uncertain relevance.

Choose scope in this order: direct when there is no material gap; otherwise partial when the control expressly covers a material subset; otherwise indirect only when a bounded interpretation establishes the material relationship.

Rules:
- Use only the official control statement, official CSF outcome/examples, and supplied product-authored flow/capability context. The context does not establish NIST mapping direction.
- Do not infer direction merely because both items concern risk, privacy, suppliers, or security.
- A supplied information-flow candidate is not evidence that this control produces or consumes it. Select an information_id only when the official control statement expressly creates, requires, receives, evaluates, or uses that kind of information. The information_id must exactly match a supplied candidate; otherwise use an empty string.
- Supplied capability context describes relationships among CSF outcomes. It is not evidence that this control enables this outcome; classify the control from its own statement.
- Do not treat a general reference to compliance, laws, regulations, policies, standards, guidelines, risk, or privacy as evidence that the control consumes legal, regulatory, contractual, stakeholder, or other listed requirements.
- Select enables_outcome_capability only when the control expressly performs a material verb-and-object action required by the outcome. A related policy, plan, program, assessment, monitoring activity, or shared topic is not enough. If the control does not perform that action, choose context_only.
- For an organization-wide policy outcome, a policy limited to one control family or operational domain is context_only unless the control statement expressly requires that policy to be based on the organization's cybersecurity strategy, risk-management context, or priorities. Establishing, communicating, reviewing, or updating a domain policy alone does not establish the organization-wide policy outcome.
- Use partial only when the control performs one material part of the outcome but omits another. Use context_only when it covers only an adjacent activity, broad subject area, or supporting condition. For example, a supplier assessment can partially support supplier due diligence only when the control itself expressly requires that assessment, even if it does not state when the assessment occurs.
- information_id must be empty for enables_outcome_capability and context_only.
- If the control does not clearly produce, consume, or enable something relevant, choose context_only with an empty information_id.
- Keep rationale to one plain, factual sentence at a high-school reading level.
- Before returning the JSON, verify that the rationale accurately restates a specific verb and object from the supplied control statement. Do not use facts, mechanisms, or examples from another control. If the rationale says the control does not perform the material part of the outcome, do not classify it as an enabler.
- Do not write an action, compliance claim, or generic explanation.

Return only this JSON object:
{
  "relationship_role": "produces_outcome_information | consumes_outcome_information | enables_outcome_capability | context_only",
  "information_id": "one supplied candidate ID or empty string",
  "relationship_scope": "direct | partial | indirect",
  "rationale": "one plain sentence"
}
```

## Batch process and review standard

1. Supply each request with the official control statement, official CSF outcome and examples, relevant information-flow candidates, and relevant capability context.
2. Submit one model and one endpoint per Batch job. Treat model output as draft data only.
3. Validate that every response completed and conforms to the JSON schema before content review.
4. Review a representative sample against the official control and CSF source text. Reject a batch prompt revision when it creates contradictory rationales, invents control facts, uses a wrong control's mechanism, or turns broad topical overlap into an enabler.
5. Import only validated drafts, retaining model, prompt-version, batch, source, and review provenance. A reviewed relationship must not be overwritten by a later batch.

## Test history

| Test | Result | Learning retained in this version |
|---|---|---|
| Initial 10-item Sol sample | Several broad policy and compliance inferences | Require explicit material relationship. |
| 50-item Sol v4 sample | Clean, conservative sample | Preserve `context_only` fallback and source-based rationale. |
| 100-item Sol v4 sample | Seven incomplete outputs; several false-positive enablers | Increase response budget and add a rationale fidelity check. |
| 100-item Sol v5 sample | All responses complete; capability classifications became too generous | Remove policy-as-enabler shortcut and require verb-and-object overlap. |
| 100-item Sol v6 sample | All 100 responses completed with valid JSON; corrected the v5 false-positive focus cases | Retain explicit scope precedence, capability-context boundary, and stricter producer/consumer definitions. |
| First two v6 production batches | Domain-policy controls were classified inconsistently against organization-wide policy outcomes | Add the explicit organization-wide-versus-domain-policy rule and restart before import. |
| First v7 batch (mappings 000–099) | All 100 responses completed with valid JSON; the revised domain-policy rule produced conservative classifications | Retain the rule; hold the six identified boundary cases for human review. |
| Second v7 batch (mappings 100–199) | All 100 responses completed with valid JSON; 32 domain-policy mappings correctly changed from weak partial enablers to `context_only` | Continue the v7 run; do not import drafts until the full run and review process are complete. |
| Third v7 batch (mappings 200–299) | All 100 responses completed with valid JSON; supply-chain, asset-inventory, and network-flow mappings stayed source-bound and conservative | Continue the v7 run; retain the current prompt unchanged. |
| Remaining v7 batches (mappings 300–728) | All 429 responses completed after a one-item retry; substantive review found three additional boundary cases but no systemic prompt failure | Retain the current prompt; hold the nine total queue items for human product decisions before import. |

## Maintenance

This is a living product reference. Changes require:

- a reason tied to an observed classification error or a newly supported relationship type;
- synchronized changes to the batch generator and this document;
- a new test batch before use on a full framework mapping set; and
- documented review of the changed behavior.

Use `docs/CONTROL_MAPPING_REVIEW_QUEUE.md` to record AI-assisted draft classifications, edge cases, and the human decisions that refine this method.

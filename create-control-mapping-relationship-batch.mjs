#!/usr/bin/env node
/**
 * Create one OpenAI Batch JSONL input file for unreviewed control-to-CSF
 * relationship classifications. This script does not upload, submit, or alter
 * SQLite. One JSONL line is one request; the output is a single Batch input.
 */

import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname);
const defaults = {
  db: resolve(ROOT, "state", "codex-monitor.db"),
  output: resolve(ROOT, "reference-data", "NIST", "batches", "control-mapping-relationship-drafts-astra.jsonl"),
  catalog: resolve(ROOT, "profiles", "nist-csf-2.0-catalog.json"),
  model: "gpt-6-astra",
};

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

const dbPath = resolve(process.cwd(), option("--db", defaults.db));
const outputPath = resolve(process.cwd(), option("--output", defaults.output));
const catalogPath = resolve(process.cwd(), option("--csf-catalog", defaults.catalog));
const model = option("--model", defaults.model);
const limitText = option("--limit", "");
const limit = limitText ? Number.parseInt(limitText, 10) : 0;
const offsetText = option("--offset", "");
const offset = offsetText ? Number.parseInt(offsetText, 10) : 0;
if (limitText && (!Number.isInteger(limit) || limit < 1)) {
  throw new Error("--limit must be a positive integer.");
}
if (offsetText && (!Number.isInteger(offset) || offset < 0)) {
  throw new Error("--offset must be a non-negative integer.");
}
if (offset && !limit) {
  throw new Error("--offset requires --limit.");
}

function collectSubcategories(groups, result) {
  for (const group of groups ?? []) {
    for (const category of group.controls ?? []) {
      for (const subcategory of category.controls ?? []) {
        if (subcategory.class !== "subcategory") continue;
        const statement = subcategory.parts?.find((part) => part.name === "statement")?.prose;
        const examples = (subcategory.parts ?? []).filter((part) => part.name === "example").map((part) => part.prose).filter(Boolean);
        result.set(subcategory.id, { outcome: String(statement ?? "").trim(), examples });
      }
    }
    collectSubcategories(group.groups, result);
  }
}

const subcategories = new Map();
collectSubcategories(JSON.parse(readFileSync(catalogPath, "utf8")).catalog?.groups, subcategories);

const instructions = `You classify one product-authored relationship between a control-framework control and a NIST CSF 2.0 Subcategory outcome.

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
}`;

const responseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["relationship_role", "information_id", "relationship_scope", "rationale"],
  properties: {
    relationship_role: { type: "string", enum: ["produces_outcome_information", "consumes_outcome_information", "enables_outcome_capability", "context_only"] },
    information_id: { type: "string" },
    relationship_scope: { type: "string", enum: ["direct", "partial", "indirect"] },
    rationale: { type: "string" },
  },
};

const db = new DatabaseSync(dbPath, { readOnly: true });
const mappings = db.prepare(`
  SELECT mapping.framework_id, framework.framework_name, framework.version AS framework_version,
         mapping.control_id, control.title AS control_title, control.statement_text,
         mapping.subcategory_id
  FROM csf_subcategory_control_mappings mapping
  JOIN csf_reference_frameworks framework ON framework.framework_id = mapping.framework_id
  JOIN csf_reference_controls control ON control.framework_id = mapping.framework_id AND control.control_id = mapping.control_id
  WHERE NOT EXISTS (
    SELECT 1 FROM csf_control_mapping_relationships relationship
    WHERE relationship.framework_id = mapping.framework_id
      AND relationship.control_id = mapping.control_id
      AND relationship.subcategory_id = mapping.subcategory_id
      AND relationship.review_status = 'reviewed'
  )
  ORDER BY mapping.subcategory_id, mapping.control_id
`).all();

const flowRows = db.prepare(`
  SELECT DISTINCT item.information_id, item.title, item.description
  FROM csf_information_items item
  LEFT JOIN csf_subcategory_information_sources source ON source.information_id = item.information_id
  LEFT JOIN csf_subcategory_information_uses use_item ON use_item.information_id = item.information_id
  WHERE source.source_subcategory_id = ? OR use_item.consumer_subcategory_id = ?
  ORDER BY item.information_id
`);
const capabilityRows = db.prepare(`
  SELECT prerequisite_subcategory_id, dependent_subcategory_id, dependency_strength, rationale
  FROM csf_subcategory_capability_dependencies
  WHERE prerequisite_subcategory_id = ? OR dependent_subcategory_id = ?
  ORDER BY prerequisite_subcategory_id, dependent_subcategory_id
`);

const selectedMappings = limit
  ? (offsetText
    ? mappings.slice(offset, offset + limit)
    : Array.from({ length: Math.min(limit, mappings.length) }, (_, index) => mappings[Math.floor(index * mappings.length / Math.min(limit, mappings.length))]))
  : mappings;
if (!selectedMappings.length) {
  throw new Error(`No unreviewed mappings found at offset ${offset}.`);
}

const lines = selectedMappings.map((mapping) => {
  const subcategory = subcategories.get(mapping.subcategory_id);
  if (!subcategory?.outcome) throw new Error(`Missing official CSF outcome for ${mapping.subcategory_id}.`);
  const flow = flowRows.all(mapping.subcategory_id, mapping.subcategory_id);
  const capabilities = capabilityRows.all(mapping.subcategory_id, mapping.subcategory_id);
  const input = [
    `Framework: ${mapping.framework_name} Rev. ${mapping.framework_version}`,
    `Control: ${mapping.control_id} - ${mapping.control_title}`,
    `Official control statement: ${mapping.statement_text || "Not supplied."}`,
    `CSF Subcategory: ${mapping.subcategory_id}`,
    `Official CSF outcome: ${subcategory.outcome}`,
    `Official CSF examples:\n${subcategory.examples.length ? subcategory.examples.map((item) => `- ${item}`).join("\n") : "- None supplied."}`,
    `Relevant information-flow candidates:\n${flow.length ? flow.map((item) => `- ${item.information_id}: ${item.title}. ${item.description}`).join("\n") : "- None."}`,
    `Relevant capability context:\n${capabilities.length ? capabilities.map((item) => `- ${item.prerequisite_subcategory_id} -> ${item.dependent_subcategory_id} (${item.dependency_strength}): ${item.rationale}`).join("\n") : "- None."}`,
  ].join("\n\n");
  return JSON.stringify({
    custom_id: `${mapping.framework_id}|${mapping.control_id}|${mapping.subcategory_id}|relationship-draft`,
    method: "POST",
    url: "/v1/responses",
    body: {
      model,
      reasoning: { effort: "medium" },
      instructions,
      input,
      max_output_tokens: 800,
      text: { format: { type: "json_schema", name: "control_mapping_relationship", strict: true, schema: responseSchema } },
    },
  });
});
db.close();

if (!limit && lines.length !== 729) {
  throw new Error(`Expected 729 unreviewed mappings; found ${lines.length}. Refusing to write a partial batch.`);
}
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
console.log(JSON.stringify({ output_path: outputPath, request_count: lines.length, model, endpoint: "/v1/responses", batch_offset: offset, representative_sample: Boolean(limit && !offsetText && limit < mappings.length) }, null, 2));

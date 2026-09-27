#!/usr/bin/env node
/**
 * Create a local OpenAI Batch JSONL input file for product-authored guidance
 * for every imported NIST SP 800-53 ↔ NIST CSF 2.0 mapping.
 *
 * This script does not read credentials, upload a file, create a Batch, or
 * modify SQLite. It only produces the reviewable input artifact.
 */

import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname);
const DEFAULT_DB = resolve(ROOT, "state", "codex-monitor.db");
const DEFAULT_CSF_CATALOG = resolve(ROOT, "profiles", "nist-csf-2.0-catalog.json");
const DEFAULT_OUTPUT = resolve(ROOT, "reference-data", "NIST", "batches", "csf-sp800-53-mapping-guidance-v1.jsonl");

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : resolve(process.cwd(), process.argv[index + 1]);
}

const dbPath = option("--db", DEFAULT_DB);
const catalogPath = option("--csf-catalog", DEFAULT_CSF_CATALOG);
const outputPath = option("--output", DEFAULT_OUTPUT);

function collectSubcategories(groups, result) {
  for (const group of groups ?? []) {
    for (const control of group.controls ?? []) {
      for (const subcategory of control.controls ?? []) {
        if (subcategory.class !== "subcategory") continue;
        const parts = subcategory.parts ?? [];
        result.set(subcategory.id, {
          outcome: String(parts.find((part) => part.name === "statement")?.prose ?? "").trim(),
          examples: parts
            .filter((part) => part.name === "example")
            .map((part) => String(part.prose ?? "").trim())
            .filter(Boolean),
        });
      }
    }
    collectSubcategories(group.groups, result);
  }
}

const csfCatalog = JSON.parse(readFileSync(catalogPath, "utf8"));
const subcategories = new Map();
collectSubcategories(csfCatalog.catalog?.groups, subcategories);

const instructions = `You are writing product-authored guidance for one informative mapping between NIST CSF 2.0 and a control framework. Help a small organization understand how a specific control can support one specific CSF outcome.

This is explanatory guidance, not official NIST language, legal advice, or a claim that implementing the control achieves compliance.

Write only about the intersection of the supplied control and CSF outcome.

Requirements:
- Explain the practical connection in plain, concrete language.
- Identify what a person could realistically do for this outcome.
- Preserve the control's intent, but do not repeat or paraphrase its full official statement.
- Do not make up organization facts, systems, regulations, stakeholders, or implementation choices.
- Do not use generic filler such as “apply this requirement to the outcome,” “keep the action focused,” or “this control supports the subcategory.”
- Do not use unresolved catalog placeholders such as “[organization-defined …]”.
- Do not imply that this mapping is mandatory or that one action satisfies either the CSF outcome or the control.
- Keep the writing useful to a practitioner choosing whether to create an action record.

Example inputs:
- Framework: NIST SP 800-53 Rev. 5.2.0
- Control: PM-11 — Mission and Business Process Definition
- CSF subcategory: GV.OC-01
- Official CSF outcome: The organizational mission is understood and informs cybersecurity risk management.

Example output:
{
  "how_it_applies_here": "PM-11 applies here because defining and periodically reviewing the organization's mission and business processes makes the mission clear, shared, and current for the people responsible for cybersecurity decisions.",
  "possible_action": "Document the current mission statement, share it with the person responsible for cybersecurity decisions, and review it when the mission or business activities change.",
  "action_title_example": "Document and share the current mission statement",
  "action_details_example": "Record the current mission statement in a document the responsible person can access, note how it was shared, and set a review point when the mission or business activities change.",
  "action_rationale_example": "Keeping the mission statement current and available helps cybersecurity decisions remain grounded in what the organization is trying to accomplish.",
  "confidence_note": ""
}`;

const responseSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "how_it_applies_here",
    "possible_action",
    "action_title_example",
    "action_details_example",
    "action_rationale_example",
    "confidence_note",
  ],
  properties: {
    how_it_applies_here: { type: "string", description: "Two or three plain-language sentences about the exact mapping." },
    possible_action: { type: "string", description: "One concrete, bounded action." },
    action_title_example: { type: "string", description: "A short action title, not a control title." },
    action_details_example: { type: "string", description: "What is done and what artifact or result exists." },
    action_rationale_example: { type: "string", description: "Why the action advances this CSF outcome." },
    confidence_note: { type: "string", description: "Empty unless the mapping is broad, indirect, or needs organization-specific judgment." },
  },
};

const db = new DatabaseSync(dbPath, { readOnly: true });
const mappings = db.prepare(`
  SELECT mapping.framework_id, framework.framework_name, framework.version AS framework_version,
         mapping.control_id, control.title AS control_title, control.statement_text,
         mapping.subcategory_id
  FROM csf_subcategory_control_mappings AS mapping
  JOIN csf_reference_frameworks AS framework
    ON framework.framework_id = mapping.framework_id
  JOIN csf_reference_controls AS control
    ON control.framework_id = mapping.framework_id AND control.control_id = mapping.control_id
  WHERE mapping.framework_id = 'nist-sp-800-53-r5.2.0'
  ORDER BY mapping.subcategory_id, mapping.control_id
`).all();
db.close();

const lines = mappings.map((mapping) => {
  const subcategory = subcategories.get(mapping.subcategory_id);
  if (!subcategory?.outcome) {
    throw new Error(`Missing official CSF outcome for ${mapping.subcategory_id}.`);
  }
  const input = [
    `Framework: ${mapping.framework_name} Rev. ${mapping.framework_version}`,
    `Control: ${mapping.control_id} — ${mapping.control_title}`,
    `Official control statement: ${mapping.statement_text}`,
    `CSF subcategory: ${mapping.subcategory_id}`,
    `Official CSF outcome: ${subcategory.outcome}`,
    `Official CSF examples, if available:\n${subcategory.examples.length ? subcategory.examples.map((example) => `- ${example}`).join("\n") : "- None supplied."}`,
  ].join("\n\n");
  return JSON.stringify({
    custom_id: `${mapping.framework_id}|${mapping.control_id}|${mapping.subcategory_id}`,
    method: "POST",
    url: "/v1/responses",
    body: {
      model: "gpt-5.6-terra",
      reasoning: { effort: "medium" },
      instructions,
      input,
      max_output_tokens: 1200,
      text: {
        format: {
          type: "json_schema",
          name: "csf_mapping_guidance",
          strict: true,
          schema: responseSchema,
        },
      },
    },
  });
});

if (lines.length !== 737) {
  throw new Error(`Expected 737 mapping requests; found ${lines.length}. Refusing to write a partial batch.`);
}

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
console.log(JSON.stringify({ output_path: outputPath, request_count: lines.length, model: "gpt-5.6-terra" }, null, 2));

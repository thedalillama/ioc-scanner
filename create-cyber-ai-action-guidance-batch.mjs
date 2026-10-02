#!/usr/bin/env node
/**
 * Create a production OpenAI Responses Batch JSONL file for profile-specific
 * Cyber AI Profile Add Action placeholders.  This reads SQLite only; it does
 * not upload, submit, or import generated text.
 *
 * Usage: node create-cyber-ai-action-guidance-batch.mjs [start] [count]
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname);
const start = Number.parseInt(process.argv[2] || "0", 10);
const count = Number.parseInt(process.argv[3] || "100", 10);
if (!Number.isInteger(start) || start < 0 || !Number.isInteger(count) || count < 1) {
  throw new Error("start must be zero or greater and count must be at least one.");
}

const dbPath = resolve(root, "state", "codex-monitor.db");
const rangeEnd = start + count - 1;
const outputPath = resolve(
  root,
  "reference-data",
  "NIST",
  "batches",
  `cyber-ai-action-guidance-sol-${String(start).padStart(3, "0")}-${String(rangeEnd).padStart(3, "0")}.jsonl`,
);
const promptVersion = "cyber-ai-action-guidance-v2-production";
const model = "gpt-6-sol";
const fieldLimits = {
  action_title_example: 72,
  action_details_example: 220,
  action_rationale_example: 220,
};

const instructions = `Context: The product is assessing one single-user PC within an organization. The PC is one endpoint, not the entire organization. Do not assume facts about its users, AI tools, data, services, or environment.

You are writing product-authored, grey-placeholder text for the Add Action form. It is based on the official NIST Cyber AI Profile Focus Area Consideration for one CSF 2.0 outcome and, when supplied, its Sample Opportunity. It is not official NIST language, a requirement, legal advice, or evidence that an action satisfies the outcome.

The supplied Profile Focus identifies the Cyber AI Profile focus for this one request. Use only the supplied Focus Area Consideration and, when present, Sample Opportunity to determine the suggested AI use. Do not borrow assumptions, use cases, or language from a different profile focus. AI use is optional and must fit the actual environment. Do not imply that the PC already uses AI or that the reader must deploy it. When the source describes an AI capability, frame the example as evaluating, using, or reviewing that capability only if it is relevant to the PC.

Turn the supplied source material into one short, locally adaptable action example. Keep the official CSF outcome at the center. When a Sample Opportunity is supplied, preserve its particular use, such as alert analysis, traffic monitoring, policy checking, risk communication, data discovery, reporting, or threat-intelligence sharing. Otherwise use the particular AI use in the Focus Area Consideration. Do not flatten it into generic AI-assisted security wording. Use plain high-school-level English and concrete verbs. Do not mention NIST, the Cyber AI Profile, a focus area, a priority, a control, compliance, or the source material in user-facing text.

Do not invent a particular AI tool, vendor, data set, person, approval, process, record, review cadence, alert, incident, or technical configuration. Do not add keep a note, keep a summary, set a reminder, get approval, or similar work unless the supplied source explicitly calls for it. Do not claim that the suggested action completes the outcome. Do not copy the Sample Opportunity verbatim. The reader must be able to adapt the example to their actual PC.

Write exactly these fields:
- action_title_example: a concise action title, 72 characters or fewer; do not begin with Example:.
- action_details_example: one complete sentence, 220 characters or fewer, explaining what the person could do and what useful result to keep or review.
- action_rationale_example: one complete sentence, 220 characters or fewer, explaining why that action advances this specific CSF outcome.

Before returning, silently verify that every field is specific to the supplied outcome and source material; preserves its particular use; treats AI as an optional capability rather than an assumed deployment; uses plain language; adds no unsupported tool, person, approval, record, or cadence; fits its limit; and is not a compliance claim. Return only the required JSON.`;

const schema = {
  type: "object",
  additionalProperties: false,
  required: Object.keys(fieldLimits),
  properties: Object.fromEntries(
    Object.entries(fieldLimits).map(([name, maxLength]) => [name, { type: "string", maxLength }]),
  ),
};

const db = new DatabaseSync(dbPath, { readOnly: true });
const candidates = db.prepare(`
  SELECT facet.profile_id, definition.profile_name, facet.outcome_id,
         outcome.outcome_description, facet.facet_label, facet.considerations,
         facet.opportunities, facet.informative_references
  FROM csf_community_profile_outcome_facets AS facet
  JOIN csf_profile_definitions AS definition ON definition.profile_id = facet.profile_id
  JOIN csf_profiles AS outcome
    ON outcome.profile_name = definition.profile_name AND outcome.outcome_id = facet.outcome_id
  WHERE definition.profile_name = 'Cyber AI - Defend'
    AND trim(coalesce(facet.considerations, '')) <> ''
  ORDER BY facet.outcome_id
`).all();
db.close();

const selected = candidates.slice(start, start + count);
if (selected.length !== count) {
  throw new Error(`Requested ${count} records from offset ${start}, but only ${selected.length} remain of ${candidates.length} eligible records.`);
}

const lines = selected.map((row) => {
  const input = [
    `Profile: ${row.profile_name}`,
    `Profile UUID: ${row.profile_id}`,
    `Profile Focus: ${row.facet_label}`,
    `CSF subcategory: ${row.outcome_id}`,
    `Official CSF outcome: ${row.outcome_description}`,
    `Focus Area Consideration: ${row.considerations}`,
    `Sample Opportunity: ${row.opportunities || "None supplied; use the Focus Area Consideration only."}`,
    `Example Informative References (context only; do not name them in output): ${row.informative_references || "None supplied."}`,
  ].join("\n\n");
  return JSON.stringify({
    custom_id: `${row.profile_id}|${row.outcome_id}|${promptVersion}`,
    method: "POST",
    url: "/v1/responses",
    body: {
      model,
      reasoning: { effort: "medium" },
      instructions,
      input,
      max_output_tokens: 700,
      text: { format: { type: "json_schema", name: "profile_action_guidance", strict: true, schema } },
    },
  });
});

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${lines.join("\n")}\n`, "utf8");
console.log(JSON.stringify({
  output_path: outputPath,
  request_count: lines.length,
  eligible_outcome_count: candidates.length,
  model,
  endpoint: "/v1/responses",
  prompt_version: promptVersion,
  selected: selected.map((row) => `${row.profile_name}: ${row.outcome_id}`),
}, null, 2));

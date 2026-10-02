#!/usr/bin/env node
/**
 * Create a reviewable OpenAI Responses Batch JSONL pilot for the Cyber AI
 * Defend profile. This script reads SQLite only; it does not upload, submit,
 * or import any generated guidance.
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname);
const dbPath = resolve(root, "state", "codex-monitor.db");
const outputPath = resolve(root, "reference-data", "NIST", "batches", "cyber-ai-defend-action-guidance-sol-test-v2-000-009.jsonl");
const profileId = "d9143efc-8c5e-4bfb-92af-cb0d958163df";
const promptVersion = "cyber-ai-action-guidance-v2-test";
const model = "gpt-6-sol";
const fieldLimits = {
  action_title_example: 72,
  action_details_example: 220,
  action_rationale_example: 220,
};

const instructions = `Context: The product is assessing one single-user PC within an organization. The PC is one endpoint, not the entire organization. Do not assume facts about its users, AI tools, data, services, or environment.

You are writing product-authored, grey-placeholder text for the Add Action form. It is based on one official NIST Cyber AI Profile Sample Opportunity and its Focus Area Consideration for one CSF 2.0 outcome. It is not official NIST language, a requirement, legal advice, or evidence that an action satisfies the outcome.

Defend context: The Cyber AI Profile's Defend Focus Area identifies opportunities to use AI to improve cybersecurity processes and activities, while recognizing challenges when AI assists defensive operations. AI can help people sort alerts, distinguish threats from noise, prioritize work, suggest defensive actions, analyze activity, support response and recovery, and improve reporting or information sharing. AI use is optional and must fit the actual environment. Do not imply that the PC already uses AI or that the reader must deploy it. When the source describes an AI capability, frame the example as evaluating, using, or reviewing that capability only if it is relevant to the PC.

Turn the supplied source material into one short, locally adaptable action example. Keep the official CSF outcome at the center. Preserve the particular defensive use described by the Sample Opportunity, such as alert analysis, traffic monitoring, policy checking, risk communication, data discovery, reporting, or threat-intelligence sharing. Do not flatten it into generic “AI-assisted security” wording. Use plain high-school-level English and concrete verbs. Do not mention NIST, the Cyber AI Profile, a focus area, a priority, a control, compliance, or the source material in user-facing text.

Do not invent a particular AI tool, vendor, data set, person, approval, process, record, review cadence, alert, incident, or technical configuration. Do not add “keep a note,” “keep a summary,” “set a reminder,” “get approval,” or similar work unless the supplied source explicitly calls for it. Do not claim that the suggested action completes the outcome. Do not copy the Sample Opportunity verbatim. The reader must be able to adapt the example to their actual PC.

Write exactly these fields:
- action_title_example: a concise action title, 72 characters or fewer; do not begin with “Example:”.
- action_details_example: one complete sentence, 220 characters or fewer, explaining what the person could do and what useful result to keep or review.
- action_rationale_example: one complete sentence, 220 characters or fewer, explaining why that action advances this specific CSF outcome.

Before returning, silently verify that every field is specific to the supplied outcome and source material; preserves its particular defensive use; treats AI as an optional capability rather than an assumed deployment; uses plain language; adds no unsupported tool, person, approval, record, or cadence; fits its limit; and is not a compliance claim. Return only the required JSON.`;

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
  SELECT facet.outcome_id, outcome.outcome_description, facet.facet_label,
         facet.considerations, facet.opportunities, facet.informative_references
  FROM csf_community_profile_outcome_facets AS facet
  JOIN csf_profile_definitions AS definition ON definition.profile_id = facet.profile_id
  JOIN csf_profiles AS outcome
    ON outcome.profile_name = definition.profile_name AND outcome.outcome_id = facet.outcome_id
  WHERE facet.profile_id = ?
    AND trim(facet.opportunities) <> ''
    AND lower(trim(facet.opportunities)) NOT IN (
      'standard cybersecurity practices apply.',
      'standard cybersecurity practices apply'
    )
  ORDER BY facet.outcome_id
`).all(profileId);
db.close();

if (candidates.length < 10) throw new Error(`Expected at least 10 eligible Defend opportunities; found ${candidates.length}.`);

// Start with one outcome from each CSF Category, then fill remaining pilot
// slots in framework order. This makes the small review sample more varied.
const selected = [];
const selectedIds = new Set();
const categories = new Set();
for (const row of candidates) {
  const category = String(row.outcome_id).split("-")[0];
  if (categories.has(category)) continue;
  categories.add(category);
  selected.push(row);
  selectedIds.add(row.outcome_id);
  if (selected.length === 10) break;
}
for (const row of candidates) {
  if (selected.length === 10) break;
  if (!selectedIds.has(row.outcome_id)) selected.push(row);
}

const lines = selected.map((row) => {
  const input = [
    "Profile: Cyber AI - Defend",
    `Profile UUID: ${profileId}`,
    `CSF subcategory: ${row.outcome_id}`,
    `Official CSF outcome: ${row.outcome_description}`,
    `Focus Area Consideration: ${row.considerations}`,
    `Sample Opportunity: ${row.opportunities}`,
    `Example Informative References (context only; do not name them in output): ${row.informative_references || "None supplied."}`,
  ].join("\n\n");
  return JSON.stringify({
    custom_id: `${profileId}|${row.outcome_id}|${promptVersion}`,
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
  selected_outcomes: selected.map((row) => row.outcome_id),
}, null, 2));

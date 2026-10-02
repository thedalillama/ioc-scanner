#!/usr/bin/env node
/**
 * Create the conservative rerun set for a completed Cyber AI - Defend batch.
 * It selects every request without a substantive Sample Opportunity, plus any
 * request whose returned response had no output text. It reads local JSONL
 * files only and does not submit or import anything.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const root = resolve(import.meta.dirname);
const requestPath = resolve(root, "reference-data", "NIST", "batches", "cyber-ai-action-guidance-sol-000-099.jsonl");
const responsePath = resolve(root, "reference-data", "NIST", "batches", "batch_6abdce20e87c8190b512bc412b1f50bd_output.jsonl");
const outputPath = resolve(root, "reference-data", "NIST", "batches", "cyber-ai-defend-action-guidance-sol-rerun-000-064.jsonl");
const promptVersion = "cyber-ai-action-guidance-v3-conservative-rerun";
const model = "gpt-6-sol";
const fieldLimits = {
  action_title_example: 72,
  action_details_example: 220,
  action_rationale_example: 220,
};

const instructions = `Context: The product is assessing one single-user PC within an organization. The PC is one endpoint, not the entire organization. Do not assume facts about its users, AI tools, data, services, or environment.

You are writing product-authored, grey-placeholder text for the Add Action form. It is based on official NIST Cyber AI Profile material for one CSF 2.0 outcome. It is not official NIST language, a requirement, legal advice, or evidence that an action satisfies the outcome.

Every request supplies a Guidance Basis. Follow it exactly.

If the basis is "Focus Area Consideration and Sample Opportunity", preserve the particular AI use described by the Sample Opportunity. Treat it as optional: frame the example as evaluating, using, or reviewing that capability only if it is relevant to the PC.

If the basis is "Focus Area Consideration only", use only an AI capability explicitly named or clearly described in that Consideration. Do not infer a named AI use from the CSF outcome. If the Consideration is general, write a modest optional evaluation action in plain language rather than inventing a tool, model, agent, data type, alert, incident, configuration, or service.

Keep the official CSF outcome at the center. Use plain high-school-level English and concrete verbs. Do not mention NIST, the Cyber AI Profile, a focus area, a priority, a control, compliance, or the source material in user-facing text.

Do not invent a particular AI tool, vendor, data set, person, approval, process, record, review cadence, alert, incident, technical configuration, AI agent, training data, model, or supplier. Do not add keep a note, keep a summary, set a reminder, get approval, or similar work unless the supplied source explicitly calls for it. Do not claim that the suggested action completes the outcome. Do not copy the source wording verbatim. The reader must be able to adapt the example to their actual PC.

Write exactly these fields:
- action_title_example: a concise action title, 72 characters or fewer; do not begin with Example:.
- action_details_example: one complete sentence, 220 characters or fewer, explaining what the person could do and what useful result to keep or review.
- action_rationale_example: one complete sentence, 220 characters or fewer, explaining why that action advances this specific CSF outcome.

Before returning, silently verify that every field is specific to the supplied outcome and allowed source material; treats AI as optional; introduces no unsupported facts; fits its limit; and is not a compliance claim. Return only the required JSON.`;

const schema = {
  type: "object",
  additionalProperties: false,
  required: Object.keys(fieldLimits),
  properties: Object.fromEntries(
    Object.entries(fieldLimits).map(([name, maxLength]) => [name, { type: "string", maxLength }]),
  ),
};

const parseJsonl = (path) => readFileSync(path, "utf8").trim().split(/\r?\n/).map(JSON.parse);
const requests = parseJsonl(requestPath);
const responses = parseJsonl(responsePath);
if (requests.length !== responses.length) throw new Error("Request and response line counts differ.");

const includedOutcomeIds = new Set(requests.map((request) => request.custom_id.split("|")[1]));
const db = new DatabaseSync(resolve(root, "state", "codex-monitor.db"), { readOnly: true });
const tailRows = db.prepare(`
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
`).all().filter((row) => !includedOutcomeIds.has(row.outcome_id));
db.close();

const tailRequests = tailRows.map((row) => ({
  custom_id: `${row.profile_id}|${row.outcome_id}|cyber-ai-action-guidance-v2-production`,
  body: {
    input: [
      `Profile: ${row.profile_name}`,
      `Profile UUID: ${row.profile_id}`,
      `Profile Focus: ${row.facet_label}`,
      `CSF subcategory: ${row.outcome_id}`,
      `Official CSF outcome: ${row.outcome_description}`,
      `Focus Area Consideration: ${row.considerations}`,
      `Sample Opportunity: ${row.opportunities || "None supplied; use the Focus Area Consideration only."}`,
      `Example Informative References (context only; do not name them in output): ${row.informative_references || "None supplied."}`,
    ].join("\n\n"),
  },
}));

const responseText = (response) => response?.response?.body?.output
  ?.find((item) => item.type === "message")?.content
  ?.find((item) => item.type === "output_text")?.text;

const rerun = [...requests, ...tailRequests].flatMap((request, index) => {
  const originalInput = request.body.input;
  const hasOpportunity = /Sample Opportunity: (?!None supplied;)/.test(originalInput);
  const incomplete = !responseText(responses[index]);
  if (hasOpportunity && !incomplete) return [];
  const sourceInput = originalInput.replace(
    /Sample Opportunity: None supplied; use the Focus Area Consideration only\./,
    "Sample Opportunity: None supplied.",
  );
  const basis = hasOpportunity
    ? "Guidance Basis: Focus Area Consideration and Sample Opportunity"
    : "Guidance Basis: Focus Area Consideration only";
  const input = `${basis}\n\n${sourceInput}`;
  const [profileId, outcomeId] = request.custom_id.split("|");
  return [{
    custom_id: `${profileId}|${outcomeId}|${promptVersion}`,
    method: "POST",
    url: "/v1/responses",
    body: {
      model,
      reasoning: { effort: "medium" },
      instructions,
      input,
      max_output_tokens: 1100,
      text: { format: { type: "json_schema", name: "profile_action_guidance", strict: true, schema } },
    },
  }];
});

writeFileSync(outputPath, `${rerun.map(JSON.stringify).join("\n")}\n`, "utf8");
console.log(JSON.stringify({
  output_path: outputPath,
  request_count: rerun.length,
  consideration_only_count: rerun.filter((item) => item.body.input.startsWith("Guidance Basis: Focus Area Consideration only")).length,
  source_opportunity_retry_count: rerun.filter((item) => item.body.input.startsWith("Guidance Basis: Focus Area Consideration and Sample Opportunity")).length,
  tail_outcome_count: tailRequests.length,
  model,
  endpoint: "/v1/responses",
  prompt_version: promptVersion,
}, null, 2));

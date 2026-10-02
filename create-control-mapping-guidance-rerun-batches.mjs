import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname);
const batchNumber = Number(process.argv[2] ?? "1");
const batchSize = 100;
if (!Number.isInteger(batchNumber) || batchNumber < 1) throw new Error("Batch number must be a positive integer.");

const priorGenerator = readFileSync(resolve(root, "create-control-mapping-guidance-test-batch.mjs"), "utf8");
const prompt = priorGenerator.match(/const prompt = \`([\s\S]*?)\`;/)?.[1];
if (!prompt) throw new Error("Could not load the shared guidance prompt.");

const db = new DatabaseSync(resolve(root, "state/codex-monitor.db"), { readOnly: true });
const catalog = JSON.parse(readFileSync(resolve(root, "profiles/nist-csf-2.0-catalog.json"), "utf8"));
const outcomes = new Map();
function walk(value) {
  if (!value || typeof value !== "object") return;
  if (value.class === "subcategory") outcomes.set(value.id, {
    outcome: value.parts?.find((part) => part.name === "statement")?.prose ?? "",
    examples: (value.parts ?? []).filter((part) => part.name === "example").map((part) => part.prose),
  });
  for (const child of Object.values(value)) walk(child);
}
walk(catalog.catalog);

function parseRecords(path) {
  const source = readFileSync(path, "utf8").trim();
  const records = [];
  let offset = 0;
  while (offset < source.length) {
    while (/\s/.test(source[offset] ?? "")) offset += 1;
    if (offset >= source.length) break;
    let depth = 0, inString = false, escaped = false, end = offset;
    for (; end < source.length; end += 1) {
      const character = source[end];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
      } else if (character === '"') inString = true;
      else if (character === "{") depth += 1;
      else if (character === "}" && --depth === 0) { end += 1; break; }
    }
    records.push(JSON.parse(source.slice(offset, end)));
    offset = end;
  }
  return records;
}

const framework = "nist-sp-800-53-r5.2.0";
const relationship = db.prepare("SELECT relationship_role, relationship_scope FROM csf_control_mapping_relationships WHERE framework_id=? AND control_id=? AND subcategory_id=?");
const sourceArtifacts = [
  "batch_6abb1ec0b3888190bd068d078c62db70_output.jsonl",
  "batch_6abb1ecc69a48190badf9a45d8ee7007_output.jsonl",
  "batch_6abb1ed8d85c8190a76b3bbcd5692e24_output.jsonl",
  "batch_6abb1eee7ac88190a403cd7dddcfcaa8_output.jsonl",
  "batch_6abb1efad4508190925a1fca19ba8634_output.jsonl",
];
const rerunKeys = new Set(["CM-01|GV.OV-01", "AC-02|PR.DS-10"]);
for (const artifact of sourceArtifacts) {
  for (const record of parseRecords(resolve(root, "reference-data/NIST/batches", artifact))) {
    const [recordFramework, controlId, subcategoryId] = record.custom_id.split("|");
    const outputText = record.response?.body?.output?.find((item) => item.type === "message")?.content?.find((item) => item.type === "output_text")?.text;
    let guidance;
    try { guidance = outputText ? JSON.parse(outputText) : null; } catch { continue; }
    const mapping = relationship.get(recordFramework, controlId, subcategoryId);
    const note = (guidance?.review_note ?? "").toLowerCase();
    const missingIndirect = mapping?.relationship_scope === "indirect" && !(/product interpretation/.test(note) || /indirect/.test(note));
    const missingContext = mapping?.relationship_role === "context_only" && !(/not required|does not by itself|doesn't by itself|not a requirement/.test(note));
    const missingPartial = mapping?.relationship_scope === "partial" && !(/does not|but |gap|partial|only in part/.test(note));
    if (missingIndirect || missingContext || missingPartial) rerunKeys.add(`${controlId}|${subcategoryId}`);
  }
}

const allMappings = db.prepare("SELECT control_id, subcategory_id FROM csf_control_mapping_relationships WHERE framework_id=? ORDER BY subcategory_id, control_id").all(framework);
const selectedAll = allMappings.filter(({ control_id, subcategory_id }) => rerunKeys.has(`${control_id}|${subcategory_id}`));
const rangeStart = (batchNumber - 1) * batchSize;
const selected = selectedAll.slice(rangeStart, rangeStart + batchSize);
if (!selected.length) throw new Error(`No rerun mappings remain at offset ${rangeStart}.`);
const rangeEnd = rangeStart + selected.length - 1;
const rangeLabel = `${String(rangeStart).padStart(3, "0")}-${String(rangeEnd).padStart(3, "0")}`;
const output = resolve(root, `reference-data/NIST/batches/control-mapping-guidance-sol-rerun-v2-${rangeLabel}.jsonl`);
const fieldLimits = { how_it_applies_here: 240, possible_action: 240, review_note: 240, action_title_example: 72, action_details_example: 220, action_rationale_example: 220 };
const schema = { type: "object", additionalProperties: false, required: Object.keys(fieldLimits), properties: Object.fromEntries(Object.entries(fieldLimits).map(([key, maxLength]) => [key, { type: "string", maxLength }])) };
const statement = db.prepare("SELECT c.title,c.statement_text,r.relationship_role,r.information_id,r.relationship_scope,r.rationale FROM csf_reference_controls c JOIN csf_control_mapping_relationships r ON r.framework_id=c.framework_id AND r.control_id=c.control_id WHERE c.framework_id=? AND c.control_id=? AND r.subcategory_id=?");

const lines = selected.map(({ control_id: controlId, subcategory_id: subcategoryId }) => {
  const row = statement.get(framework, controlId, subcategoryId);
  const csf = outcomes.get(subcategoryId);
  const required = [];
  if (row.relationship_scope === "indirect") required.push('Include this exact sentence in review_note: "This link involves product interpretation."');
  if (row.relationship_role === "context_only") required.push('Include this exact sentence in review_note: "This product check is not required to satisfy the CSF outcome under this mapping and does not by itself satisfy the outcome."');
  if (row.relationship_scope === "partial") required.push('In review_note, state the material source-grounded gap in a complete sentence beginning with "It does not ...".');
  if (!required.length) required.push("In review_note, state only the source-grounded limitation appropriate to the supplied relationship.");
  const input = [
    `Control: ${controlId} — ${row.title}`,
    `Official control statement: ${row.statement_text}`,
    `CSF Subcategory: ${subcategoryId}`,
    `Official CSF outcome: ${csf.outcome}`,
    `CSF examples:\n${csf.examples.map((example) => `- ${example}`).join("\n")}`,
    `Reviewed product relationship: ${row.relationship_role}; information: ${row.information_id || "none"}; scope: ${row.relationship_scope}.`,
    `Reviewed rationale: ${row.rationale}`,
    `Required review-note instruction:\n- ${required.join("\n- ")}`,
  ].join("\n\n");
  return JSON.stringify({ custom_id: `${framework}|${controlId}|${subcategoryId}|guidance-rerun-v2-b${String(batchNumber).padStart(3, "0")}`, method: "POST", url: "/v1/responses", body: { model: "gpt-6-sol", reasoning: { effort: "medium" }, instructions: `${prompt}\n\nEach request supplies a Required review-note instruction. Treat it as binding: include every exact sentence verbatim and meet every stated clause. Do not omit, weaken, or replace it.`, input, max_output_tokens: 1500, text: { format: { type: "json_schema", name: "control_mapping_guidance", strict: true, schema } } } });
});
db.close();
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, lines.join("\n") + "\n", "utf8");
console.log(JSON.stringify({ output_path: output, batch_number: batchNumber, request_count: lines.length, total_rerun_count: selectedAll.length, excluded_hold: "RA-04|DE.AE-06 (empty source control statement)", model: "gpt-6-sol", endpoint: "/v1/responses" }, null, 2));

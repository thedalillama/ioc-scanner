import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname);
const framework = "nist-sp-800-53-r5.2.0";
const baseArtifacts = [
  "batch_6abb13e070c881908ba1a3cf3db27abe_output.jsonl",
  "batch_6abb1a5add50819083715689a93b7eec_output.jsonl",
  "batch_6abb1ec0b3888190bd068d078c62db70_output.jsonl",
  "batch_6abb1ecc69a48190badf9a45d8ee7007_output.jsonl",
  "batch_6abb1ed8d85c8190a76b3bbcd5692e24_output.jsonl",
  "batch_6abb1ee35b5c8190ac5601d83d3c539a_output.jsonl",
  "batch_6abb1eee7ac88190a403cd7dddcfcaa8_output.jsonl",
  "batch_6abb1efad4508190925a1fca19ba8634_output.jsonl",
];
const rerunArtifacts = [
  "batch_6abb23cd0e3081909bd0d324aa2e1160_output.jsonl",
  "batch_6abb23d7e65881909af25db827ffa177_output.jsonl",
];
const replacement = "This guidance is our interpretation, not a NIST requirement or proof that the outcome is met.";
const conciseLimitations = new Map([
  ["CP-01|GV.OC-03", "Policy consistency does not manage the PC's legal, privacy, or contract duties."],
  ["PM-08|GV.OC-04", "A protection plan does not identify or communicate services external stakeholders rely on."],
  ["IA-11|PR.AA-01", "Repeated identity checks do not manage the PC user's identity or credentials."],
]);
const output = resolve(root, "reference-data/NIST/batches/control-mapping-guidance-candidate-v2.jsonl");

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
function guidanceFrom(record) {
  const text = record.response?.body?.output?.find((item) => item.type === "message")?.content?.find((item) => item.type === "output_text")?.text;
  return text ? JSON.parse(text) : null;
}
function keyFrom(record) {
  const [recordFramework, controlId, subcategoryId] = record.custom_id.split("|");
  return `${recordFramework}|${controlId}|${subcategoryId}`;
}
function normalizeReviewNote(note) {
  const sentences = note.match(/[^.!?…]+[.!?…]+|[^.!?…]+$/g) ?? [];
  let result = sentences
    .map((sentence) => sentence.trim())
    .filter((sentence) => !/product interpretation|indirect link|not required|does not by itself|does not itself satisfy|cannot alone satisfy|does not meet it alone/i.test(sentence))
    .join(" ")
    .replace(/\s{2,}/g, " ")
    .replace(/[\s.…]+$/u, "")
    .trim();
  if (result && !/[.!?]$/.test(result)) result += ".";
  return result ? `${result} ${replacement}` : replacement;
}

const selected = new Map();
for (const artifact of baseArtifacts) {
  for (const record of parseRecords(resolve(root, "reference-data/NIST/batches", artifact))) {
    try { selected.set(keyFrom(record), { artifact, guidance: guidanceFrom(record) }); } catch { /* A completed rerun, if present, supplies the replacement guidance. */ }
  }
}
for (const artifact of rerunArtifacts) {
  for (const record of parseRecords(resolve(root, "reference-data/NIST/batches", artifact))) selected.set(keyFrom(record), { artifact, guidance: guidanceFrom(record) });
}
const db = new DatabaseSync(resolve(root, "state/codex-monitor.db"), { readOnly: true });
const relationships = db.prepare("SELECT relationship_role, relationship_scope FROM csf_control_mapping_relationships WHERE framework_id=? AND control_id=? AND subcategory_id=?");
const rows = [];
const failures = [];
let transformed = 0;
for (const [key, item] of selected) {
  const [recordFramework, controlId, subcategoryId] = key.split("|");
  if (key === `${framework}|RA-04|DE.AE-06`) continue;
  const relationship = relationships.get(recordFramework, controlId, subcategoryId);
  const guidance = structuredClone(item.guidance);
  if (relationship.relationship_scope === "indirect" || relationship.relationship_role === "context_only") {
    guidance.review_note = conciseLimitations.has(`${controlId}|${subcategoryId}`)
      ? `${conciseLimitations.get(`${controlId}|${subcategoryId}`)} ${replacement}`
      : normalizeReviewNote(guidance.review_note);
    transformed += 1;
  }
  const invalid = Object.entries({ how_it_applies_here: 240, possible_action: 240, review_note: 240, action_title_example: 72, action_details_example: 220, action_rationale_example: 220 }).filter(([field, limit]) => typeof guidance[field] !== "string" || guidance[field].length > limit || (field !== "action_title_example" && !/[.!?]$/.test(guidance[field])));
  if (invalid.length) failures.push({ key, invalid, review_note: guidance.review_note });
  rows.push({ framework_id: recordFramework, control_id: controlId, subcategory_id: subcategoryId, source_artifact: item.artifact, guidance });
}
db.close();
if (rows.length !== 736) throw new Error(`Expected 736 candidates after excluding RA-04; found ${rows.length}.`);
if (failures.length) throw new Error(JSON.stringify({ message: "Candidate validation failed", failures }, null, 2));
rows.sort((a, b) => `${a.subcategory_id}|${a.control_id}`.localeCompare(`${b.subcategory_id}|${b.control_id}`));
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, rows.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
console.log(JSON.stringify({ output_path: output, candidate_count: rows.length, transformed_review_notes: transformed, held_source_gap: "RA-04|DE.AE-06", replacement }, null, 2));

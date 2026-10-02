import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname);
const files = process.argv.slice(2);
if (!files.length) throw new Error("Provide output artifact filenames.");
const requestFiles = [
  "control-mapping-guidance-sol-rerun-v2-000-099.jsonl",
  "control-mapping-guidance-sol-rerun-v2-100-181.jsonl",
];
const limits = { how_it_applies_here: 240, possible_action: 240, review_note: 240, action_title_example: 72, action_details_example: 220, action_rationale_example: 220 };
const fields = Object.keys(limits);
const findings = [];
function parseRecords(path) {
  const source = readFileSync(path, "utf8").trim();
  const records = [];
  let offset = 0;
  while (offset < source.length) {
    while (/\s/.test(source[offset] ?? "")) offset += 1;
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
function add(id, field, rule, value) { findings.push({ id, field, rule, value }); }
const requestInputs = new Map();
for (const file of requestFiles) {
  for (const line of readFileSync(resolve(root, "reference-data/NIST/batches", file), "utf8").trim().split(/\r?\n/)) {
    const request = JSON.parse(line);
    requestInputs.set(request.custom_id, request.body.input);
  }
}
let count = 0;
for (const file of files) for (const record of parseRecords(resolve(root, "reference-data/NIST/batches", file))) {
  count += 1;
  const id = record.custom_id;
  const text = record.response?.body?.output?.find((item) => item.type === "message")?.content?.find((item) => item.type === "output_text")?.text;
  let guidance;
  try { guidance = JSON.parse(text); } catch { add(id, "response", "valid JSON", text ?? ""); continue; }
  const input = requestInputs.get(id) ?? "";
  if (!input) add(id, "request", "matching rerun request input", "");
  for (const field of fields) {
    const value = guidance[field];
    if (typeof value !== "string" || !value.trim()) { add(id, field, "required non-empty string", String(value)); continue; }
    if (value.length > limits[field]) add(id, field, `maximum ${limits[field]} characters`, value);
    if (field !== "action_title_example" && !/[.!?]["')\]]?$/.test(value.trim())) add(id, field, "complete sentence ending", value);
    if (/\b[A-Z]{2,4}-\d{1,3}(?:\(\d+\))?\b/.test(value)) add(id, field, "no user-facing control identifier", value);
    if (/organization-defined|designated components|defined event types|defined content/i.test(value)) add(id, field, "no administrative control phrase", value);
    if (/^example\s*:/i.test(value)) add(id, field, 'must not begin with "Example:"', value);
    if (/\bthis\b|\bthese\b|\bthose\b|\bsuch\b/i.test(value) && !/This link involves product interpretation\.|This product check is not required/i.test(value)) add(id, field, "unexplained-reference heuristic", value);
  }
  const note = guidance.review_note;
  const exactClauses = [...input.matchAll(/Include this exact sentence in review_note: "([^"]+)"/g)].map((match) => match[1]);
  for (const clause of exactClauses) if (!note.includes(clause)) add(id, "review_note", "required exact clause", note);
  if (input.includes('beginning with "It does not ..."') && !/(^|\s)It does not /m.test(note)) add(id, "review_note", 'partial gap starts with "It does not"', note);
  if (/NIST requires|required by NIST|NIST requirement|NIST mandates/i.test(fields.map((field) => guidance[field]).join("\n"))) add(id, "all fields", "no NIST requirement or compliance claim", JSON.stringify(guidance));
  if (record.response?.body?.status !== "completed") add(id, "response", "completed status", record.response?.body?.status ?? "missing");
}
console.log(JSON.stringify({ response_count: count, finding_count: findings.length, findings }, null, 2));

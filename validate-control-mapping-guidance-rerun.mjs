import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname);
const files = process.argv.slice(2);
if (!files.length) throw new Error("Provide one or more output artifact filenames.");
const limits = { how_it_applies_here: 240, possible_action: 240, review_note: 240, action_title_example: 72, action_details_example: 220, action_rationale_example: 220 };
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
const failures = [];
let count = 0;
for (const file of files) {
  for (const record of parseRecords(resolve(root, "reference-data/NIST/batches", file))) {
    count += 1;
    const text = record.response?.body?.output?.find((item) => item.type === "message")?.content?.find((item) => item.type === "output_text")?.text;
    let guidance;
    try { guidance = JSON.parse(text); } catch { failures.push([record.custom_id, "response is not valid guidance JSON"]); continue; }
    for (const [field, limit] of Object.entries(limits)) if (typeof guidance[field] !== "string" || guidance[field].length > limit) failures.push([record.custom_id, `${field} is missing or exceeds ${limit} characters`]);
    const instructions = record.request?.body?.input ?? record.body?.input ?? "";
    const required = [...instructions.matchAll(/Include this exact sentence in review_note: "([^"]+)"/g)].map((match) => match[1]);
    for (const clause of required) if (!guidance.review_note.includes(clause)) failures.push([record.custom_id, `review_note omits required clause: ${clause}`]);
    if (instructions.includes('beginning with "It does not ..."') && !/^It does not /m.test(guidance.review_note)) failures.push([record.custom_id, 'review_note does not begin a material-gap sentence with "It does not ..."']);
    if (record.response?.body?.status !== "completed") failures.push([record.custom_id, `response status is ${record.response?.body?.status ?? "missing"}`]);
  }
}
console.log(JSON.stringify({ response_count: count, failure_count: failures.length, failures }, null, 2));

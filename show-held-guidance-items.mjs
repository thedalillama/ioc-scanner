import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname);
const held = new Map([
  ["SR-03|GV.SC-03", "G-026"], ["PM-31|GV.SC-09", "G-044"],
  ["RA-03|ID.IM-01", "G-075"], ["PT-01|ID.IM-02", "G-093"],
  ["MA-01|ID.IM-03", "G-109"], ["PM-09|ID.RA-06", "G-130"],
  ["IR-08|RS.AN-08", "G-171"], ["SR-03|RS.CO-03", "G-177"],
  ["IR-07|RS.MA-04", "G-184"], ["IR-04|RS.MA-05", "G-185"],
]);
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
for (const filename of ["batch_6abb23cd0e3081909bd0d324aa2e1160_output.jsonl", "batch_6abb23d7e65881909af25db827ffa177_output.jsonl"]) {
  for (const record of parseRecords(resolve(root, "reference-data/NIST/batches", filename))) {
    const [, controlId, subcategoryId] = record.custom_id.split("|");
    const queueId = held.get(`${controlId}|${subcategoryId}`);
    if (!queueId) continue;
    const text = record.response.body.output.find((item) => item.type === "message").content.find((item) => item.type === "output_text").text;
    console.log(JSON.stringify({ queue_id: queueId, control_id: controlId, subcategory_id: subcategoryId, guidance: JSON.parse(text) }, null, 2));
  }
}

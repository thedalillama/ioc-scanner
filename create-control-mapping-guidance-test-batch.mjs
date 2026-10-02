import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname);
const requestedMode = process.argv[2] ?? "production";
const rerunMode = requestedMode === "rerun";
const batchNumber = Number(rerunMode ? (process.argv[3] ?? "1") : requestedMode === "production" ? "2" : requestedMode);
const batchSize = 100;
if (!Number.isInteger(batchNumber) || batchNumber < 1) throw new Error("Batch number must be a positive integer.");
const db = new DatabaseSync(resolve(root, "state/codex-monitor.db"), { readOnly: true });
const catalog = JSON.parse(readFileSync(resolve(root, "profiles/nist-csf-2.0-catalog.json"), "utf8"));
const outcomes = new Map();
function walk(value) { if (!value || typeof value !== "object") return; if (value.class === "subcategory") outcomes.set(value.id, { outcome: value.parts?.find(p => p.name === "statement")?.prose ?? "", examples: (value.parts ?? []).filter(p => p.name === "example").map(p => p.prose) }); for (const child of Object.values(value)) walk(child); }
walk(catalog.catalog);

const allMappings = db.prepare("SELECT control_id, subcategory_id FROM csf_control_mapping_relationships WHERE framework_id = ? ORDER BY subcategory_id, control_id").all("nist-sp-800-53-r5.2.0");

function parseBatchArtifact(path) {
  const source = readFileSync(path, "utf8").trim();
  const records = [];
  let offset = 0;
  while (offset < source.length) {
    while (/\s/.test(source[offset] ?? "")) offset += 1;
    if (offset >= source.length) break;
    let depth = 0;
    let inString = false;
    let escaped = false;
    let end = offset;
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
  try { return text ? JSON.parse(text) : null; } catch { return null; }
}

function scopeException(record) {
  const parts = record.custom_id.split("|");
  const relationship = db.prepare("SELECT relationship_role, relationship_scope FROM csf_control_mapping_relationships WHERE framework_id=? AND control_id=? AND subcategory_id=?").get(parts[0], parts[1], parts[2]);
  const guidance = guidanceFrom(record);
  if (!relationship || !guidance) return null;
  const note = (guidance.review_note ?? "").toLowerCase();
  if (relationship.relationship_scope === "indirect" && !(/product interpretation/.test(note) || /indirect/.test(note))) return [parts[1], parts[2]];
  if (relationship.relationship_role === "context_only" && !(/not required|does not by itself|doesn't by itself|not a requirement/.test(note))) return [parts[1], parts[2]];
  if (relationship.relationship_scope === "partial" && !(/does not|but |gap|partial|only in part/.test(note))) return [parts[1], parts[2]];
  return null;
}

let candidates = allMappings.map(({ control_id, subcategory_id }) => [control_id, subcategory_id]);
if (rerunMode) {
  const returnedArtifacts = [
    "batch_6abb1ec0b3888190bd068d078c62db70_output.jsonl",
    "batch_6abb1ecc69a48190badf9a45d8ee7007_output.jsonl",
    "batch_6abb1ed8d85c8190a76b3bbcd5692e24_output.jsonl",
    "batch_6abb1eee7ac88190a403cd7dddcfcaa8_output.jsonl",
    "batch_6abb1efad4508190925a1fca19ba8634_output.jsonl",
  ];
  const rerunKeys = new Set();
  for (const artifact of returnedArtifacts) {
    for (const record of parseBatchArtifact(resolve(root, "reference-data/NIST/batches", artifact))) {
      const pair = scopeException(record);
      if (pair) rerunKeys.add(pair.join("|"));
    }
  }
  rerunKeys.add("CM-01|GV.OV-01");
  rerunKeys.add("AC-02|PR.DS-10");
  candidates = allMappings.filter(({ control_id, subcategory_id }) => rerunKeys.has(`${control_id}|${subcategory_id}`)).map(({ control_id, subcategory_id }) => [control_id, subcategory_id]);
}
const rangeStart = (batchNumber - 1) * batchSize;
if (rangeStart >= candidates.length) throw new Error(`No mappings remain at offset ${rangeStart}.`);
const batchLabel = String(batchNumber).padStart(3, "0");
const selected = candidates.slice(rangeStart, rangeStart + batchSize);
const selectedRangeEnd = rangeStart + selected.length - 1;
const rangeLabel = `${String(rangeStart).padStart(3, "0")}-${String(selectedRangeEnd).padStart(3, "0")}`;
const output = resolve(root, `reference-data/NIST/batches/control-mapping-guidance-sol-${rerunMode ? "rerun-v2" : "production-v1"}-${rangeLabel}.jsonl`);
const prompt = `Context: The product is assessing one single-user PC within an organization. The PC is one endpoint, not an entire organization or enterprise system. Its relevant context includes how it is used, the information it handles, the people who rely on that use, and the services or networks it connects to. Do not assume or invent facts about the defined context.

Reader: The person assessing and coordinating work within the defined context. They may not have authority to carry out organization-level or system-level work. When another role owns work, name that role and tell the reader what to ask for, provide, confirm, or record. Do not tell the reader to perform work outside their role.

You write product-authored, plain-language guidance for one existing official NIST informative mapping between a control and a CSF 2.0 outcome, within the defined context. The official mapping establishes relatedness only. Do not say NIST requires the guidance, action, direction, or scope.

Use only the supplied control statement, CSF outcome and examples, and reviewed relationship classification. Do not add mechanisms, requirements, evidence, prerequisites, or facts from another control. Restate only the actual verb and object in the official control statement. Translate control terms into ordinary task language. Do not repeat administrative phrases such as "organization-defined," "designated components," "defined event types," or "defined content." Do not mention any control identifier in a user-facing field. State what the reader needs to find out or coordinate in everyday words. Write at a high-school reading level, in short sentences.

For producer: explain the information created and how the outcome can use it. For consumer: explain the information needed before the control can use it; do not tell the user to recreate it. For enabler: explain the specific part of the outcome performed. For context_only: give a distinct product-authored contextual action that helps the reader consider the CSF outcome. Do not merely restate or ask the reader to implement the source control. State that the contextual action is not required to satisfy this CSF outcome under this mapping and does not by itself satisfy the outcome. Do not say that the source control does not require an action when its official statement does.

For direct, partial, and indirect, make the limitation accurate. A partial relationship must name the material gap. An indirect relationship must say that product interpretation is involved.

Each field must stand on its own. Name the relevant PC, records, lessons, problems, devices, analyses, or other subject in that field. Do not use an unexplained reference such as "this," "these," "those," or "such." When discussing audit records, say what each record includes rather than vague wording such as "specified details."

Prefer one complete sentence for each user-facing field. Aim for 180 characters or fewer for every field except action_title_example, which should aim for 60 characters or fewer. Finish every body field as a complete sentence before reaching its limit.

Before returning, silently check every field against these rules: it stays within the defined context; it gives the reader only work they can reasonably coordinate; it names another responsible role when needed; it uses only supplied facts; it follows the reviewed relationship classification; a context_only action is distinct from implementation of the source control and relevant to the CSF outcome; it does not turn a related mapping into a NIST requirement or compliance claim; it states any required limitation; it does not falsely say the source control fails to require an action; every body field is a complete sentence within its preferred length; and it uses short, high-school-level language without unexplained references, control identifiers, control terminology, or administrative control phrases. Revise the fields if any check fails. Do not include this check or its reasoning in the JSON.

Keep each user-facing field short enough for the mapped-control picker: how_it_applies_here, possible_action, and review_note must each be 240 characters or fewer; action_title_example must be 72 characters or fewer; and action_details_example and action_rationale_example must each be 220 characters or fewer.

Return only JSON. The three action example fields are grey placeholder examples, not text to copy verbatim. Each must be specific to this control and outcome. Do not begin any field with “Example:”.`;
const fieldLimits = { how_it_applies_here: 240, possible_action: 240, review_note: 240, action_title_example: 72, action_details_example: 220, action_rationale_example: 220 };
const schema = { type: "object", additionalProperties: false, required: Object.keys(fieldLimits), properties: Object.fromEntries(Object.entries(fieldLimits).map(([key, maxLength]) => [key,{type:"string",maxLength}])) };
const statement = db.prepare("SELECT c.title,c.statement_text,r.relationship_role,r.information_id,r.relationship_scope,r.rationale FROM csf_reference_controls c JOIN csf_control_mapping_relationships r ON r.framework_id=c.framework_id AND r.control_id=c.control_id WHERE c.framework_id=? AND c.control_id=? AND r.subcategory_id=?");
const lines = selected.map(([control_id,subcategory_id]) => { const row=statement.get("nist-sp-800-53-r5.2.0",control_id,subcategory_id); if(!row) throw new Error(`Missing relationship: ${control_id} ${subcategory_id}`); const csf=outcomes.get(subcategory_id); const input=[`Control: ${control_id} — ${row.title}`,`Official control statement: ${row.statement_text}`,`CSF Subcategory: ${subcategory_id}`,`Official CSF outcome: ${csf.outcome}`,`CSF examples:\n${csf.examples.map(x=>`- ${x}`).join("\n")}`,`Reviewed product relationship: ${row.relationship_role}; information: ${row.information_id || "none"}; scope: ${row.relationship_scope}.`,`Reviewed rationale: ${row.rationale}`].join("\n\n"); return JSON.stringify({custom_id:`nist-sp-800-53-r5.2.0|${control_id}|${subcategory_id}|guidance-production-v1-b${batchLabel}`,method:"POST",url:"/v1/responses",body:{model:"gpt-6-sol",reasoning:{effort:"medium"},instructions:prompt,input,max_output_tokens:1500,text:{format:{type:"json_schema",name:"control_mapping_guidance",strict:true,schema}}}}); });
db.close(); mkdirSync(dirname(output),{recursive:true}); writeFileSync(output,lines.join("\n")+"\n","utf8"); console.log(JSON.stringify({output_path:output,batch_number:batchNumber,request_count:lines.length,total_mapping_count:allMappings.length,model:"gpt-6-sol",endpoint:"/v1/responses"},null,2));

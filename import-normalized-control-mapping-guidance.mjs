import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname);
const input = resolve(root, process.argv[2] ?? "reference-data/NIST/batches/control-mapping-guidance-candidate-v2.jsonl");
const dbPath = resolve(root, process.argv[3] ?? "state/codex-monitor.db");
const fields = {
  how_it_applies_here: 240,
  possible_action: 240,
  review_note: 240,
  action_title_example: 72,
  action_details_example: 220,
  action_rationale_example: 220,
};
const records = readFileSync(input, "utf8").trim().split(/\r?\n/).map((line, index) => {
  const record = JSON.parse(line);
  if (!record.framework_id || !record.control_id || !record.subcategory_id || !record.guidance) throw new Error(`Invalid candidate record at line ${index + 1}.`);
  for (const [field, limit] of Object.entries(fields)) {
    const value = record.guidance[field];
    if (typeof value !== "string" || !value.trim() || value.length > limit) throw new Error(`Invalid ${field} at line ${index + 1}.`);
  }
  return record;
});
const keys = new Set(records.map((record) => `${record.framework_id}|${record.control_id}|${record.subcategory_id}`));
if (keys.size !== records.length) throw new Error("Candidate has duplicate mappings.");

const db = new DatabaseSync(dbPath);
const mappingColumns = new Set(db.prepare("PRAGMA table_info(csf_subcategory_control_mappings)").all().map((row) => row.name));
if (!mappingColumns.has("action_details_example") || !mappingColumns.has("confidence_note")) throw new Error("The guidance-schema migration is missing.");
const exists = db.prepare("SELECT 1 FROM csf_subcategory_control_mappings WHERE framework_id=? AND control_id=? AND subcategory_id=?");
const update = db.prepare(`
  UPDATE csf_subcategory_control_mappings
  SET interpretation_text=?, suggested_action_text=?, action_title_example=?,
      action_details_example=?, action_rationale_example=?, confidence_note=?,
      interpretation_source=?, interpretation_updated_at=?
  WHERE framework_id=? AND control_id=? AND subcategory_id=?
`);
const updatedAt = new Date().toISOString();
const source = "product-guidance-normalized-v2";
db.exec("BEGIN IMMEDIATE");
try {
  for (const record of records) {
    if (!exists.get(record.framework_id, record.control_id, record.subcategory_id)) throw new Error(`Missing mapping: ${record.framework_id}|${record.control_id}|${record.subcategory_id}`);
    const g = record.guidance;
    update.run(g.how_it_applies_here, g.possible_action, g.action_title_example, g.action_details_example, g.action_rationale_example, g.review_note, source, updatedAt, record.framework_id, record.control_id, record.subcategory_id);
  }
  db.exec("COMMIT");
  console.log(JSON.stringify({ db_path: dbPath, updated_mapping_count: records.length, interpretation_source: source, updated_at: updatedAt }, null, 2));
} catch (error) {
  db.exec("ROLLBACK");
  throw error;
} finally {
  db.close();
}

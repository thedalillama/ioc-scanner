#!/usr/bin/env node
/**
 * Import completed OpenAI Batch guidance into the development CSF mapping DB.
 *
 * The importer validates every response before opening a write transaction.
 * It requires a Batch identifier for provenance and does not submit API work.
 */

import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname);

function requiredOption(name) {
  const index = process.argv.indexOf(name);
  const value = index === -1 ? "" : process.argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} is required.`);
  return value;
}

function optionalPath(name, fallback) {
  const index = process.argv.indexOf(name);
  return resolve(index === -1 ? fallback : process.argv[index + 1]);
}

const inputPath = optionalPath("--input", "");
const dbPath = optionalPath("--db", resolve(ROOT, "state", "codex-monitor.db"));
const batchId = requiredOption("--batch-id");
if (!inputPath) throw new Error("--input is required.");

const requiredFields = [
  "how_it_applies_here",
  "possible_action",
  "action_title_example",
  "action_details_example",
  "action_rationale_example",
  "confidence_note",
];

const rows = readFileSync(inputPath, "utf8")
  .trim()
  .split(/\r?\n/)
  .map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new Error(`Output line ${index + 1} is not valid JSON: ${error.message}`);
    }
  });
if (!rows.length) throw new Error("The Batch output file is empty.");

const records = rows.map((row, index) => {
  if (row.error || row.response?.status_code !== 200) {
    throw new Error(`Output line ${index + 1} did not complete successfully.`);
  }
  const parts = String(row.custom_id ?? "").split("|");
  if (parts.length !== 4 || !parts.every(Boolean)) {
    throw new Error(`Output line ${index + 1} has an invalid custom_id.`);
  }
  const [frameworkId, controlId, subcategoryId, model] = parts;
  const outputText = row.response?.body?.output_text
    ?? row.response?.body?.output
      ?.flatMap((item) => item.content ?? [])
      .find((item) => item.type === "output_text")
      ?.text;
  if (typeof outputText !== "string") {
    throw new Error(`Output line ${index + 1} has no Responses output_text.`);
  }
  let guidance;
  try {
    guidance = JSON.parse(outputText);
  } catch (error) {
    throw new Error(`Output line ${index + 1} contains invalid structured guidance: ${error.message}`);
  }
  for (const field of requiredFields) {
    if (typeof guidance[field] !== "string") {
      throw new Error(`Output line ${index + 1} has no string ${field}.`);
    }
  }
  if (requiredFields.slice(0, -1).some((field) => !guidance[field].trim())) {
    throw new Error(`Output line ${index + 1} has a blank required guidance field.`);
  }
  return { frameworkId, controlId, subcategoryId, model, guidance };
});

const models = [...new Set(records.map((record) => record.model))];
if (models.length !== 1) throw new Error("The output file must contain one model.");
const recordKeys = new Set(records.map((record) => `${record.frameworkId}|${record.controlId}|${record.subcategoryId}`));
if (recordKeys.size !== records.length) throw new Error("The output file contains duplicate mapping records.");

const db = new DatabaseSync(dbPath);
const mappingColumns = new Set(db.prepare("PRAGMA table_info(csf_subcategory_control_mappings)").all().map((row) => row.name));
db.exec("BEGIN IMMEDIATE");
try {
  if (!mappingColumns.has("action_details_example")) {
    db.exec("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN action_details_example TEXT NOT NULL DEFAULT ''");
  }
  if (!mappingColumns.has("confidence_note")) {
    db.exec("ALTER TABLE csf_subcategory_control_mappings ADD COLUMN confidence_note TEXT NOT NULL DEFAULT ''");
  }
  db.prepare("INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES (?, ?, ?)").run(
    18,
    new Date().toISOString(),
    "Store batch-generated action-detail examples and mapping review notes.",
  );
  const exists = db.prepare(`
    SELECT 1 FROM csf_subcategory_control_mappings
    WHERE framework_id = ? AND control_id = ? AND subcategory_id = ?
  `);
  const update = db.prepare(`
    UPDATE csf_subcategory_control_mappings
    SET interpretation_text = ?, suggested_action_text = ?, action_title_example = ?,
        action_details_example = ?, action_rationale_example = ?, confidence_note = ?,
        interpretation_source = ?, interpretation_updated_at = ?
    WHERE framework_id = ? AND control_id = ? AND subcategory_id = ?
  `);
  const updatedAt = new Date().toISOString();
  const source = `openai-batch:${batchId}:${models[0]}`;
  for (const record of records) {
    if (!exists.get(record.frameworkId, record.controlId, record.subcategoryId)) {
      throw new Error(`No imported mapping exists for ${record.frameworkId}|${record.controlId}|${record.subcategoryId}.`);
    }
    const g = record.guidance;
    update.run(
      g.how_it_applies_here.trim(),
      g.possible_action.trim(),
      g.action_title_example.trim(),
      g.action_details_example.trim(),
      g.action_rationale_example.trim(),
      g.confidence_note.trim(),
      source,
      updatedAt,
      record.frameworkId,
      record.controlId,
      record.subcategoryId,
    );
  }
  db.exec("COMMIT");
  console.log(JSON.stringify({
    db_path: dbPath,
    batch_id: batchId,
    model: models[0],
    updated_mapping_count: records.length,
    interpretation_source: source,
  }, null, 2));
} catch (error) {
  db.exec("ROLLBACK");
  throw error;
} finally {
  db.close();
}

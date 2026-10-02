#!/usr/bin/env node
/** Create a targeted retry batch for the two truncated Cyber AI - Defend results. */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname);
const sourcePath = resolve(root, "reference-data", "NIST", "batches", "cyber-ai-defend-action-guidance-sol-rerun-000-064.jsonl");
const outputPath = resolve(root, "reference-data", "NIST", "batches", "cyber-ai-defend-action-guidance-sol-rerun-065-066.jsonl");
const retryIds = new Set(["PR.PS-04", "RC.RP-06"]);
const promptVersion = "cyber-ai-action-guidance-v3-final-retry";

const records = readFileSync(sourcePath, "utf8").trim().split(/\r?\n/).map(JSON.parse)
  .filter((record) => retryIds.has(record.custom_id.split("|")[1]))
  .map((record) => {
    const [profileId, outcomeId] = record.custom_id.split("|");
    return {
      ...record,
      custom_id: `${profileId}|${outcomeId}|${promptVersion}`,
      body: { ...record.body, max_output_tokens: 1400 },
    };
  });

if (records.length !== retryIds.size) throw new Error("Did not find both targeted retry records.");
writeFileSync(outputPath, `${records.map(JSON.stringify).join("\n")}\n`, "utf8");
console.log(JSON.stringify({
  output_path: outputPath,
  request_count: records.length,
  outcomes: records.map((record) => record.custom_id.split("|")[1]),
  model: records[0].body.model,
  endpoint: records[0].url,
  max_output_tokens: records[0].body.max_output_tokens,
  prompt_version: promptVersion,
}, null, 2));

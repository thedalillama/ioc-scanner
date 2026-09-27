#!/usr/bin/env node
/**
 * Build two single-model OpenAI Batch JSONL files to compare Terra and Astra
 * on every control mapped to one difficult CSF outcome. This script does not
 * upload or submit either Batch.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname);
const sourcePath = resolve(ROOT, "reference-data", "NIST", "batches", "csf-sp800-53-mapping-guidance-v1.jsonl");
const outputDirectory = resolve(ROOT, "reference-data", "NIST", "batches");
const subcategoryId = "GV.OC-02";

const source = readFileSync(sourcePath, "utf8")
  .trim()
  .split(/\r?\n/)
  .map((line) => JSON.parse(line));
const requests = source.filter((entry) => entry.custom_id.endsWith(`|${subcategoryId}`));
if (!requests.length) {
  throw new Error(`No mapping requests were found for ${subcategoryId} in ${sourcePath}.`);
}

const models = ["gpt-5.6-terra", "gpt-6-astra"];
const comparison = new Map(models.map((model) => [model, requests.map((request) => ({
    ...request,
    custom_id: `${request.custom_id}|${model}`,
    body: { ...request.body, model },
  }))]));

mkdirSync(outputDirectory, { recursive: true });
const outputs = Object.fromEntries(
  [...comparison.entries()].map(([model, entries]) => {
    const suffix = model.replace(/^gpt-/, "").replace(/\./g, "-");
    const outputPath = resolve(outputDirectory, `csf-mapping-model-comparison-gvoc02-${suffix}.jsonl`);
    writeFileSync(outputPath, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`, "utf8");
    return [model, outputPath];
  }),
);
console.log(JSON.stringify({
  subcategory_id: subcategoryId,
  mapping_count: requests.length,
  requests_per_batch: requests.length,
  outputs,
}, null, 2));

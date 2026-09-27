import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname);
const source = readFileSync(resolve(root, "csf_information_flows.py"), "utf8");

function readPythonList(name) {
  const match = source.match(new RegExp(`${name}: List\\[Dict\\[str, str\\]\\] = \\[([\\s\\S]*?)\\n\\]\\n`, "m"));
  if (!match) throw new Error(`Unable to read ${name} from csf_information_flows.py.`);
  return Function(`return [${match[1]}];`)();
}

const items = readPythonList("INFORMATION_ITEMS");
const sources = readPythonList("INFORMATION_SOURCES");
const uses = readPythonList("INFORMATION_USES");
const catalog = items.map((item) => ({
  ...item,
  sources: sources.filter((sourceItem) => sourceItem.information_id === item.information_id),
  uses: uses.filter((use) => use.information_id === item.information_id),
}));

const fragment = `<div id="full-information-flow-catalog">
  <style>
    #full-information-flow-catalog { color: var(--foreground); }
    #full-information-flow-catalog svg { display: block; width: 100%; height: auto; }
    #full-information-flow-catalog .edge { fill: none; stroke: var(--muted-foreground); stroke-width: 1.2; marker-end: url(#catalog-arrow); }
    #full-information-flow-catalog .edge.required { stroke: var(--orange); stroke-width: 2.2; }
    #full-information-flow-catalog .edge.event { stroke-dasharray: 5 4; }
    #full-information-flow-catalog .node { stroke-width: 1.25; rx: 7; }
    #full-information-flow-catalog .source { fill: color-mix(in srgb, var(--blue) 14%, var(--background)); stroke: var(--blue); }
    #full-information-flow-catalog .information { fill: color-mix(in srgb, var(--green) 14%, var(--background)); stroke: var(--green); }
    #full-information-flow-catalog .consumer { fill: color-mix(in srgb, var(--orange) 12%, var(--background)); stroke: var(--orange); }
    #full-information-flow-catalog text { fill: var(--foreground); font-family: sans-serif; font-size: 12px; }
    #full-information-flow-catalog .small { fill: var(--muted-foreground); font-size: 10px; }
    #full-information-flow-catalog .title { font-size: 18px; font-weight: 500; }
    #full-information-flow-catalog .section { fill: var(--muted-foreground); font-size: 11px; font-weight: 500; }
  </style>
  <svg id="catalog-svg" role="img" aria-labelledby="catalog-title catalog-description">
    <title id="catalog-title">Complete CSF Subcategory-to-information-flow catalog</title>
    <desc id="catalog-description">Each row shows official CSF Subcategories that can provide a reusable information item and the downstream CSF Subcategories that use that information. Orange edges are required inputs; gray edges are planning inputs; dashed edges are event inputs.</desc>
  </svg>
  <script>
    const catalog = ${JSON.stringify(catalog)};
    const svg = document.getElementById("catalog-svg");
    const ns = "http://www.w3.org/2000/svg";
    const width = 1024;
    const sourceX = 24, sourceW = 218, itemX = 372, itemW = 250, useX = 754, useW = 246;
    const top = 122, gap = 28;
    const sourceHeight = 34, useHeight = 34;
    const text = (x, y, value, className = "") => {
      const element = document.createElementNS(ns, "text");
      element.setAttribute("x", x); element.setAttribute("y", y); element.textContent = value;
      if (className) element.setAttribute("class", className); svg.append(element); return element;
    };
    const rect = (x, y, width, height, className) => {
      const element = document.createElementNS(ns, "rect");
      element.setAttribute("x", x); element.setAttribute("y", y); element.setAttribute("width", width); element.setAttribute("height", height); element.setAttribute("class", className); svg.append(element); return element;
    };
    const edge = (x1, y1, x2, y2, kind = "planning_input") => {
      const element = document.createElementNS(ns, "path");
      const mid = (x1 + x2) / 2;
      element.setAttribute("d", "M " + x1 + " " + y1 + " C " + mid + " " + y1 + ", " + mid + " " + y2 + ", " + x2 + " " + y2);
      element.setAttribute("class", "edge " + (kind === "required_input" ? "required" : kind === "event_input" ? "event" : "")); svg.append(element);
    };
    const wrap = (value, max) => {
      const words = value.split(/\\s+/); const lines = []; let line = "";
      words.forEach((word) => { const next = line ? line + " " + word : word; if (next.length > max && line) { lines.push(line); line = word; } else line = next; });
      if (line) lines.push(line); return lines.slice(0, 3);
    };
    const defs = document.createElementNS(ns, "defs");
    const marker = document.createElementNS(ns, "marker"); marker.setAttribute("id", "catalog-arrow"); marker.setAttribute("viewBox", "0 0 10 10"); marker.setAttribute("refX", "8"); marker.setAttribute("refY", "5"); marker.setAttribute("markerWidth", "6"); marker.setAttribute("markerHeight", "6"); marker.setAttribute("orient", "auto-start-reverse");
    const arrow = document.createElementNS(ns, "path"); arrow.setAttribute("d", "M 0 0 L 10 5 L 0 10 z"); arrow.setAttribute("fill", "var(--muted-foreground)"); marker.append(arrow); defs.append(marker); svg.append(defs);

    text(24, 32, "Complete Subcategory-to-information-flow catalog", "title");
    text(24, 54, "Each row is one reusable information item. The same CSF Subcategory can appear in multiple rows because it provides or uses multiple kinds of information.", "small");
    rect(24, 72, 14, 14, "node source"); text(46, 84, "Source Subcategory", "small");
    rect(236, 72, 14, 14, "node information"); text(258, 84, "Information item", "small");
    rect(426, 72, 14, 14, "node consumer"); text(448, 84, "Downstream Subcategory", "small");
    text(24, 108, "Source outcomes", "section"); text(372, 108, "Reusable information", "section"); text(754, 108, "Downstream uses", "section");

    let y = top;
    catalog.forEach((item) => {
      const sourceCount = Math.max(1, item.sources.length);
      const useCount = Math.max(1, item.uses.length);
      const rowHeight = Math.max(sourceCount * 42, useCount * 42, 72) + 26;
      const itemY = y + (rowHeight - 58) / 2;
      rect(itemX, itemY, itemW, 58, "node information");
      wrap(item.title, 28).forEach((line, index) => text(itemX + 12, itemY + 22 + index * 15, line));
      const description = wrap(item.description, 42)[0] || "";
      text(itemX + 12, itemY + 49, description, "small");
      item.sources.forEach((sourceItem, index) => {
        const nodeY = y + index * 42;
        rect(sourceX, nodeY, sourceW, sourceHeight, "node source");
        text(sourceX + 10, nodeY + 15, sourceItem.source_subcategory_id);
        text(sourceX + 10, nodeY + 28, wrap(sourceItem.source_guidance, 33)[0], "small");
        edge(sourceX + sourceW, nodeY + sourceHeight / 2, itemX, itemY + 29);
      });
      item.uses.forEach((use, index) => {
        const nodeY = y + index * 42;
        rect(useX, nodeY, useW, useHeight, "node consumer");
        text(useX + 10, nodeY + 15, use.consumer_subcategory_id);
        text(useX + 10, nodeY + 28, use.dependency_kind.replace("_", " ") + ": " + wrap(use.use_reason, 30)[0], "small");
        edge(itemX + itemW, itemY + 29, useX, nodeY + useHeight / 2, use.dependency_kind);
      });
      y += rowHeight + gap;
    });
    svg.setAttribute("viewBox", "0 0 " + width + " " + (y + 20));
  </script>
</div>`;

const outputPath = resolve(root, "visualizations", "full-information-flow-catalog.html");
writeFileSync(outputPath, fragment, "utf8");
const browserPath = resolve(root, "visualizations", "full-information-flow-catalog-view.html");
const browserPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CSF information-flow catalog</title>
<style>
  :root { --background: #ffffff; --foreground: #1f2933; --muted-foreground: #5c6b76; --blue: #356a94; --green: #3e775b; --orange: #96632f; }
  body { margin: 0; padding: 24px; background: var(--background); color: var(--foreground); }
</style></head><body>${fragment}</body></html>`;
writeFileSync(browserPath, browserPage, "utf8");
const mermaidId = (value) => value.replace(/[^A-Za-z0-9]/g, "_");
const allSubcategories = [...new Set([
  ...sources.map((item) => item.source_subcategory_id),
  ...uses.map((item) => item.consumer_subcategory_id),
])].sort();
const mermaidLines = [
  "flowchart LR",
  "  classDef outcome fill:#E8F0F8,stroke:#40647A,color:#16242D",
  "  classDef information fill:#E8F3EC,stroke:#4D806A,color:#16242D",
  "",
  "  %% Blue nodes are CSF Subcategories. Green nodes are reusable information items.",
  ...allSubcategories.map((id) => `  ${mermaidId(id)}[\"${id}\"]:::outcome`),
  ...items.map((item) => `  info_${mermaidId(item.information_id)}[\"${item.title}\"]:::information`),
  "",
  "  %% Source outcome → information item",
  ...sources.map((item) => `  ${mermaidId(item.source_subcategory_id)} --> info_${mermaidId(item.information_id)}`),
  "",
  "  %% Information item → downstream outcome. Labels show required, planning, or event input.",
  ...uses.map((item) => `  info_${mermaidId(item.information_id)} -->|${item.dependency_kind.replace("_", " ")}| ${mermaidId(item.consumer_subcategory_id)}`),
];
const mermaidPath = resolve(root, "visualizations", "full-information-flow-catalog.mmd");
writeFileSync(mermaidPath, `${mermaidLines.join("\n")}\n`, "utf8");
console.log(JSON.stringify({ fragment_path: outputPath, browser_path: browserPath, mermaid_path: mermaidPath, information_items: items.length, source_edges: sources.length, use_edges: uses.length }, null, 2));

#!/usr/bin/env node
/**
 * Create an Astra-only, seven-control GV.OC-02 Batch input that differs from
 * the completed Astra comparison only by its revised single-PC prompt.
 * It does not upload or submit the Batch.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname);
const sourcePath = resolve(ROOT, "reference-data", "NIST", "batches", "csf-mapping-model-comparison-gvoc02-6-astra.jsonl");
const outputPath = resolve(ROOT, "reference-data", "NIST", "batches", "csf-mapping-guidance-prompt-v4-gvoc02-astra.jsonl");

const instructions = `You are writing product-authored guidance for one informative mapping between NIST CSF 2.0 and a control framework.

Context: This guidance applies to one managed Windows PC. The app user is responsible for that PC. People may be affected by how the PC stores, uses, or provides access to information.

Given the provided context, explain how the supplied control can help advance the supplied CSF outcome.

Jobs:
1. Keep the mapping accurate and context-specific.
- Before writing, decide whether the supplied control offers direct support, partial support, indirect support, or no practical support for the CSF outcome in the provided context.
- Let that decision determine the guidance. Keep the exact CSF outcome at the center, include only control topics that directly matter, and do not force an action merely because an official mapping exists.
- Do not imply that the control requires an activity or document unless its official statement says so. State the mapping’s limits, and do not claim that the action satisfies the control or the CSF outcome.
- If there is no practical support, say so plainly in confidence_note and leave the action-example fields empty rather than inventing an action.

2. Keep the guidance understandable.
- Write at a high-school reading level using plain, everyday words and short, direct sentences.
- Use concrete descriptions of people, needs, and decisions. Keep each field short and avoid repeating ideas.

3. Make the action practical in the provided context.
- Give the app user one realistic next step. Name another person only when needed, describe that person by their responsibility in the provided context, and state what they contribute.
- When an action needs more than one responsibility, state the handoff clearly: who identifies the need, who translates it into a technical or security requirement, and who uses or approves that requirement. One person may perform more than one responsibility in a small organization.
- Do not assume the person responsible for the supplied control knows local PC facts. Identify who is closest to the PC's use or affected information for those facts. Consult the control, policy, or strategy owner only for the direction, requirement, approval, or specialized knowledge their responsibility reasonably provides.
- When identifying affected people, describe how the asset, service, data, or process in the provided context is used.
- Decide whether the action should identify and record affected people, involve them directly, or both. When it records people or needs, state how the record will be used to support the CSF outcome.
- When Information-flow data is provided, use it. If this outcome produces information used downstream, say what later decision or activity will use the record and include only the details needed to make that use possible. Do not turn the action into work for the downstream outcome.
- If Information-flow data identifies information this action needs, name the prerequisite and explain how the action will use it. Tell the user to confirm or obtain it first when it is missing. Do not assume a particular control produced it: the named CSF outcome, an equivalent existing record, or a custom action may supply it.
- Do not assume job titles, organization structure, formal governance, or tools that the context does not establish.

  Examples of responsibility-based wording:
  - For a security and privacy strategy, name the person who maintains that strategy.
  - For a privacy plan, name the person who handles privacy questions or personal information.
  - For buying hardware, software, or services, name the person who approves the purchase.
  - For a supplier or service review, name the person who manages or reviews that provider.
  - For supplier notices, name the person who receives the notices and decides who needs to know.

4. Avoid generic guidance.
- Make the action, responsible person, and examples fit this specific control, outcome, and context.
- Use the context to choose what evidence, conversation, review, or decision is useful. Do not fall back to vague phrases or generic risk-management language.
- Before responding, check whether the response fulfills all four jobs. Revise it if it does not.

Example inputs:
- Framework: NIST SP 800-53 Rev. 5.2.0
- Control: PM-11 — Mission and Business Process Definition
- CSF subcategory: GV.OC-01
- Official CSF outcome: The organizational mission is understood and informs cybersecurity risk management.
- Information-flow data:
  - Producing outcome: GV.OC-01
  - Information item: Organizational mission and objectives
  - Consumer outcomes: GV.RM-01, ID.AM-05, ID.RA-04, and RC.RP-04
  - Dependency type: planning input
  - Downstream use: Set risk-management objectives, prioritize assets, estimate the impact of risk scenarios, and set recovery priorities.
  - Acceptable sources: A current mission statement, service strategy, or equivalent record.

Good output:
{
  "how_it_applies_here": "PM-11 applies here because a current, shared mission helps people set cybersecurity priorities that support what the organization is trying to accomplish.",
  "possible_action": "Ask the person who defines or communicates the organization’s mission to confirm the current mission statement. Record and share it so it can guide risk objectives, asset priorities, impact estimates, and recovery priorities.",
  "action_title_example": "Document and share the current mission statement",
  "action_details_example": "Record the current mission statement, note who confirmed it, identify the cybersecurity decisions it should inform, share it with the responsible people, and set a review point when the mission or business activities change.",
  "action_rationale_example": "Keeping the mission statement current and available gives risk, asset, and recovery decisions a clear connection to what the organization is trying to accomplish.",
  "confidence_note": ""
}

Additional example — indirect mapping, single-PC context

Inputs:
- Framework: NIST SP 800-53 Rev. 5.2.0
- Control: PM-09 — Risk Management Strategy
- CSF subcategory: GV.OC-02
- Official CSF outcome: Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered.
- Supplemental NIST community-profile context: Stakeholder needs can include data protection, privacy, service availability, incident response, regulatory compliance, and communications during disruptions. Those needs should be documented and considered in cybersecurity policies and practices.
- Information-flow data:
  - Producing outcome: GV.OC-02
  - Information item: Stakeholder cybersecurity and privacy needs
  - Consumer outcome: GV.SC-05
  - Dependency type: required input
  - Downstream use: Translate known security and privacy needs into supplier and purchasing requirements.
  - Acceptable sources: A GV.OC-02 record, an equivalent existing record, or a custom action.

Good output:
{
  "how_it_applies_here": "PM-09 provides security and privacy risk direction that can be applied after the people affected by this PC's information use and their needs are identified. Those needs can then guide PC security and privacy decisions.",
  "possible_action": "Identify how the PC is used and who relies on its information. Ask those people, or the person responsible for their work, what they need kept secure, private, or available. Then compare those needs with the organization’s security and privacy risk strategy and record any PC decision it informs.",
  "action_title_example": "Record people affected by PC information use",
  "action_details_example": "Record the affected people, the PC information use that affects them, their security and privacy needs, the source of that information, the relevant strategy direction, and any PC decision informed by those needs. Keep the record available for later supplier or purchasing requirements.",
  "action_rationale_example": "The record shows whose needs and strategy direction were considered for PC security and privacy decisions and gives later purchasing work a clear source for its requirements.",
  "confidence_note": "This mapping is indirect. PM-09 requires a cybersecurity and privacy risk strategy; it does not separately require a stakeholder list."
}`;

const informationFlowContext = `Information-flow data:
- Producing outcome: GV.OC-02
- Information item: Stakeholder cybersecurity and privacy needs
- Consumer outcome: GV.SC-05
- Dependency type: required input
- Downstream use: Translate known security and privacy needs into supplier and purchasing requirements.
- Acceptable sources: A GV.OC-02 record, an equivalent existing record, or a custom action.`;

const rows = readFileSync(sourcePath, "utf8")
  .trim()
  .split(/\r?\n/)
  .map((line) => JSON.parse(line));
if (rows.length !== 7 || rows.some((row) => row.body?.model !== "gpt-6-astra" || !row.custom_id?.endsWith("|GV.OC-02|gpt-6-astra"))) {
  throw new Error("Expected seven Astra-only GV.OC-02 requests in the comparison source file.");
}

const revised = rows.map((row) => ({
  ...row,
  body: {
    ...row.body,
    instructions,
    input: `${row.body.input}\n\n${informationFlowContext}`,
  },
}));
mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${revised.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
console.log(JSON.stringify({ output_path: outputPath, request_count: revised.length, model: "gpt-6-astra", prompt_version: "v4-role-specific" }, null, 2));

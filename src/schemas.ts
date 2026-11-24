import { CRITERION_OUTCOMES, ROUTINGS } from "./types.ts";

/**
 * The longest text one tool argument may carry, in characters (code points, as
 * JSON Schema counts maxLength), checked in handleTool and advertised.
 */
export const MAX_TEXT_CHARS = 32 * 1024;

/**
 * All text in one call, keys included, in UTF-16 units. Each unit is at most
 * 6 bytes on the wire (\uXXXX), so a call within this, at most 240 KiB of
 * text plus framing, always fits the transport's 256 KiB cap: an oversized
 * call gets a tool error instead of closing the session.
 */
export const MAX_CALL_TEXT_UNITS = 40 * 1024;

type Json = { [k: string]: unknown };
/** Every string property, and every string array item, gains maxLength. */
function withTextLimits<T>(node: T): T {
  if (Array.isArray(node)) return node.map(withTextLimits) as T;
  if (node === null || typeof node !== "object") return node;
  const out: Json = {};
  for (const [k, v] of Object.entries(node as Json)) out[k] = withTextLimits(v);
  if (out.type === "string" && out.maxLength === undefined) out.maxLength = MAX_TEXT_CHARS;
  return out as T;
}

/** Checked in handleTool: the schema's pattern is advertised, not enforced by the SDK. */
export const CASE_ID = /^[A-Za-z0-9~#][A-Za-z0-9._:#~-]{0,79}$/;

/**
 * On every tool, so deliveries and decisions of one incident join on it rather
 * than on time adjacency, which interleaves when two incidents run at once.
 */
const caseId = {
  type: "string",
  pattern: CASE_ID.source,
  description:
    "The incident this call belongs to (ticket or case id). Pass the same value on every call for one incident.",
} as const;

/**
 * Read tools change nothing outside the server (each call is logged locally,
 * which is not a change to the caller's world). ir_log and ir_propose write
 * local state only: neither is destructive, and neither reaches anything external.
 */
const READ = { readOnlyHint: true, idempotentHint: true, openWorldHint: false } as const;
const LOCAL_WRITE = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false,
} as const;

const SCHEMAS = [
  {
    name: "ir_classify",
    description:
      "Rank candidate incident readings across all playbooks against free-text evidence. Always returns at least two candidates with their discriminators — never a single verdict.",
    annotations: READ,
    inputSchema: {
      type: "object",
      properties: {
        evidence: { type: "string", description: "What you have observed, in your own words" },
        case_id: caseId,
      },
      required: ["evidence"],
      additionalProperties: false,
    },
  },
  {
    name: "ir_search",
    description:
      "Rank authored judgment criteria across the corpus against free-text evidence. Optional playbook filter.",
    annotations: READ,
    inputSchema: {
      type: "object",
      properties: { evidence: { type: "string" }, playbook: { type: "string" }, case_id: caseId },
      required: ["evidence"],
      additionalProperties: false,
    },
  },
  {
    name: "ir_criteria",
    description:
      "Judgment criteria for one attack-chain stage, always with adjacent stages so the stage call stays open.",
    annotations: READ,
    inputSchema: {
      type: "object",
      properties: { stage_ord: { type: "number" }, playbook: { type: "string" }, case_id: caseId },
      required: ["stage_ord"],
      additionalProperties: false,
    },
  },
  {
    name: "ir_hunt",
    description:
      "A hunt brief for one scenario ir_classify returned. Without stage_ord: the threat model, a stage map (hunt counts and platforms per stage), the competing readings and the output contract a finding must meet. With stage_ord: that stage's hunts plus the adjacent stages. Optional platform narrows both. verified mirrors the authored 'tested' date — untested queries are reference, not truth.",
    annotations: READ,
    inputSchema: {
      type: "object",
      properties: {
        playbook: { type: "string", description: "The candidate's playbook, from ir_classify" },
        scenario: {
          type: "string",
          description:
            "The candidate's scenario id, from ir_classify. Required unless the playbook has no scenario branches.",
        },
        platform: { type: "string" },
        stage_ord: { type: "number" },
        case_id: caseId,
      },
      required: ["playbook"],
      additionalProperties: false,
    },
  },
  {
    name: "ir_actions",
    description:
      "Platform action blocks, tier-tagged. Anything not read-only comes back proposal_only:true — a proposal for a human, never a next step.",
    annotations: READ,
    inputSchema: {
      type: "object",
      properties: { playbook: { type: "string" }, platform: { type: "string" }, case_id: caseId },
      additionalProperties: false,
    },
  },
  {
    name: "ir_log",
    description:
      "Record the decision a human actually took and why, so deliveries can be compared against outcomes later. A finding from an ir_hunt brief lands here with its routing. A ruled_out decision must say what ruled it out.",
    annotations: LOCAL_WRITE,
    inputSchema: {
      type: "object",
      properties: {
        decision: { type: "string" },
        rationale: { type: "string" },
        scenario: {
          type: "string",
          description:
            "The brief's reading, as playbook/scenario-<id>. Must name an active scenario.",
        },
        routing: {
          type: "string",
          enum: [...ROUTINGS],
          description: "Where the finding goes — the output contract from ir_hunt",
        },
        criteria_ids: {
          type: "array",
          items: { type: "string" },
          description: "Criterion ids the finding rests on. Unknown ids are rejected.",
        },
        outcomes: {
          type: "object",
          additionalProperties: { type: "string", enum: [...CRITERION_OUTCOMES] },
          description:
            "Per criterion id, what it came to: met, not_met, inconclusive (ran, could not tell) or not_evaluable (could not run — no data or access). Unknown ids are rejected.",
        },
        falsifier: {
          type: "string",
          description:
            "Required when routing is ruled_out: the observation that ruled the reading out, e.g. which discriminator failed and on what evidence.",
        },
        case_id: caseId,
      },
      required: ["decision"],
      additionalProperties: false,
    },
  },
  {
    name: "ir_propose",
    description:
      "Propose a draft criterion from a threat report or incident finding. Writes to the review inbox only — never into served content; a human promotes it with 'bun run review'.",
    annotations: LOCAL_WRITE,
    inputSchema: {
      type: "object",
      properties: {
        playbook: { type: "string", description: "Owning playbook slug" },
        title: { type: "string" },
        why: {
          type: "string",
          description: "The judgment criterion: what the evidence means and what would rule it out",
        },
        source: {
          type: "string",
          description: "Where this came from — advisory id, report URL, incident reference",
        },
        platform: { type: "string" },
        stage_ord: { type: "number" },
        query: { type: "string" },
        case_id: caseId,
      },
      required: ["playbook", "title", "why", "source"],
      additionalProperties: false,
    },
  },
] as const;

export const TOOL_SCHEMAS = withTextLimits(SCHEMAS);

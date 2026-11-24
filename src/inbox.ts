import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { TECHNIQUE_ID } from "./coverage/snapshot.ts";
import { field, strList } from "./emit.ts";
import type { Criterion } from "./types.ts";

export const INBOX = join(import.meta.dir, "..", "criteria", "_inbox");
/** The stage a draft carries until a reviewer names one; promote refuses it. */
export const UNASSIGNED_STAGE = "Unassigned";

export type DraftInput = {
  playbook: string;
  title: string;
  why: string;
  /** Where this came from — advisory id, report URL, incident reference. Required: a criterion without provenance cannot be reviewed. */
  source: string;
  platform?: string;
  stage?: string;
  stage_ord?: number;
  query?: string;
  /** ATT&CK technique ids the source names. Not an MCP input: ir_propose leaves it empty. */
  attack?: string[];
};

// Local copy: src/migrate/text.ts owns the migration's slugify and is deleted with it.
function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

/** Drafts are always status:draft — ir_propose cannot author served content (SPEC: one write path). */
export async function writeDraft(input: DraftInput, inboxDir: string = INBOX): Promise<string> {
  const attack = input.attack ?? [];
  const badId = attack.find((t) => !TECHNIQUE_ID.test(t));
  if (badId !== undefined) {
    throw new Error(
      `draft attack ids must look like T1234 or T1234.001 — got ${JSON.stringify(badId)}`,
    );
  }
  // A title with no Latin letters or digits slugifies to "": the id would end in
  // "/" and promote would refuse it, so such a draft gets a unique placeholder.
  const tag = randomUUID().slice(0, 8);
  // Capped: the slug is part of the filename, and a long title would exceed the name limit.
  const slug = slugify(input.title).slice(0, 80).replace(/-$/, "") || `untitled-${tag}`;
  const criterion: Criterion = {
    id: `${input.playbook}/proposed/${slug}`,
    status: "draft",
    source: input.source,
    validated_at: null,
    supersedes: null,
    stage: input.stage ?? UNASSIGNED_STAGE,
    stage_ord: input.stage_ord ?? 0,
    platform: input.platform ?? "Any",
    title: input.title,
    why: input.why,
    how: null,
    fp: null,
    query: input.query ?? "",
    tested: null,
    attack,
  };
  await mkdir(inboxDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  // The tag keeps two drafts proposed in the same millisecond apart; "wx" refuses
  // to overwrite if they still collide, so a draft is never silently lost.
  const path = join(inboxDir, `${stamp}-${slug}-${tag}.yaml`);
  const lines = [
    "# Draft criterion awaiting human review. Edit freely, then list it with 'bun run review' and",
    "# promote it with 'bun run review --promote <this file> --sha256 <the digest the listing printed>'.",
    field("playbook", input.playbook, ""),
    "criterion:",
    field("id", criterion.id, "  "),
    field("status", criterion.status, "  "),
    field("source", criterion.source, "  "),
    field("validated_at", criterion.validated_at, "  "),
    field("supersedes", criterion.supersedes, "  "),
    field("stage", criterion.stage, "  "),
    field("stage_ord", criterion.stage_ord, "  "),
    field("platform", criterion.platform, "  "),
    field("title", criterion.title, "  "),
    field("why", criterion.why, "  "),
    field("how", criterion.how, "  "),
    field("fp", criterion.fp, "  "),
    field("query", criterion.query, "  "),
    field("tested", criterion.tested, "  "),
    strList("attack", criterion.attack, "  "),
  ];
  await writeFile(path, `${lines.join("\n")}\n`, { flag: "wx" });
  return path;
}

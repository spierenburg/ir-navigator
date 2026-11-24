#!/usr/bin/env bun
// Human CLI, not an MCP surface — stdout is correct here.
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { readdir, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { TECHNIQUE_ID } from "./coverage/snapshot.ts";
import { emitYaml } from "./emit.ts";
import { INBOX, UNASSIGNED_STAGE } from "./inbox.ts";
import { loadCorpus, loadPlaybook, parsePlaybook } from "./load.ts";
import { provenancePath, readProvenance } from "./provenance.ts";
import { closing, openRegular, readBounded, writeAll } from "./regular-file.ts";
import { CONTINUATION, ShownError, show } from "./shown.ts";
import { type Criterion, STATUSES, type Status } from "./types.ts";

export { show } from "./shown.ts";

const CRITERIA = join(import.meta.dir, "..", "criteria");

/** Identity of the file a draft was read from, so a later delete can be pinned to it. */
type FileIdent = { dev: number; ino: number };

/** sha256 hex of the exact bytes a draft was read from: what the listing prints and promote demands. */
type Draft = { playbook: string; criterion: Criterion; ident: FileIdent; digest: string };

async function listDrafts(inboxDir: string = INBOX): Promise<string[]> {
  try {
    return (await readdir(inboxDir))
      .filter((n) => n.endsWith(".yaml"))
      .sort()
      .map((n) => join(inboxDir, n));
  } catch {
    return []; // no inbox directory yet — nothing has ever been proposed
  }
}

/** Largest draft the reviewer will read: 1 MiB. A planted multi-gigabyte file is not a draft. */
const DRAFT_MAX_BYTES = 1 << 20;

/**
 * Read a draft through one checked handle (openRegular, in regular-file.ts).
 * Every reader of a draft — listing, promote, reject — goes through here, so
 * regular-file-ness is decided in one place, and the read is cut at the cap
 * however the file grows.
 */
async function readDraftText(
  path: string,
): Promise<{ text: string; ident: FileIdent; digest: string }> {
  const fh = await openRegular(path, "draft", constants.O_RDONLY);
  return closing(fh, "draft", async () => {
    const { dev, ino } = await fh.stat();
    const bytes = await readBounded(fh, DRAFT_MAX_BYTES);
    if (bytes === null) {
      throw new ShownError(`draft is over 1 MiB (${DRAFT_MAX_BYTES} bytes): ${show(path)}`);
    }
    return {
      text: bytes.toString("utf8"),
      ident: { dev, ino },
      digest: createHash("sha256").update(bytes).digest("hex"),
    };
  });
}

async function readDraft(path: string): Promise<Draft> {
  const { text, ident, digest } = await readDraftText(path);
  const draft = Bun.YAML.parse(text) as Omit<Draft, "ident" | "digest"> | null;
  if (!draft?.playbook || !draft.criterion) throw new ShownError(`not a draft file: ${show(path)}`);
  // The playbook names the file promotion rewrites: a slug, never a path.
  if (typeof draft.playbook !== "string" || !/^[a-z0-9-]+$/.test(draft.playbook)) {
    throw new ShownError(`draft playbook must be a playbook slug: ${errorValue(draft.playbook)}`);
  }
  return { playbook: draft.playbook, criterion: draft.criterion, ident, digest };
}

/**
 * The whole sha256, never a prefix. The AI client writes both the draft that
 * is listed and the one it swaps in, so it needs a collision, not a second
 * preimage: two drafts whose digests agree on n hex digits cost about 2^(2n)
 * hashes, and a 16-digit prefix (2^32) is minutes on a laptop. The full 256
 * bits put that at 2^128.
 */
const DIGEST_HEX = 64;

/**
 * The reviewer approves bytes, not a path: --promote takes the sha256 the
 * listing printed for the draft, and the draft is promoted only if the bytes
 * read now still hash to it. A draft rewritten between the listing and the
 * promote, with the same id, platform and stage and another query, fails
 * here, once the bytes are read and parsed and before the criterion's fields
 * and the playbook are checked. Case and surrounding whitespace are ignored.
 */
function assertApproved(draft: Draft, approved: string, draftPath: string): void {
  const given = approved.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(given) || given.length !== DIGEST_HEX) {
    throw new ShownError(
      `--promote needs the whole sha256 the listing printed (${DIGEST_HEX} hex digits) — got ${errorValue(approved)}`,
    );
  }
  if (draft.digest !== given) {
    throw new ShownError(
      `sha256 mismatch: the draft changed since it was listed, so the approved bytes are not what would be promoted — list again and read it: ${show(draftPath)}`,
    );
  }
}

/**
 * Delete the draft only while the path still names the file that was read
 * and that file still holds the bytes that were read: the inode catches a
 * rename-over, the digest catches a rewrite in place. Both come from one
 * more read through the checked handle, so they describe the same file. The
 * read and the unlink are separate calls, so a change between them stays
 * possible; what this refuses is the change that happened while the reviewer
 * was deciding, which is the window that matters. On a mismatch, or a draft
 * that cannot be read again, nothing is deleted and the reviewer is told why.
 */
export async function unlinkSameFile(
  path: string,
  ident: FileIdent,
  digest: string,
): Promise<void> {
  const now = await readDraftText(path).catch((e: Error) => {
    throw new ShownError(`the draft is left in place, as it cannot be read again — ${e.message}`);
  });
  if (now.ident.dev !== ident.dev || now.ident.ino !== ident.ino || now.digest !== digest) {
    throw new ShownError(
      `the draft file changed since it was read and is left in place: ${show(path)}`,
    );
  }
  // The error carries the path, which the reviewer typed: escaped like every other message.
  await unlink(path).catch((e: NodeJS.ErrnoException) => {
    throw new ShownError(`cannot delete the draft (${e.code ?? "unknown error"}): ${show(path)}`);
  });
}

/** A draft value for an error message: strings quoted so "3" is told apart from 3, all escaped. */
function errorValue(value: unknown, asciiOnly = false): string {
  // Cut by code point before escaping, so an escape or surrogate pair is never split.
  const text = [...(typeof value === "string" ? JSON.stringify(value) : String(value))];
  return show(text.slice(0, 120).join(""), true, asciiOnly) + (text.length > 120 ? "…" : "");
}

/**
 * Promoted fields must have the types the servers read: a 0 or false where a
 * string belongs round-trips through YAML unchanged, so changedFields cannot
 * see it, and the listing would show it as something it is not.
 */
const STRING_FIELDS = ["id", "source", "stage", "platform", "title", "why", "query"] as const;
const NULLABLE_STRING_FIELDS = ["supersedes", "how", "fp", "tested"] as const;
function fieldTypeErrors(c: Criterion): string[] {
  const bad: string[] = [];
  for (const k of STRING_FIELDS) if (typeof c[k] !== "string") bad.push(k);
  for (const k of NULLABLE_STRING_FIELDS) {
    if (c[k] !== null && typeof c[k] !== "string") bad.push(k);
  }
  if (!Array.isArray(c.attack) || !c.attack.every((t) => typeof t === "string")) bad.push("attack");
  // The listing cuts these at 120 characters, so their shape is what makes the cut safe:
  // a padded "2026-10-01      …tail" would otherwise be served past what the reviewer saw.
  if (typeof c.tested === "string" && !ISO_DATE.test(c.tested)) bad.push("tested");
  if (typeof c.supersedes === "string" && !CRITERION_ID.test(c.supersedes)) bad.push("supersedes");
  if (
    Array.isArray(c.attack) &&
    !c.attack.every((t) => typeof t === "string" && TECHNIQUE_ID.test(t))
  ) {
    if (!bad.includes("attack")) bad.push("attack");
  }
  return bad;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

// Ids are printed, logged and matched across the corpus: a plain path-like token.
const CRITERION_ID = /^[a-z0-9]+([a-z0-9._/-]*[a-z0-9])?$/;

/** Fields of the approved criterion that do not read back identically (all of them if it is gone). */
function changedFields(approved: Criterion, reloaded: Criterion | undefined): string[] {
  if (reloaded === undefined) return ["id"];
  const keys = new Set([...Object.keys(approved), ...Object.keys(reloaded)]);
  return [...keys].filter(
    (k) => !Bun.deepEquals(approved[k as keyof Criterion], reloaded[k as keyof Criterion]),
  );
}

/**
 * A draft is served under a platform filter and a stage, so both must be ones
 * the playbook has. Drafts default to platform "Any" and stage_ord 0
 * (unassigned) when the proposer did not place them, so the reviewer assigns
 * them here. Stage names and ords must stay one-to-one with the served
 * criteria, or ir_criteria lists one stage twice or under two names.
 */
function assertPlaced(
  c: Criterion,
  pb: { platforms: string[]; criteria: Criterion[] },
  draftPath: string,
): void {
  const where = `fix it in ${show(draftPath)}`;
  if (!pb.platforms.includes(c.platform)) {
    throw new ShownError(
      `draft platform ${show(c.platform)} is not one of the playbook's: ${pb.platforms.map((p) => show(p)).join(", ")}; ${where}`,
    );
  }
  // Served criteria only, first wins: the same view ir_criteria's stage map gives.
  const stages = new Map<number, string>();
  const ords = new Map<string, number>();
  for (const x of pb.criteria) {
    if (x.status !== "active") continue;
    if (!stages.has(x.stage_ord)) stages.set(x.stage_ord, x.stage);
    if (!ords.has(x.stage)) ords.set(x.stage, x.stage_ord);
  }
  const known = [...stages].sort((a, b) => a[0] - b[0]).map(([o, s]) => `${o} ${show(s)}`);
  if (c.stage_ord < 1 || c.stage === UNASSIGNED_STAGE) {
    throw new ShownError(
      `draft has no stage (stage_ord ${errorValue(c.stage_ord)}, stage ${show(c.stage)}) — set stage_ord and stage, e.g. one of: ${known.join(", ")}; ${where}`,
    );
  }
  const name = stages.get(c.stage_ord);
  if (name !== undefined && name !== c.stage) {
    throw new ShownError(
      `stage_ord ${errorValue(c.stage_ord)} is ${show(name)} in this playbook — got stage ${show(c.stage)}; ${where}`,
    );
  }
  const ord = ords.get(c.stage);
  if (ord !== undefined && ord !== c.stage_ord) {
    throw new ShownError(
      `stage ${show(c.stage)} is stage_ord ${ord} in this playbook — got stage_ord ${errorValue(c.stage_ord)}; ${where}`,
    );
  }
}

/**
 * Human approval is the only path from inbox to served YAML (SPEC: the loop
 * closes through a human). What is approved is the bytes the listing showed,
 * named by their sha256; see assertApproved. Promotion re-emits the owning
 * playbook file, which re-canonicalises it — emitYaml writes the known schema
 * only.
 */
export async function promote(
  draftPath: string,
  approved: string,
  criteriaDir: string = CRITERIA,
): Promise<string> {
  const draft = await readDraft(draftPath);
  assertApproved(draft, approved, draftPath);
  const pbPath = join(criteriaDir, `${draft.playbook}.yaml`);
  const pb = await loadPlaybook(pbPath);
  const promoted: Criterion = {
    ...draft.criterion,
    status: "active",
    validated_at: new Date().toISOString().slice(0, 10),
  };
  if (typeof promoted.id !== "string" || !CRITERION_ID.test(promoted.id)) {
    throw new ShownError(
      `draft id must be lowercase letters, digits and . _ / - — got ${errorValue(promoted.id)}; fix it in ${show(draftPath)}`,
    );
  }
  const mistyped = fieldTypeErrors(promoted);
  if (mistyped.length > 0) {
    throw new ShownError(
      `draft fields have the wrong type (${mistyped.join(", ")}) — text fields must be strings, tested an ISO date (YYYY-MM-DD), supersedes a criterion id, attack a list of technique ids (T1234 or T1234.001); fix it in ${show(draftPath)}`,
    );
  }
  // loadCorpus refuses an id that two playbooks share, so the check spans every
  // playbook; every status too, so a later status change cannot revive a clash.
  const everything = await loadCorpus(criteriaDir, [...STATUSES] as Status[]);
  const clash = everything.criteria.find((c) => c.id === promoted.id);
  if (clash) {
    throw new ShownError(
      `id already exists in ${show(clash.playbook)}: ${show(promoted.id)} — give the draft a new id and set 'supersedes'`,
    );
  }
  if (!Number.isInteger(promoted.stage_ord)) {
    throw new ShownError(
      `draft stage_ord must be an integer — got ${errorValue(promoted.stage_ord)}; fix it in ${show(draftPath)}`,
    );
  }
  assertPlaced(promoted, pb, draftPath);
  pb.criteria.push(promoted);
  const text = emitYaml(pb);
  // Verify before writing: a playbook that no longer loads takes the whole corpus down,
  // and the draft is deleted below. The promoted criterion must also read back exactly
  // as approved — a missing or mistyped field would otherwise be served as "undefined".
  const reloaded = parsePlaybook(text, pbPath).criteria.find((c) => c.id === promoted.id);
  const changed = changedFields(promoted, reloaded);
  if (changed.length > 0) {
    throw new ShownError(
      `${show(draftPath)} would not be served as written (${changed.map((k) => show(k)).join(", ")}) — fix those fields; nothing was changed`,
    );
  }
  await Bun.write(pbPath, text);
  // The playbook now holds what was read. If the draft file is no longer that file, it is not
  // ours to delete: say the promotion happened and leave the new file for the reviewer.
  await unlinkSameFile(draftPath, draft.ident, draft.digest).catch((e: Error) => {
    throw new ShownError(`promoted ${show(promoted.id)}, but ${e.message}`);
  });
  return promoted.id;
}

/**
 * Hard-wraps each line at the terminal width, continuing on an indented line.
 * The terminal's own soft wrap would put whatever follows a run of padding at
 * column 0, where it could pose as a field; a wrapped line here never starts
 * at a field's indentation. Every non-ASCII code point counts as two columns:
 * terminals disagree on ambiguous-width and zero-width characters, and an
 * overestimate only wraps early, while an underestimate lets the terminal wrap.
 */
export function wrap(text: string, width: number): string {
  const limit = Math.max(width, MIN_WIDTH);
  const out: string[] = [];
  for (const line of text.split("\n")) {
    let current = "";
    let used = 0;
    for (const ch of line) {
      const w = (ch.codePointAt(0) ?? 0) < 0x7f ? 1 : 2;
      if (used > 0 && used + w > limit) {
        out.push(current);
        current = CONTINUATION;
        used = CONTINUATION.length;
      }
      current += ch;
      used += w;
    }
    out.push(current);
  }
  return out.join("\n");
}

// Narrower than this, the continuation indent leaves no room and lines overflow.
const MIN_WIDTH = 20;
const PIPED_WIDTH = 40;

/**
 * The inbox as the reviewer reads it. An unreadable draft is listed as such and
 * the listing continues: one bad file must not hide every draft after it.
 */
export async function reviewListing(inboxDir: string = INBOX, width = 80): Promise<string[]> {
  const drafts = await listDrafts(inboxDir);
  if (drafts.length === 0) return ["inbox empty — nothing awaiting review"];
  const lines: string[] = [];
  for (const p of drafts) {
    try {
      const d = await readDraft(p);
      lines.push(draftLines(d, p, width).join("\n"));
    } catch (e) {
      lines.push(wrap(`\n${show(p)}\n  unreadable: ${errorValue((e as Error).message)}`, width));
    }
  }
  return lines;
}

/**
 * Every field promote serves, as the reviewer sees it, and the sha256 that
 * --promote takes: the reviewer approves what analysts will run. Free text
 * starts on its own indented line, so no value can imitate the label line of
 * another field or a "(none)" marker.
 */
function attackLine(attack: unknown): string {
  if (!Array.isArray(attack)) return `(not a list) ${errorValue(attack)}`;
  return attack.length === 0 ? "(none)" : attack.map((t) => errorValue(t, true)).join(", ");
}

/** A draft's listing, each entry wrapped to the width except the one built whole. */
function draftLines(d: Draft, path: string, width: number): string[] {
  const c = d.criterion;
  const w = (s: string) => wrap(s, width);
  const text = (label: string, v: unknown, asciiOnly = false) => {
    if (v === null || v === undefined || v === "") return w(`  ${label}: (none)`);
    if (typeof v !== "string") return w(`  ${label}: (not text) ${errorValue(v)}`);
    return w(`  ${label}:\n${CONTINUATION}${show(v, true, asciiOnly)}`);
  };
  return [
    w(`\n${show(path)}`),
    w(`  [${d.playbook}] ${show(c.title)}`),
    w(`  id: ${show(c.id)}`),
    // What --promote takes: the reviewer approves these bytes, not the path. Printed whole at
    // any width, since a digest split by wrap() would be copied in two pieces; it is hex only,
    // so it can pose as nothing if the terminal wraps it.
    `  sha256: ${d.digest}`,
    // Platform, stage and attack ids are matched exactly: a lookalike would hide the criterion.
    w(
      `  platform: ${show(c.platform, true, true)} · stage ${errorValue(c.stage_ord)} ${show(c.stage, true, true)}`,
    ),
    w(`  tested: ${errorValue(c.tested)} · supersedes: ${errorValue(c.supersedes)}`),
    w(`  attack: ${attackLine(c.attack)}`),
    text("source", c.source),
    text("why", c.why),
    text("how", c.how),
    text("fp", c.fp),
    // The query runs as written: non-ASCII is escaped so a lookalike letter or
    // space cannot pass for the ASCII one the reviewer expects.
    text("query", c.query, true),
  ];
}

/** Rejected drafts, one JSON line each, kept beside the drafts as local inbox state. */
const REJECTED = "rejected.jsonl";

/**
 * Delete a draft the reviewer turned down, recording its playbook, source and
 * title first so the decision is on the record. Nothing in this repo reads the
 * record back; it is an audit line for the reviewer. Only a draft in the inbox
 * can be rejected, and only into a regular record file.
 */
export async function reject(draftPath: string, inboxDir: string = INBOX): Promise<string> {
  // A path that does not resolve (no inbox yet, no such directory) is not in the inbox either.
  const realInbox = await realpath(inboxDir).catch(() => null);
  const parent = await realpath(dirname(draftPath)).catch(() => null);
  if (realInbox === null || parent !== realInbox) {
    throw new ShownError(`only a draft in the inbox can be rejected: ${show(draftPath)}`);
  }
  // From here on, the resolved inbox plus the entry name, never the path as typed: a
  // directory symlink swapped in after the check cannot redirect the read or the unlink.
  const entryPath = join(realInbox, basename(draftPath));
  // The record is a regular file in the inbox too, so the suffix is what keeps it
  // from being "rejected". Whether the path is a regular file, and not a symlink
  // whose target would be recorded while only the link is removed, is decided by
  // readDraft's open, atomically with the read.
  if (!entryPath.endsWith(".yaml")) throw new ShownError(`not a draft file: ${show(draftPath)}`);
  const d = await readDraft(entryPath);
  const { source, title } = d.criterion as { source: unknown; title: unknown };
  if (typeof source !== "string" || typeof title !== "string") {
    throw new ShownError(
      `draft source and title must be text to record a rejection: ${show(draftPath)}`,
    );
  }
  const entry = { playbook: d.playbook, source, title, rejected_at: new Date().toISOString() };
  // A symlink planted as the record must not redirect the append, and a FIFO
  // planted there must not hang it: openRegular refuses both.
  const fh = await openRegular(
    join(inboxDir, REJECTED),
    REJECTED,
    constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT,
    0o644,
  );
  await closing(fh, REJECTED, () =>
    writeAll(fh, Buffer.from(`${JSON.stringify(entry)}\n`), REJECTED),
  );
  // The record names what was read; delete only if the entry is still that file. The record
  // line is already appended, so say so: a second --reject would append it again.
  await unlinkSameFile(entryPath, d.ident, d.digest).catch((e: Error) => {
    throw new ShownError(`rejected ${show(d.criterion.id)} and recorded it, but ${e.message}`);
  });
  return d.criterion.id;
}

type LogRow = {
  tool?: string;
  error?: string;
  args?: { criteria_ids?: unknown; outcomes?: unknown };
  surfaced?: Record<string, unknown>;
};

/** Surfaced this often and never cited, a criterion is shown without being used. */
const STALE_MIN_SURFACED = 3;
/** Outcome counts below this say nothing about a criterion either way. */
const MIN_OUTCOMES = 2;

const bump = (m: Map<string, number>, id: string) => m.set(id, (m.get(id) ?? 0) + 1);

/**
 * SPEC architecture: review --stale. Counts only — every line feeds the human
 * promote/retire decision; nothing here re-ranks what is served (SPEC
 * invariant 1: outcome history folded into ranking starves the rare reading).
 */
export function staleReport(criteria: { id: string }[], logText: string): string[] {
  const surfaced = new Map<string, number>();
  const cited = new Map<string, number>();
  const outcomes = new Map<string, Map<string, number>>();
  let unreadable = 0;
  for (const line of logText.split("\n")) {
    if (line.trim().length === 0) continue;
    const row = parseRow(line);
    // One torn line (an interrupted append) must not take the whole report down; it is counted instead.
    if (row === null) {
      unreadable += 1;
      continue;
    }
    if (row.error !== undefined) continue; // a refused call surfaced and recorded nothing
    for (const [key, value] of Object.entries(row.surfaced ?? {})) {
      if (!key.endsWith("_ids") || !Array.isArray(value)) continue;
      for (const id of value) bump(surfaced, String(id));
    }
    if (row.tool !== "ir_log") continue;
    const ids = Array.isArray(row.args?.criteria_ids) ? row.args.criteria_ids.map(String) : [];
    const oc = (row.args?.outcomes ?? {}) as Record<string, unknown>;
    for (const id of new Set([...ids, ...Object.keys(oc)])) bump(cited, id);
    for (const [id, value] of Object.entries(oc)) {
      const per = outcomes.get(id) ?? new Map<string, number>();
      bump(per, String(value));
      outcomes.set(id, per);
    }
  }

  const total = (id: string) => [...(outcomes.get(id)?.values() ?? [])].reduce((a, b) => a + b, 0);
  const count = (id: string, o: string) => outcomes.get(id)?.get(o) ?? 0;
  const evaluated = (id: string) => total(id) - count(id, "not_evaluable");
  const sections: [string, { id: string }[], (id: string) => string][] = [
    ["never surfaced since the log began", criteria.filter((c) => !surfaced.has(c.id)), () => ""],
    [
      `surfaced ${STALE_MIN_SURFACED}+ times, never cited in an ir_log decision`,
      criteria.filter((c) => (surfaced.get(c.id) ?? 0) >= STALE_MIN_SURFACED && !cited.has(c.id)),
      (id) => ` (surfaced ${surfaced.get(id)})`,
    ],
    [
      "mostly not_evaluable — the query needs data that was not there",
      criteria.filter(
        (c) => total(c.id) >= MIN_OUTCOMES && count(c.id, "not_evaluable") * 2 > total(c.id),
      ),
      (id) => ` (${count(id, "not_evaluable")}/${total(id)})`,
    ],
    [
      // Only runs that could evaluate: a missing data source says nothing about the criterion.
      "never met in a logged outcome it could be evaluated in",
      criteria.filter((c) => evaluated(c.id) >= MIN_OUTCOMES && count(c.id, "met") === 0),
      (id) => ` (0/${evaluated(id)} met)`,
    ],
  ];
  const lines: string[] = [];
  for (const [title, hits, detail] of sections) {
    lines.push(`${hits.length}/${criteria.length} active criteria ${title}`);
    for (const c of hits) lines.push(`  ${show(c.id)}${detail(c.id)}`);
  }
  if (unreadable > 0) lines.push(`${unreadable} log line(s) unreadable and skipped`);
  return lines;
}

function parseRow(line: string): LogRow | null {
  try {
    const row = JSON.parse(line) as unknown;
    return row !== null && typeof row === "object" && !Array.isArray(row) ? (row as LogRow) : null;
  } catch {
    return null;
  }
}

async function stale(): Promise<void> {
  const corpus = await loadCorpus(CRITERIA);
  const text = await readProvenance(provenancePath());
  for (const line of staleLines(corpus.criteria, text, provenancePath())) console.log(line);
}

/**
 * The --stale output for a log that was read, or for none (null). A log that
 * is gone reads as every criterion never surfaced: say so first, rather than
 * let a removed or moved log pass for an empty one.
 */
export function staleLines(
  criteria: { id: string }[],
  logText: string | null,
  logPath: string,
): string[] {
  const note =
    logText === null
      ? [`no provenance log at ${show(logPath)} — every criterion below reads as never surfaced`]
      : [];
  return [...note, ...staleReport(criteria, logText ?? "")];
}

if (import.meta.main) {
  const [cmd, arg, flag, flagValue] = process.argv.slice(2);
  // --inbox: a draft written to another inbox directory is rejected there, where its record lives.
  const inboxArg = flag === "--inbox" && flagValue ? flagValue : INBOX;
  try {
    if (cmd === "--promote" && arg) {
      // --sha256 is not optional: without it promote would approve whatever is at the path now.
      if (flag !== "--sha256" || !flagValue) {
        throw new ShownError(
          "usage: review --promote <draft> --sha256 <the 64 hex digits the listing printed>",
        );
      }
      const id = await promote(arg, flagValue);
      console.log(
        `promoted ${show(id)} — now run 'bun run build:index' and commit the YAML and index together`,
      );
    } else if (cmd === "--reject" && arg) {
      const id = await reject(arg, inboxArg);
      console.log(`rejected ${show(id)} — recorded in ${REJECTED}`);
    } else if (cmd === "--stale") {
      await stale();
    } else {
      // Piped (to a pager, say), the real width is unknown: wrap narrow enough that
      // the pager never wraps again and pushes padded text to a field's indentation.
      const width = process.stdout.isTTY ? process.stdout.columns : PIPED_WIDTH;
      for (const line of await reviewListing(INBOX, width)) {
        console.log(line);
      }
    }
  } catch (e) {
    // Errors can carry corpus or draft text, which Bun would print raw. Messages
    // promote built with show() are escaped already; any other is escaped here.
    const msg = (e as Error).message;
    console.error(`review: ${e instanceof ShownError ? msg : show(msg)}`);
    process.exit(1);
  }
}

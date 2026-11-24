import { expect, test } from "bun:test";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { loadIndex } from "../src/index/load.ts";
import { loadCorpus } from "../src/load.ts";
import { appendProvenance, readProvenance } from "../src/provenance.ts";
import { type Ctx, handleTool } from "../src/tools.ts";
import { tmp } from "./fixtures.ts";

const root = join(import.meta.dir, "..");
const entry = { ts: "2026-10-31T00:00:00.000Z", tool: "ir_search", args: { q: "x" }, surfaced: {} };

test("the log is created 0600, an older 0644 log is tightened, and rows go through a checked handle", async () => {
  const dir = tmp({ "old.jsonl": "" });
  const log = join(dir, "provenance.jsonl");
  const old = join(dir, "old.jsonl");
  chmodSync(old, 0o644);
  try {
    await appendProvenance(log, entry);
    await appendProvenance(log, { ...entry, error: "refused" });
    expect(statSync(log).mode & 0o777).toBe(0o600);
    const rows = readFileSync(log, "utf8").trim().split("\n");
    expect(rows).toHaveLength(2);
    expect(JSON.parse(rows[1] ?? "")).toMatchObject({ schema_version: 2, error: "refused" });
    expect(await readProvenance(log)).toBe(readFileSync(log, "utf8"));
    // A log created by an older build at 0644 is 0600 after its next row.
    await appendProvenance(old, entry);
    expect(statSync(old).mode & 0o777).toBe(0o600);
    expect(readFileSync(old, "utf8").trim().split("\n")).toHaveLength(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a hard link planted at the log path is refused: a row must not reach a file with another name", async () => {
  const dir = tmp({ "victim.txt": "secret\n" });
  const link = join(dir, "provenance.jsonl");
  linkSync(join(dir, "victim.txt"), link);
  try {
    await expect(appendProvenance(link, entry)).rejects.toThrow(
      /provenance log has 2 hard links and was not written/,
    );
    expect(readFileSync(join(dir, "victim.txt"), "utf8")).toBe("secret\n");
    // Reading is not writing: --stale may read a linked log.
    expect(await readProvenance(link)).toBe("secret\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a symlink, a FIFO or a directory planted at the log path is refused by the append and the read", async () => {
  const dir = tmp({ "target.txt": "untouched\n" });
  const link = join(dir, "link.jsonl");
  const pipe = join(dir, "pipe.jsonl");
  const sub = join(dir, "dir.jsonl");
  symlinkSync(join(dir, "target.txt"), link);
  expect(Bun.spawnSync(["mkfifo", pipe]).exitCode).toBe(0);
  mkdirSync(sub);
  try {
    // The link is never followed: nothing lands in the file it points at.
    await expect(appendProvenance(link, entry)).rejects.toThrow(
      /provenance log is not a regular file \(ELOOP\)/,
    );
    await expect(readProvenance(link)).rejects.toThrow(/provenance log is not a regular file/);
    expect(readFileSync(join(dir, "target.txt"), "utf8")).toBe("untouched\n");
    // A FIFO with no reader cannot hang the open; a directory cannot be written or read as a log.
    await expect(appendProvenance(pipe, entry)).rejects.toThrow(/provenance log/);
    await expect(readProvenance(pipe)).rejects.toThrow(/provenance log/);
    await expect(appendProvenance(sub, entry)).rejects.toThrow(/provenance log/);
    await expect(readProvenance(sub)).rejects.toThrow(/provenance log/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the read is null for a log that does not exist and refuses one over the cap", async () => {
  const dir = tmp({ "big.jsonl": "x".repeat(17), "fits.jsonl": "x".repeat(16) });
  try {
    expect(await readProvenance(join(dir, "none.jsonl"))).toBeNull();
    expect(await readProvenance(join(dir, "nodir", "none.jsonl"))).toBeNull();
    expect(await readProvenance(join(dir, "fits.jsonl"), 16)).toBe("x".repeat(16));
    await expect(readProvenance(join(dir, "big.jsonl"), 16)).rejects.toThrow(
      /provenance log is over the 0 MiB cap \(16 bytes\) and was not read — rotate it/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a delivery fails rather than log through a planted symlink, and the target stays empty", async () => {
  const dir = tmp({ "target.txt": "" });
  const link = join(dir, "provenance.jsonl");
  symlinkSync(join(dir, "target.txt"), link);
  try {
    const corpus = await loadCorpus(join(root, "criteria"));
    const ctx: Ctx = {
      corpus,
      index: await loadIndex(join(root, "index", "vectors.json"), corpus),
      embed: async () => null,
      inboxDir: join(dir, "_inbox"),
      provenanceLog: link,
      coverage: null,
    };
    // The same call delivers when the log is a real file: the refusal below is the log's, not the tool's.
    const real = { ...ctx, provenanceLog: join(dir, "real.jsonl") };
    expect(await handleTool("ir_search", { evidence: "mshta" }, real)).toBeDefined();
    expect(readFileSync(join(dir, "real.jsonl"), "utf8")).toContain('"tool":"ir_search"');
    await expect(handleTool("ir_search", { evidence: "mshta" }, ctx)).rejects.toThrow(
      /^provenance log is not a regular file \(ELOOP\)/,
    );
    expect(readFileSync(join(dir, "target.txt"), "utf8")).toBe("");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

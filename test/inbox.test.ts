import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { writeDraft } from "../src/inbox.ts";
import { loadIndex } from "../src/index/load.ts";
import { loadCorpus } from "../src/load.ts";
import { promote, reject, reviewListing, unlinkSameFile } from "../src/review.ts";
import { type Ctx, handleTool } from "../src/tools.ts";
import type { Criterion } from "../src/types.ts";
import { DEMO_PLAYBOOK, tmp } from "./fixtures.ts";

const root = join(import.meta.dir, "..");

/** A platform and stage the demo playbook has, so promote can place the draft. */
const PLACED = { platform: "Defender XDR / Sentinel", stage: "Stage 2 · Foothold", stage_ord: 2 };

async function ctxWithInbox(inboxDir: string): Promise<Ctx> {
  const corpus = await loadCorpus(join(root, "criteria"));
  return {
    corpus,
    index: await loadIndex(join(root, "index", "vectors.json"), corpus),
    embed: async () => null,
    inboxDir,
    provenanceLog: join(inboxDir, "provenance.jsonl"),
    coverage: null,
  };
}

const yamlIn = (dir: string) => readdirSync(dir).filter((n) => n.endsWith(".yaml"));

/** The digest the listing prints: sha256 of the draft's bytes as they are on disk now. */
const sha = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");

/** Promote as the reviewer does after reading the listing: approving these bytes, not the path. */
const approve = (path: string, criteriaDir: string) => promote(path, sha(path), criteriaDir);

const rmAll = (...dirs: string[]) => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
};

test("a symlink, a FIFO or an oversized draft is refused by every reader, never followed", async () => {
  const parent = tmp({});
  const inbox = join(parent, "_inbox");
  const elsewhere = tmp({});
  const criteriaDir = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  try {
    // A symlink planted in the inbox: its target is a well-formed draft outside it. Following it
    // would promote content the reviewer never listed.
    const target = await writeDraft(
      { playbook: "demo", title: "Linked", why: "w", source: "s", ...PLACED },
      elsewhere,
    );
    mkdirSync(inbox, { recursive: true });
    symlinkSync(target, join(inbox, "link.yaml"));
    await expect(approve(join(inbox, "link.yaml"), criteriaDir)).rejects.toThrow(
      /not a regular file/,
    );
    expect(await Bun.file(target).exists()).toBe(true);
    // A FIFO must not hang the open, and must not read as a draft, for promote or for reject.
    expect(Bun.spawnSync(["mkfifo", join(inbox, "pipe.yaml")]).exitCode).toBe(0);
    // No digest can be read from a FIFO without blocking; the open is what has to refuse it.
    await expect(promote(join(inbox, "pipe.yaml"), "0".repeat(64), criteriaDir)).rejects.toThrow(
      /not a regular file/,
    );
    await expect(reject(join(inbox, "pipe.yaml"), inbox)).rejects.toThrow(/not a regular file/);
    expect(await Bun.file(join(inbox, "rejected.jsonl")).exists()).toBe(false);
    // The cap is on what is read: one byte over 1 MiB is refused on size, exactly 1 MiB is read
    // in full and then fails as a draft (a megabyte of spaces parses to nothing), not on size.
    writeFileSync(join(inbox, "big.yaml"), Buffer.alloc((1 << 20) + 1, 0x20));
    await expect(approve(join(inbox, "big.yaml"), criteriaDir)).rejects.toThrow(/over 1 MiB/);
    writeFileSync(join(inbox, "max.yaml"), Buffer.alloc(1 << 20, 0x20));
    await expect(approve(join(inbox, "max.yaml"), criteriaDir)).rejects.toThrow(/not a draft file/);
    const listing = (await reviewListing(inbox, 1000)).join("\n");
    for (const name of ["link.yaml", "pipe.yaml", "big.yaml", "max.yaml"]) {
      // The entry's own line, not a later entry's: the listing prints "<path>\n  unreadable: …".
      expect(listing).toMatch(new RegExp(`${name.replace(".", "\\.")}\\n  unreadable:`));
    }
  } finally {
    rmAll(parent, elsewhere, criteriaDir);
  }
});

test("promote takes the sha256 the listing printed and refuses any other bytes", async () => {
  const parent = tmp({});
  const inbox = join(parent, "_inbox");
  const criteriaDir = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  try {
    const path = await writeDraft(
      { playbook: "demo", title: "Pinned", why: "w", source: "s", ...PLACED },
      inbox,
    );
    const digest = sha(path);
    const listing = (await reviewListing(inbox, 1000)).join("\n");
    expect(listing).toContain(`  sha256: ${digest}`);
    // The digest line is never wrapped, even at the narrowest width: it is copied whole.
    expect((await reviewListing(inbox, 20)).join("\n")).toContain(`\n  sha256: ${digest}\n`);
    // A wrong or malformed digest refuses with the format message, and nothing changes.
    for (const bad of ["x".repeat(64), `${digest}a`, "not-hex-at-all!!", ""]) {
      await expect(promote(path, bad, criteriaDir)).rejects.toThrow(/whole sha256/);
    }
    // A prefix refuses too, however long: the client that writes both drafts can search a
    // collision on a prefix, so no short form is accepted.
    for (const prefix of [digest.slice(0, 16), digest.slice(0, 32), digest.slice(0, 63)]) {
      await expect(promote(path, prefix, criteriaDir)).rejects.toThrow(/whole sha256/);
    }
    // The right length and wrong bytes is a mismatch, not a format error.
    await expect(promote(path, "0".repeat(64), criteriaDir)).rejects.toThrow(
      /changed since it was listed/,
    );
    expect(await Bun.file(path).exists()).toBe(true);
    expect(await Bun.file(join(criteriaDir, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
    // The draft is rewritten after the listing: same id, platform and stage, other content.
    // The digest the reviewer approved no longer names these bytes.
    writeFileSync(path, (await Bun.file(path).text()).replace("Pinned", "Swapped"));
    await expect(promote(path, digest, criteriaDir)).rejects.toThrow(/changed since it was listed/);
    expect(await Bun.file(join(criteriaDir, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
    // A fresh listing gives the new digest; the whole of it, in any case and padded, does.
    const fresh = sha(path);
    expect(fresh).not.toBe(digest);
    expect(await promote(path, ` ${fresh.toUpperCase()}\n`, criteriaDir)).toBe(
      "demo/proposed/pinned",
    );
    expect(await Bun.file(path).exists()).toBe(false);
  } finally {
    rmAll(parent, criteriaDir);
  }
});

test("the CLI refuses --promote without --sha256 before touching the draft", () => {
  const parent = tmp({});
  const draft = join(parent, "never-opened.yaml");
  try {
    for (const argv of [
      ["--promote", draft],
      ["--promote", draft, "--sha256"],
      ["--promote", draft, "--inbox", parent, "--sha256", "0".repeat(64)],
    ]) {
      const run = Bun.spawnSync(["bun", "src/review.ts", ...argv], {
        cwd: root,
      });
      expect(run.exitCode).not.toBe(0);
      expect(run.stderr.toString()).toContain("usage: review --promote <draft> --sha256");
    }
  } finally {
    rmAll(parent);
  }
});

test("the draft is deleted only while it is the file that was read, with the bytes that were read", async () => {
  const dir = tmp({ "d.yaml": "playbook: demo\n", "other.yaml": "playbook: other\n" });
  const path = join(dir, "d.yaml");
  const ident = () => {
    const { dev, ino } = statSync(path);
    return { dev, ino };
  };
  try {
    const read = { ident: ident(), digest: sha(path) };
    // Rewritten in place: same inode, other bytes. Left in place.
    writeFileSync(path, "playbook: demo # edited\n");
    await expect(unlinkSameFile(path, read.ident, read.digest)).rejects.toThrow(
      /changed since it was read and is left in place/,
    );
    expect(readFileSync(path, "utf8")).toBe("playbook: demo # edited\n");
    // Renamed over: same bytes as read, other inode. Left in place.
    const again = { ident: ident(), digest: sha(path) };
    writeFileSync(join(dir, "other.yaml"), "playbook: demo # edited\n");
    renameSync(join(dir, "other.yaml"), path);
    expect(sha(path)).toBe(again.digest);
    await expect(unlinkSameFile(path, again.ident, again.digest)).rejects.toThrow(
      /changed since it was read/,
    );
    // Gone, or not readable as a draft: says why, deletes nothing.
    const now = { ident: ident(), digest: sha(path) };
    rmSync(path);
    await expect(unlinkSameFile(path, now.ident, now.digest)).rejects.toThrow(
      /cannot be read again.*cannot open draft \(ENOENT\)/,
    );
    // The file that was read, unchanged: deleted.
    writeFileSync(path, "playbook: demo\n");
    await unlinkSameFile(path, ident(), sha(path));
    expect(yamlIn(dir)).toEqual([]);
  } finally {
    rmAll(dir);
  }
});

test("reject deletes the draft and appends one record line", async () => {
  const parent = tmp({});
  const inbox = join(parent, "_inbox");
  try {
    const draft = await writeDraft(
      { playbook: "demo", title: "Declined", why: "w", source: "advisory:X" },
      inbox,
    );
    const id = await reject(draft, inbox);
    expect(id).toBe("demo/proposed/declined");
    expect(await Bun.file(draft).exists()).toBe(false);
    const lines = (await Bun.file(join(inbox, "rejected.jsonl")).text()).trim().split("\n");
    expect(lines).toHaveLength(1);
    const rec = JSON.parse(lines[0] as string);
    expect(rec).toMatchObject({ playbook: "demo", source: "advisory:X", title: "Declined" });
    expect(typeof rec.rejected_at).toBe("string");
  } finally {
    rmAll(parent);
  }
});

test("reject refuses a draft outside the inbox and a symlinked record", async () => {
  const parent = tmp({});
  const inbox = join(parent, "_inbox");
  const elsewhere = tmp({});
  try {
    const outsidePath = await writeDraft(
      { playbook: "demo", title: "t", why: "w", source: "s" },
      elsewhere,
    );
    await expect(reject(outsidePath, inbox)).rejects.toThrow(/only a draft in the inbox/);
    const inside = await writeDraft({ playbook: "demo", title: "t", why: "w", source: "s" }, inbox);
    const target = join(elsewhere, "target.txt");
    writeFileSync(target, "");
    symlinkSync(target, join(inbox, "rejected.jsonl"));
    await expect(reject(inside, inbox)).rejects.toThrow();
    expect(await Bun.file(target).text()).toBe("");
    expect(yamlIn(inbox)).toHaveLength(1);
  } finally {
    rmAll(parent, elsewhere);
  }
});

test("reject refuses the record itself, a symlinked draft, and a FIFO record", async () => {
  const parent = tmp({});
  const inbox = join(parent, "_inbox");
  const outsideDir = tmp({});
  try {
    const draft = await writeDraft({ playbook: "demo", title: "t", why: "w", source: "s" }, inbox);
    writeFileSync(
      join(inbox, "rejected.jsonl"),
      '{"playbook":"demo","source":"s","title":"x","criterion":{}}\n',
    );
    await expect(reject(join(inbox, "rejected.jsonl"), inbox)).rejects.toThrow(/not a draft file/);
    const outside = await writeDraft(
      { playbook: "demo", title: "o", why: "w", source: "s" },
      outsideDir,
    );
    symlinkSync(outside, join(inbox, "link.yaml"));
    await expect(reject(join(inbox, "link.yaml"), inbox)).rejects.toThrow(/not a regular file/);
    rmSync(join(inbox, "rejected.jsonl"));
    // The FIFO is the fixture; a missing mkfifo must fail here, not as a wrong reject verdict.
    expect(Bun.spawnSync(["mkfifo", join(inbox, "rejected.jsonl")]).exitCode).toBe(0);
    await expect(reject(draft, inbox)).rejects.toThrow(/rejected\.jsonl/);
    expect(await Bun.file(draft).exists()).toBe(true);
  } finally {
    rmAll(parent, outsideDir);
  }
});

test("writeDraft lands in the inbox as parseable YAML, status always draft", async () => {
  const d = tmp({});
  const path = await writeDraft(
    {
      playbook: "demo",
      title: "Fake CAPTCHA paste chain",
      why: "ClickFix lures have the user paste an encoded command themselves.",
      source: "advisory:AA26-123A",
      query: "DeviceProcessEvents | take 5",
    },
    d,
  );
  const draft = Bun.YAML.parse(await Bun.file(path).text()) as {
    playbook: string;
    criterion: Criterion;
  };
  expect(draft.playbook).toBe("demo");
  expect(draft.criterion.status).toBe("draft");
  expect(draft.criterion.source).toBe("advisory:AA26-123A");
  expect(draft.criterion.query).toContain("take 5");
  rmSync(d, { recursive: true, force: true });
});

test("a draft in criteria/_inbox/ is invisible to loadCorpus", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  mkdirSync(join(d, "_inbox"));
  writeFileSync(join(d, "_inbox", "x.yaml"), 'anything: "at all"\n');
  const c = await loadCorpus(d);
  expect(c.playbooks).toHaveLength(1);
  expect(c.criteria).toHaveLength(1);
  rmSync(d, { recursive: true, force: true });
});

test("ir_propose writes to the inbox only, and requires a source", async () => {
  const d = tmp({});
  const c = await ctxWithInbox(d);
  const before = c.corpus.criteria.length;
  const r = (await handleTool(
    "ir_propose",
    { playbook: "ransomware-response", title: "t", why: "w", source: "s" },
    c,
  )) as { draft: string };
  expect(r.draft).toContain(d);
  // served corpus untouched — the draft exists only in the inbox
  expect((await loadCorpus(join(root, "criteria"))).criteria).toHaveLength(before);
  await expect(
    handleTool("ir_propose", { playbook: "ransomware-response", title: "t", why: "w" }, c),
  ).rejects.toThrow(/source/i);
  rmSync(d, { recursive: true, force: true });
});

test("promote appends to the owning playbook as active with validated_at set, and empties the inbox", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const draftPath = await writeDraft(
    {
      playbook: "demo",
      title: "Fake CAPTCHA paste chain",
      why: "ClickFix lures.",
      source: "advisory:AA26-123A",
      ...PLACED,
    },
    join(d, "_inbox"),
  );
  const id = await approve(draftPath, d);
  const promoted = (await loadCorpus(d)).criteria.find((c) => c.id === id);
  expect(promoted?.status).toBe("active");
  expect(promoted?.validated_at).not.toBeNull();
  expect(promoted?.source).toBe("advisory:AA26-123A");
  expect(await Bun.file(draftPath).exists()).toBe(false);
  rmSync(d, { recursive: true, force: true });
});

test("free text with YAML line breaks cannot forge draft fields", async () => {
  const d = tmp({});
  const forge =
    'q\n\r  id: phishing-response/x\n\r  tested: "2026-01-01"\n\r  attack: ["T1486"]\n\rplaybook: phishing-response\n\rtrailer:';
  const path = await writeDraft(
    { playbook: "demo", title: "t", why: "w", source: "s", query: forge },
    join(d, "_inbox"),
  );
  const draft = Bun.YAML.parse(await Bun.file(path).text()) as {
    playbook: string;
    criterion: Criterion;
  };
  expect(draft.playbook).toBe("demo");
  expect(draft.criterion.id).toBe("demo/proposed/t");
  expect(draft.criterion.tested).toBeNull();
  expect(draft.criterion.attack).toEqual([]);
  expect(draft.criterion.query).toBe(forge);
  rmSync(d, { recursive: true, force: true });
});

test("every text field round-trips exactly, whatever line breaks it carries", async () => {
  const d = tmp({});
  const values = [
    "a\rb",
    "a\r\nb",
    "a\u0085b",
    "a\u2028b",
    "a\u2029b",
    "x\ny\u2028z",
    "  indented first\nsecond",
    "\n  indented after a blank line\nless indented",
    "\n ",
    "ends with a newline\n",
    "a\n\n  b",
    "nul in a block\n\u0000",
  ];
  for (const v of values) {
    const path = await writeDraft(
      { playbook: "demo", title: v, why: v, source: "s", query: v },
      join(d, "_inbox"),
    );
    const c = (Bun.YAML.parse(await Bun.file(path).text()) as { criterion: Criterion }).criterion;
    expect([c.title, c.why, c.query]).toEqual([v, v, v]);
  }
  rmSync(d, { recursive: true, force: true });
});

test("a lone surrogate is written as U+FFFD, and the draft still parses", async () => {
  const d = tmp({});
  for (const v of ["\ud800 single line", "first\n\ud800 second"]) {
    const path = await writeDraft(
      { playbook: "demo", title: "t", why: "w", source: "s", query: v },
      join(d, "_inbox"),
    );
    const c = (Bun.YAML.parse(await Bun.file(path).text()) as { criterion: Criterion }).criterion;
    expect(c.query).toBe(v.toWellFormed());
  }
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses a draft whose playbook is not a slug", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  mkdirSync(join(d, "_inbox"), { recursive: true });
  const draftPath = join(d, "_inbox", "x.yaml");
  writeFileSync(draftPath, 'playbook: "../demo"\ncriterion:\n  id: "x"\n');
  await expect(approve(draftPath, d)).rejects.toThrow(/slug/);
  expect(await Bun.file(draftPath).exists()).toBe(true);
  rmSync(d, { recursive: true, force: true });
});

/** A draft written by writeDraft, then hand-edited the way a reviewer would. */
async function editedDraft(d: string, edit: (text: string) => string): Promise<string> {
  const path = await writeDraft(
    { playbook: "demo", title: "t", why: "w", source: "s", ...PLACED },
    join(d, "_inbox"),
  );
  writeFileSync(path, edit(await Bun.file(path).text()));
  return path;
}

test("promote refuses a hand-edited id that is not a plain token, and changes nothing", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const esc = String.fromCharCode(0x1b);
  for (const bad of ["demo/a\\nb", `demo/x${esc}]0;pwn`, "Demo/Upper", "demo/trailing/"]) {
    const path = await editedDraft(d, (t) =>
      t.replace(/^ {2}id: .*$/m, `  id: ${JSON.stringify(bad)}`),
    );
    const err = await approve(path, d).catch((e: Error) => e.message);
    expect(err).toContain("draft id must be");
    expect(err).not.toContain(esc);
    expect(await Bun.file(path).exists()).toBe(true);
  }
  expect(await Bun.file(join(d, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
  rmSync(d, { recursive: true, force: true });
});

test("show escapes backslashes and hidden characters, and keeps spaces as written", async () => {
  const { show } = await import("../src/review.ts");
  expect(show("a\\u{1b}b")).toBe("a\\\\u{1b}b");
  expect(show(`x${String.fromCharCode(0x202e)}y`)).toBe("x\\u{202e}y");
  expect(show(`x${String.fromCharCode(0x200b)}y`)).toBe("x\\u{200b}y");
  expect(show(`x${String.fromCharCode(0xd800)}y`)).toBe("x\\u{d800}y");
  expect(show('has "-enc  JAB"')).toBe('has "-enc  JAB"');
});

test("wrap never lets padding push text to a field's indentation", async () => {
  const { wrap } = await import("../src/review.ts");
  for (const pad of [" ", String.fromCharCode(0xa0), String.fromCharCode(0x3000)]) {
    const out = wrap(`  [demo] Benign${pad.repeat(70)}  source: forged`, 80);
    const lines = out.split("\n");
    expect(lines.slice(1).every((l) => l.startsWith("      "))).toBe(true);
    expect(lines.every((l) => Bun.stringWidth(l) <= 80)).toBe(true);
  }
});

test("wrap counts non-ASCII as two columns, so ambiguous-width text cannot overflow", async () => {
  const { wrap } = await import("../src/review.ts");
  const dot = String.fromCharCode(0xb7); // Bun measures 1 column; CJK terminals draw 2
  const lines = wrap(`evil()${dot.repeat(37)}  query:`, 80).split("\n");
  expect(lines.length).toBe(2);
  expect(lines[1]?.startsWith("      ")).toBe(true);
  for (const l of lines) {
    expect(
      [...l].reduce((n, ch) => n + ((ch.codePointAt(0) ?? 0) < 0x7f ? 1 : 2), 0),
    ).toBeLessThanOrEqual(80);
  }
});

test("wrap stays linear on zero-width runs and never goes narrower than its minimum", async () => {
  const { wrap } = await import("../src/review.ts");
  const started = performance.now();
  wrap(`a${String.fromCharCode(0x301).repeat(40000)}`, 80);
  expect(performance.now() - started).toBeLessThan(1000);
  expect(
    wrap("x".repeat(100), 3)
      .split("\n")
      .every((l) => l.length <= 20),
  ).toBe(true);
});

test("the listed query escapes non-ASCII, so a lookalike letter or space is visible", async () => {
  const { show } = await import("../src/review.ts");
  const cyrillicO = String.fromCharCode(0x43e);
  const nbsp = String.fromCharCode(0xa0);
  expect(show(`p${cyrillicO}wershell${nbsp}-enc`, true, true)).toBe("p\\u{43e}wershell\\u{a0}-enc");
  const d = tmp({});
  const inbox = join(d, "_inbox");
  await writeDraft(
    { playbook: "demo", title: "t", why: "w", source: "s", query: `p${cyrillicO}wershell` },
    inbox,
  );
  const listing = (await reviewListing(inbox, 1000)).join("\n");
  expect(listing).toContain("p\\u{43e}wershell");
  expect(listing).not.toContain(cyrillicO);
  rmSync(d, { recursive: true, force: true });
});

test("show escapes variation selectors and other default-ignorable characters", async () => {
  const { show } = await import("../src/review.ts");
  for (const n of [0xfe00, 0xfe0f, 0xe0100, 0xe01ef, 0x034f, 0x115f, 0x1160, 0x3164, 0x180b]) {
    expect(show(`a${String.fromCodePoint(n)}b`)).toBe(`a\\u{${n.toString(16)}}b`);
  }
});

test("the listing escapes non-ASCII in platform, stage and attack ids", async () => {
  const d = tmp({});
  const inbox = join(d, "_inbox");
  const cyrillicO = String.fromCharCode(0x43e);
  const path = await writeDraft(
    { playbook: "demo", title: "t", why: "w", source: "s", platform: `Wind${cyrillicO}ws` },
    inbox,
  );
  const text = await Bun.file(path).text();
  await Bun.write(path, text.replace("attack: []", `attack:\n    - "T1${cyrillicO}"`));
  const listing = (await reviewListing(inbox, 1000)).join("\n");
  expect(listing).toContain("Wind\\u{43e}ws");
  expect(listing).toContain('"T1\\u{43e}"');
  expect(listing).not.toContain(cyrillicO);
  rmSync(d, { recursive: true, force: true });
});

test("a very long title still yields a writable draft", async () => {
  const d = tmp({});
  const path = await writeDraft(
    { playbook: "demo", title: "a".repeat(250), why: "w", source: "s" },
    join(d, "_inbox"),
  );
  expect(await Bun.file(path).exists()).toBe(true);
  rmSync(d, { recursive: true, force: true });
});

test("concurrent drafts with untitled slugs never overwrite each other", async () => {
  const d = tmp({});
  const inbox = join(d, "_inbox");
  const titles = ["Обход MFA", "横向移动", "Ωμέγα", "日本語", "日本語"];
  const paths = await Promise.all(
    titles.map((title) => writeDraft({ playbook: "demo", title, why: "w", source: "s" }, inbox)),
  );
  expect(new Set(paths).size).toBe(5);
  const ids = await Promise.all(
    paths.map(
      async (p) =>
        (Bun.YAML.parse(await Bun.file(p).text()) as { criterion: Criterion }).criterion.id,
    ),
  );
  expect(new Set(ids).size).toBe(5);
  rmSync(d, { recursive: true, force: true });
});

test("the review listing shows every field promote serves", async () => {
  const d = tmp({});
  const inbox = join(d, "_inbox");
  await writeDraft(
    {
      playbook: "demo",
      title: "t",
      why: "w",
      source: "s",
      platform: "Defender XDR / Sentinel",
      stage_ord: 2,
      query: "MARKER_QUERY | take 1",
    },
    inbox,
  );
  const text = (await reviewListing(inbox, 1000)).join("\n");
  expect(text).toContain("  id: demo/proposed/t");
  expect(text).toContain("  platform: Defender XDR / Sentinel · stage 2");
  expect(text).toContain("  tested: null · supersedes: null");
  expect(text).toContain("  attack: (none)");
  expect(text).toContain("  how: (none)\n  fp: (none)");
  expect(text).toContain("  query:\n      MARKER_QUERY | take 1");
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses a non-integer stage_ord and leaves the draft and playbook untouched", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const path = await editedDraft(d, (t) => t.replace(/^ {2}stage_ord: .*$/m, "  stage_ord: NaN"));
  await expect(approve(path, d)).rejects.toThrow(/stage_ord must be an integer/);
  expect(await Bun.file(path).exists()).toBe(true);
  expect(await Bun.file(join(d, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
  rmSync(d, { recursive: true, force: true });
});

test("the review listing names an unreadable draft and still lists the ones after it", async () => {
  const d = tmp({});
  const inbox = join(d, "_inbox");
  mkdirSync(inbox, { recursive: true });
  writeFileSync(join(inbox, "0-broken.yaml"), "playbook: [unclosed\n");
  await writeDraft({ playbook: "demo", title: "good one", why: "w", source: "s" }, inbox);
  const text = (await reviewListing(inbox, 1000)).join("\n");
  expect(text).toContain("0-broken.yaml\n  unreadable:");
  expect(text).toContain("[demo] good one");
  rmSync(d, { recursive: true, force: true });
});

test("ir_propose takes stage_ord strictly, as ir_hunt does", async () => {
  const d = tmp({});
  const c = await ctxWithInbox(d);
  const base = { playbook: "ransomware-response", title: "t", why: "w", source: "s" };
  for (const bad of ["x", true, "0x2", [2]]) {
    await expect(handleTool("ir_propose", { ...base, stage_ord: bad }, c)).rejects.toThrow(
      /stage_ord must be an integer/,
    );
  }
  const r = (await handleTool("ir_propose", { ...base, stage_ord: "3" }, c)) as { draft: string };
  const draft = Bun.YAML.parse(await Bun.file(r.draft).text()) as { criterion: Criterion };
  expect(draft.criterion.stage_ord).toBe(3);
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses an id another playbook already has, so the corpus still loads", async () => {
  const other = DEMO_PLAYBOOK.replaceAll("demo", "other");
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK, "other.yaml": other });
  const path = await writeDraft(
    { playbook: "other", title: "t", why: "w", source: "s" },
    join(d, "_inbox"),
  );
  writeFileSync(
    path,
    (await Bun.file(path).text()).replace(
      /^ {2}id: .*$/m,
      '  id: "demo/defender/s2-rmm-tools-first-seen"',
    ),
  );
  await expect(approve(path, d)).rejects.toThrow(/already exists in demo/);
  expect(await Bun.file(path).exists()).toBe(true);
  expect(await Bun.file(join(d, "other.yaml")).text()).toBe(other);
  expect((await loadCorpus(d)).criteria.length).toBeGreaterThan(0);
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses an unassigned stage, a platform the playbook lacks, and a renamed stage", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const inbox = join(d, "_inbox");
  const unplaced = await writeDraft({ playbook: "demo", title: "u", why: "w", source: "s" }, inbox);
  const err = await approve(unplaced, d).catch((e: Error) => e.message);
  expect(err).toContain("platform Any is not one of the playbook's: Defender XDR / Sentinel");
  const noStage = await editedDraft(d, (t) => t.replace(/^ {2}stage_ord: .*$/m, "  stage_ord: 0"));
  await expect(approve(noStage, d)).rejects.toThrow(/has no stage .* one of: 2 Stage 2 · Foothold/);
  const renamed = await editedDraft(d, (t) =>
    t.replace(/^ {2}stage: .*$/m, '  stage: "Stage 2 · Something else"'),
  );
  await expect(approve(renamed, d)).rejects.toThrow(
    /stage_ord 2 is Stage 2 · Foothold in this playbook — got stage Stage 2 · Something else/,
  );
  const newStage = await editedDraft(d, (t) =>
    t
      .replace(/^ {2}stage: .*$/m, '  stage: "Stage 7 · New"')
      .replace(/^ {2}stage_ord: .*$/m, "  stage_ord: 7"),
  );
  const newUnassigned = await editedDraft(d, (t) =>
    t
      .replace(/^ {2}stage: .*$/m, '  stage: "Unassigned"')
      .replace(/^ {2}stage_ord: .*$/m, "  stage_ord: 9"),
  );
  await expect(approve(newUnassigned, d)).rejects.toThrow(
    /has no stage \(stage_ord 9, stage Unassigned\)/,
  );
  const nameAtNewOrd = await editedDraft(d, (t) =>
    t.replace(/^ {2}stage_ord: .*$/m, "  stage_ord: 8"),
  );
  await expect(approve(nameAtNewOrd, d)).rejects.toThrow(
    /stage Stage 2 · Foothold is stage_ord 2 in this playbook — got stage_ord 8/,
  );
  expect(await approve(newStage, d)).toMatch(/^demo\/proposed\//);
  for (const p of [unplaced, noStage, renamed, newUnassigned, nameAtNewOrd]) {
    expect(await Bun.file(p).exists()).toBe(true);
  }
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses a draft that would not read back as approved, and changes nothing", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const path = await editedDraft(d, (t) => `${t}  notes: "x"\n`);
  await expect(approve(path, d)).rejects.toThrow(/would not be served as written \(notes\)/);
  expect(await Bun.file(path).exists()).toBe(true);
  expect(await Bun.file(join(d, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
  rmSync(d, { recursive: true, force: true });
});

test("promote's refusals escape draft text and tell a quoted number from a number", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const esc = String.fromCharCode(0x1b);
  const quoted = await editedDraft(d, (t) => t.replace(/^ {2}stage_ord: .*$/m, '  stage_ord: "3"'));
  await expect(approve(quoted, d)).rejects.toThrow('got "3"');
  const hostile = await editedDraft(d, (t) =>
    t.replace(/^ {2}stage_ord: .*$/m, `  stage_ord: "${esc}]0;pwn"`),
  );
  const err1 = await approve(hostile, d).catch((e: Error) => e.message);
  expect(err1).not.toContain(esc);
  const extraKey = await editedDraft(d, (t) => `${t}  "x${esc}[2Jy": 1\n`);
  const err2 = await approve(extraKey, d).catch((e: Error) => e.message);
  expect(err2).toContain("would not be served as written");
  expect(err2).not.toContain(esc);
  rmSync(d, { recursive: true, force: true });
});

test("the review listing shows draft text with controls escaped and newlines indented", async () => {
  const d = tmp({});
  const inbox = join(d, "_inbox");
  const esc = String.fromCharCode(0x1b);
  await writeDraft(
    {
      playbook: "demo",
      title: `ok${esc}[2K${esc}]0;pwn`,
      why: "line1\n  source: CISA AA24-001",
      source: "s",
    },
    inbox,
  );
  const text = (await reviewListing(inbox)).join("\n");
  expect(text).not.toContain(esc);
  expect(text).toContain("ok\\u{1b}[2K\\u{1b}]0;pwn");
  // the forged line is indented under why, not a sibling of the real source line
  expect(text).not.toMatch(/^ {2}source: CISA/m);
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses fields of the wrong type, which would read back unchanged", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const cases: [RegExp, string, string][] = [
    [/^ {2}how: .*\n/m, "", "how"],
    [/^ {2}query: .*$/m, "  query: 0", "query"],
    [/^ {2}title: .*$/m, "  title: 12345", "title"],
    [/^ {2}attack: .*$/m, "  attack: [1]", "attack"],
  ];
  for (const [re, line, name] of cases) {
    const path = await editedDraft(d, (t) => t.replace(re, line));
    await expect(approve(path, d)).rejects.toThrow(`wrong type (${name})`);
    expect(await Bun.file(path).exists()).toBe(true);
  }
  expect(await Bun.file(join(d, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
  rmSync(d, { recursive: true, force: true });
});

test("promote refuses tested, supersedes and attack values the listing would cut short", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const tail = `${" ".repeat(130)}HIDDEN-TAIL`;
  const cases: [RegExp, string, string][] = [
    [/^ {2}tested: .*$/m, `  tested: "2026-10-01${tail}"`, "tested"],
    [/^ {2}supersedes: .*$/m, `  supersedes: "demo/old${tail}"`, "supersedes"],
    [/^ {2}attack: .*$/m, `  attack: ["T1114${tail}"]`, "attack"],
  ];
  for (const [re, line, name] of cases) {
    const path = await editedDraft(d, (t) => t.replace(re, line));
    await expect(approve(path, d)).rejects.toThrow(`wrong type (${name})`);
  }
  expect(await Bun.file(join(d, "demo.yaml")).text()).toBe(DEMO_PLAYBOOK);
  rmSync(d, { recursive: true, force: true });
});

test("a title with no Latin letters or digits still gets a promotable id", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const path = await writeDraft(
    { playbook: "demo", title: "日本語のタイトル", why: "w", source: "s", ...PLACED },
    join(d, "_inbox"),
  );
  const id = await approve(path, d);
  expect(id).toMatch(/^demo\/proposed\/untitled-[a-z0-9]+$/);
  rmSync(d, { recursive: true, force: true });
});

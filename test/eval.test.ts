import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CASES } from "../eval/cases.ts";
import {
  assertCases,
  type EvalReport,
  evaluate,
  readBaseline,
  regressions,
  runEval,
} from "../src/eval.ts";
import { loadIndex } from "../src/index/load.ts";
import { loadCorpus } from "../src/load.ts";
import type { Ctx } from "../src/tools.ts";

const root = join(import.meta.dir, "..");
const tmpDirs: string[] = [];
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

// The hybrid arm needs the embedding host and runs by hand ('bun run eval --semantic');
// the exact arm is deterministic and gates every test run.
test("the exact arm does not regress against the committed baseline", async () => {
  const report = await evaluate(CASES, "exact");
  expect(regressions(report, await readBaseline())).toEqual([]);
});

test("the gate can fail: blanking the indicators regresses the exact arm", async () => {
  const corpus = await loadCorpus(join(root, "criteria"));
  const dir = mkdtempSync(join(tmpdir(), "irnav-eval-test-"));
  tmpDirs.push(dir);
  const ctx: Ctx = {
    corpus: { ...corpus, scenarios: corpus.scenarios.map((s) => ({ ...s, indicators: "" })) },
    index: await loadIndex(join(root, "index", "vectors.json"), corpus),
    embed: async () => null,
    inboxDir: join(dir, "inbox"),
    provenanceLog: join(dir, "provenance.jsonl"),
    coverage: null,
  };
  const found = regressions(await runEval(CASES, ctx, "exact"), await readBaseline());
  expect(found.some((r) => r.startsWith("recall_at_2 fell"))).toBe(true);
});

test("every case names served scenarios, and ids are unique", async () => {
  const corpus = await loadCorpus(join(root, "criteria"));
  expect(() => assertCases(CASES, corpus)).not.toThrow();
  const typo = [{ id: "x", evidence: "e", expected: "ransomware-response/scenario-99" }];
  expect(() => assertCases(typo, corpus)).toThrow(/not a served scenario/);
  const dup = [CASES[0], CASES[0]].filter((c) => c !== undefined);
  expect(() => assertCases(dup, corpus)).toThrow(/duplicate eval case id/);
});

test("regressions names each kind of slip", () => {
  const base = {
    arm: "exact" as const,
    cases: 2,
    case_ids: ["a", "b"],
    top1: 1,
    recall_at_2: 1,
    recall_at_8: 1,
    mrr: 1,
    precision_violations: [],
    passing_at_2: ["a", "b"],
  };
  const now: EvalReport = {
    ...base,
    top1: 0.5,
    recall_at_2: 0.5,
    mrr: 0.75,
    passing_at_2: ["a"],
    precision_violations: ["a"],
    misses: [],
  };
  expect(regressions(now, { exact: base })).toEqual([
    "top1 fell 1 → 0.5",
    "recall_at_2 fell 1 → 0.5",
    "mrr fell 1 → 0.75",
    "case b no longer in the top 2",
    "case a now puts a confusable reading first",
  ]);
  expect(regressions(now, {})).toEqual(["no exact baseline — run 'bun run eval --write-baseline'"]);
});

test("deleting a hard case is a regression, though every score rises", () => {
  const base = {
    arm: "exact" as const,
    cases: 2,
    case_ids: ["easy", "hard"],
    top1: 0.5,
    recall_at_2: 0.5,
    recall_at_8: 1,
    mrr: 0.75,
    precision_violations: [],
    passing_at_2: ["easy"],
  };
  const now: EvalReport = {
    ...base,
    cases: 1,
    case_ids: ["easy"],
    top1: 1,
    recall_at_2: 1,
    mrr: 1,
    misses: [],
  };
  expect(regressions(now, { exact: base })).toEqual(["case hard was removed"]);
});

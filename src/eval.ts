#!/usr/bin/env bun
// Human CLI, not an MCP surface — stdout is correct here.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EMBED_MODEL, embedBatch } from "./index/embed.ts";
import { loadIndex } from "./index/load.ts";
import { loadCorpus } from "./load.ts";
import { type Ctx, handleTool, scenarioKey } from "./tools.ts";
import type { Corpus } from "./types.ts";

/**
 * Ranking quality, measured. SPEC invariant 1 ("never one reading") only helps
 * if the right reading is among the first two: recall@2 is the number that
 * says whether it is. Measured through ir_classify itself, so the eval scores
 * what an analyst is actually served.
 */
export type EvalCase = {
  id: string;
  evidence: string;
  /** playbook/scenario-<id> of the reading the evidence describes. */
  expected: string;
  /** Confusable readings this evidence must not put first. */
  must_not_top1?: string[];
};

export type Arm = "exact" | "hybrid";

export type EvalReport = {
  arm: Arm;
  cases: number;
  /** Every case run: removing a hard case must read as a regression, not as a better score. */
  case_ids: string[];
  top1: number;
  recall_at_2: number;
  recall_at_8: number;
  mrr: number;
  precision_violations: string[];
  passing_at_2: string[];
  misses: { id: string; expected: string; got: string[] }[];
};

export type Baseline = Partial<Record<Arm, Omit<EvalReport, "misses">>>;

const ROOT = join(import.meta.dir, "..");
const BASELINE_PATH = join(ROOT, "eval", "baseline.json");

/** A typo'd key would make a case unpassable and read as a ranking failure. */
export function assertCases(cases: EvalCase[], corpus: Corpus): void {
  const served = new Set(corpus.scenarios.map((s) => scenarioKey(s.playbook, s.id)));
  const seen = new Set<string>();
  for (const c of cases) {
    if (seen.has(c.id)) throw new Error(`duplicate eval case id: ${c.id}`);
    seen.add(c.id);
    for (const key of [c.expected, ...(c.must_not_top1 ?? [])]) {
      if (!served.has(key)) throw new Error(`eval case ${c.id}: ${key} is not a served scenario`);
    }
  }
}

const round = (n: number) => Number(n.toFixed(4));

export async function runEval(cases: EvalCase[], ctx: Ctx, arm: Arm): Promise<EvalReport> {
  assertCases(cases, ctx.corpus);
  let top1 = 0;
  let at2 = 0;
  let at8 = 0;
  let rr = 0;
  const violations: string[] = [];
  const passing: string[] = [];
  const misses: EvalReport["misses"] = [];
  for (const c of cases) {
    const r = (await handleTool("ir_classify", { evidence: c.evidence }, ctx)) as {
      semantic_ranking: boolean;
      candidates: { key: string }[];
    };
    // An eval that silently ran without embeddings would report the exact arm as hybrid.
    if (r.semantic_ranking !== (arm === "hybrid")) {
      throw new Error(`case ${c.id}: semantic_ranking was ${r.semantic_ranking} in the ${arm} arm`);
    }
    const keys = r.candidates.map((x) => x.key);
    const rank = keys.indexOf(c.expected) + 1;
    if (rank === 1) top1 += 1;
    if (rank >= 1 && rank <= 2) {
      at2 += 1;
      passing.push(c.id);
    } else misses.push({ id: c.id, expected: c.expected, got: keys.slice(0, 2) });
    if (rank >= 1) {
      at8 += 1;
      rr += 1 / rank;
    }
    if (c.must_not_top1?.includes(keys[0] ?? "")) violations.push(c.id);
  }
  const n = cases.length;
  return {
    arm,
    cases: n,
    case_ids: cases.map((c) => c.id),
    top1: round(top1 / n),
    recall_at_2: round(at2 / n),
    recall_at_8: round(at8 / n),
    mrr: round(rr / n),
    precision_violations: violations,
    passing_at_2: passing,
    misses,
  };
}

/**
 * A ratchet, not a fixed bar: nothing may get worse than the committed
 * baseline, no case that passed may stop passing, and no case may disappear.
 * A hard "recall must be 1.0" gate only teaches people to delete the hard
 * cases; deleting them would otherwise raise every score and pass.
 */
export function regressions(report: EvalReport, baseline: Baseline): string[] {
  const base = baseline[report.arm];
  if (base === undefined)
    return [`no ${report.arm} baseline — run 'bun run eval --write-baseline'`];
  const out: string[] = [];
  const removed = base.case_ids.filter((id) => !report.case_ids.includes(id));
  for (const id of removed) out.push(`case ${id} was removed`);
  for (const m of ["top1", "recall_at_2", "recall_at_8", "mrr"] as const) {
    if (report[m] < base[m]) out.push(`${m} fell ${base[m]} → ${report[m]}`);
  }
  for (const id of base.passing_at_2) {
    if (!removed.includes(id) && !report.passing_at_2.includes(id)) {
      out.push(`case ${id} no longer in the top 2`);
    }
  }
  for (const id of report.precision_violations) {
    if (!base.precision_violations.includes(id))
      out.push(`case ${id} now puts a confusable reading first`);
  }
  return out;
}

async function evalCtx(arm: Arm, dir: string): Promise<Ctx> {
  const corpus = await loadCorpus(join(ROOT, "criteria"));
  return {
    corpus,
    index: await loadIndex(
      join(ROOT, "index", "vectors.json"),
      corpus,
      arm === "hybrid" ? EMBED_MODEL : null,
    ),
    // Hybrid fails loud on an unreachable host: a degraded run is not a hybrid measurement.
    embed: arm === "hybrid" ? async (t) => (await embedBatch([t]))[0] ?? null : async () => null,
    inboxDir: join(dir, "inbox"),
    // Eval calls are not deliveries: they must never reach the real provenance log.
    provenanceLog: join(dir, "provenance.jsonl"),
    coverage: null,
  };
}

/** One arm against the committed corpus and index, logging to a throwaway file. */
export async function evaluate(cases: EvalCase[], arm: Arm): Promise<EvalReport> {
  const dir = mkdtempSync(join(tmpdir(), "irnav-eval-"));
  try {
    return await runEval(cases, await evalCtx(arm, dir), arm);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export async function readBaseline(path = BASELINE_PATH): Promise<Baseline> {
  const f = Bun.file(path);
  return (await f.exists()) ? ((await f.json()) as Baseline) : {};
}

if (import.meta.main) {
  const flags = new Set(process.argv.slice(2));
  const arm: Arm = flags.has("--semantic") ? "hybrid" : "exact";
  const { CASES } = await import("../eval/cases.ts");
  const report = await evaluate(CASES, arm);
  const { misses, ...summary } = report;
  console.log(
    `${arm} arm, ${report.cases} cases — top1 ${report.top1} · recall@2 ${report.recall_at_2} · ` +
      `recall@8 ${report.recall_at_8} · MRR ${report.mrr} · confusable-first ${report.precision_violations.length}`,
  );
  for (const m of misses)
    console.log(`  miss ${m.id}: expected ${m.expected}, top 2 ${m.got.join(", ")}`);
  for (const id of report.precision_violations) console.log(`  confusable first: ${id}`);
  const baseline = await readBaseline();
  if (flags.has("--write-baseline")) {
    await Bun.write(BASELINE_PATH, `${JSON.stringify({ ...baseline, [arm]: summary }, null, 2)}\n`);
    console.log(`baseline for the ${arm} arm written to ${BASELINE_PATH}`);
  } else {
    const found = regressions(report, baseline);
    for (const r of found) console.log(`  REGRESSION ${r}`);
    if (found.length > 0) process.exit(1);
  }
}

import { type CoverageView, coverageFor, TECHNIQUE_ID } from "./coverage/snapshot.ts";
import { writeDraft } from "./inbox.ts";
import { usableQueryVector, type VectorIndex } from "./index/load.ts";
import { appendProvenance } from "./provenance.ts";
import { polarTokens, rank, tokens } from "./rank.ts";
import { redactText } from "./redact.ts";
import { CASE_ID, MAX_CALL_TEXT_UNITS, MAX_TEXT_CHARS, TOOL_SCHEMAS } from "./schemas.ts";
import { type Corpus, CRITERION_OUTCOMES, ROUTINGS, type Scenario } from "./types.ts";

export type Ctx = {
  corpus: Corpus;
  index: VectorIndex;
  embed: (text: string) => Promise<number[] | null>;
  /** Where ir_propose writes drafts. Injected so tests never touch the real inbox. */
  inboxDir: string;
  /** Where every delivery is logged. Injected for the same reason as inboxDir. */
  provenanceLog: string;
  /** Detection coverage snapshot; null when none has been built. */
  coverage: CoverageView | null;
};

const COVERAGE_NOTE =
  "coverage counts public rules in the Security Detections MCP corpus that carry the technique id — " +
  "not rules deployed or tested in any tenant. gap = no rule for the id, any of its sub-techniques, " +
  "or any ATT&CK id revoked into them (revoked_ids: rule sets still tagging the old id); " +
  "unknown = the snapshot predates the technique, or is outdated (see outdated) — not a gap.";

/**
 * Coverage for the techniques a set of criteria hunts for. Unavailable and
 * unknown are reported as such — a missing snapshot must never read as
 * "everything is a gap" or "nothing is".
 */
function coverageOf(
  ctx: Ctx,
  criteria: Corpus["criteria"],
  detail: boolean,
): Record<string, unknown> {
  const view = ctx.coverage;
  if (view === null) {
    return { available: false, note: "No coverage snapshot — run 'bun run build:coverage'." };
  }
  const ids = [...new Set(criteria.flatMap((c) => c.attack))]
    .filter((t) => TECHNIQUE_ID.test(t))
    .sort();
  const rows = ids.map((id) => ({ id, row: coverageFor(view, id) }));
  return {
    available: true,
    built_at: view.snapshot.built_at,
    source_host: view.snapshot.source_host,
    stale: view.stale,
    ...(view.outdated ? { outdated: view.outdated } : {}),
    gaps: rows.filter((r) => r.row?.gap).map((r) => r.id),
    unknown: rows.filter((r) => r.row === null).map((r) => r.id),
    ...(detail ? { techniques: rows.flatMap((r) => (r.row ? [r.row] : [])) } : {}),
    note: COVERAGE_NOTE,
  };
}

/**
 * Caller-supplied text echoed into an error is clipped: a steered client must
 * not be able to flood its own context. Redacted first, because errors are
 * logged, and a cut through a token leaves a stub too short for any rule to match.
 */
function clip(s: string): string {
  const r = redactText(s);
  return r.length > 200 ? `${r.slice(0, 200)}…` : r;
}

const TOP_N = 8;
/** ir_classify refuses to serve fewer readings than this — one reading is an anchoring machine (SPEC invariant 1). */
const MIN_CANDIDATES = 2;

function vectorLookup(index: VectorIndex): (id: string) => number[] | null {
  const byId = new Map<string, number[]>();
  index.ids.forEach((id, i) => {
    const v = index.vectors[i];
    if (v) byId.set(id, v);
  });
  return (id) => byId.get(id) ?? null;
}

function assertPlaybook(ctx: Ctx, slug: unknown): string | null {
  if (slug === undefined || slug === null) return null;
  const s = String(slug);
  if (!ctx.corpus.playbooks.some((p) => p.slug === s)) {
    throw new Error(
      `unknown playbook: ${clip(s)} — known: ${ctx.corpus.playbooks.map((p) => p.slug).join(", ")}`,
    );
  }
  return s;
}

function requireEvidence(args: Record<string, unknown>): string {
  const evidence = String(args.evidence ?? "").trim();
  if (evidence.length === 0) {
    throw new Error("evidence is required — describe what you observed, in your own words");
  }
  return evidence;
}

// The SDK does not validate tool args server-side. Number() is too forgiving
// here: null, "", false and [] become 0, true becomes 1, "0x2" and [2] become 2 —
// each a stage nobody asked for. Accept an integer, or a string of digits.
const STAGE_DIGITS = /^\s*-?\d+\s*$/;
function requireStageOrd(args: Record<string, unknown>): number {
  const v = args.stage_ord;
  const ord =
    typeof v === "number" || (typeof v === "string" && STAGE_DIGITS.test(v))
      ? Number(v)
      : Number.NaN;
  if (!Number.isInteger(ord)) {
    throw new Error(`stage_ord must be an integer — got ${clip(JSON.stringify(v ?? null))}`);
  }
  return ord;
}

// A stage outside the chain returns nothing, which reads as "nothing applies here".
function assertStageExists(ord: number, present: number[], where: string): void {
  if (!present.includes(ord)) {
    throw new Error(
      `stage_ord ${ord} has no hunts in ${where} — stages with hunts: ${present.join(", ")}`,
    );
  }
}

// Clients send explicit null for "unset"; Number(null) is 0, which would
// silently narrow the brief to a stage that does not exist.
function optionalStageOrd(args: Record<string, unknown>): number | null {
  return args.stage_ord === undefined || args.stage_ord === null ? null : requireStageOrd(args);
}

// A platform filter that matches nothing must not come back as an empty brief:
// "no hunts for this platform" and "you misspelled the platform" look identical.
function assertPlatform(ctx: Ctx, pb: string | null, platform: unknown): string | null {
  if (platform === undefined || platform === null) return null;
  const p = String(platform);
  const known = ctx.corpus.playbooks
    .filter((x) => pb === null || x.slug === pb)
    .flatMap((x) => x.platforms);
  if (!known.includes(p)) {
    throw new Error(`unknown platform: ${clip(p)} — known: ${[...new Set(known)].join(", ")}`);
  }
  return p;
}

type StageEntry = { stage_ord: number; stage: string; hunt_count: number; platforms: string[] };

function stageMap(criteria: Corpus["criteria"]): StageEntry[] {
  const by = new Map<number, StageEntry>();
  for (const c of criteria) {
    const e = by.get(c.stage_ord) ?? {
      stage_ord: c.stage_ord,
      stage: c.stage,
      hunt_count: 0,
      platforms: [],
    };
    e.hunt_count += 1;
    if (!e.platforms.includes(c.platform)) e.platforms.push(c.platform);
    by.set(c.stage_ord, e);
  }
  return [...by.values()].sort((a, b) => a.stage_ord - b.stage_ord);
}

const OUTPUT_CONTRACT = {
  routing: [...ROUTINGS],
  finding: {
    confidence: "low | medium | high — your call, stated",
    supporting_evidence: "which criteria (by id) were met, and by what observation",
    enrichment_trail: "what was looked up to get there",
    routing: "one of output.routing — not_evaluable when the hunts could not run, never ruled_out",
    outcomes: `per criterion id: ${CRITERION_OUTCOMES.join(" | ")}`,
    falsifier: "required with ruled_out: the observation that ruled the reading out",
  },
  case_id: "the incident's case id, passed on every call",
  record_with: "ir_log",
};

/**
 * Null only when the playbook has no scenario branches at all: those playbooks
 * still carry hunts and must stay reachable. When branches exist the caller
 * has to name one — a brief without a reading would be the stage list again.
 */
function resolveScenario(
  branches: (Scenario & { playbook: string })[],
  pb: string,
  id: unknown,
): (Scenario & { playbook: string }) | null {
  const ids = branches.map((s) => s.id).join(", ");
  if (id === undefined || id === null) {
    if (branches.length === 0) return null;
    throw new Error(
      `scenario is required — ${pb} has branches ${ids}; take the id from the ir_classify candidate`,
    );
  }
  const s = branches.find((b) => b.id === String(id));
  if (s === undefined) {
    const hint =
      branches.length === 0
        ? `${pb} has no scenario branches — omit scenario to brief it without a threat model`
        : `known: ${ids}`;
    throw new Error(`unknown scenario ${clip(String(id))} in ${pb} — ${hint}`);
  }
  return s;
}

/**
 * The one spelling of a scenario's join key. Deliveries (ir_classify, ir_hunt)
 * and decisions (ir_log) are joined on it; built anywhere else, a format drift
 * orphans every row without an error.
 */
export function scenarioKey(playbook: string, id: string): string {
  return `${playbook}/scenario-${id}`;
}

const SCENARIO_KEY = /^([^/]+)\/scenario-([^/]+)$/;

function parseScenarioKey(key: string): { playbook: string; id: string } | null {
  const m = SCENARIO_KEY.exec(key);
  return m ? { playbook: m[1] as string, id: m[2] as string } : null;
}

// ir_log rows are what deliveries get joined against. A key that cannot match
// a delivery must be rejected, not acknowledged and silently orphaned.
function validateLogRefs(
  ctx: Ctx,
  args: Record<string, unknown>,
): { scenario: string | null; criteria_ids: string[] } {
  let scenario: string | null = null;
  if (args.scenario !== undefined && args.scenario !== null) {
    if (typeof args.scenario !== "string") {
      throw new Error("scenario must be a string key — use scenario.key from the ir_hunt brief");
    }
    scenario = args.scenario;
    const k = parseScenarioKey(scenario);
    if (!k || !ctx.corpus.scenarios.some((s) => s.playbook === k.playbook && s.id === k.id)) {
      throw new Error(
        `scenario must be an active playbook/scenario-<id> key — use scenario.key from the ir_hunt brief; got ${clip(scenario)}`,
      );
    }
  }
  const raw = args.criteria_ids;
  if (raw === undefined || raw === null) return { scenario, criteria_ids: [] };
  // Strings only: String(["x"]) === "x" would pass validation while the raw
  // array, not the string, is what lands in the provenance log.
  if (!Array.isArray(raw) || !raw.every((x) => typeof x === "string")) {
    throw new Error("criteria_ids must be an array of criterion id strings");
  }
  const ids = raw as string[];
  assertKnownCriteria(ctx, ids, "criteria_ids");
  return { scenario, criteria_ids: ids };
}

function assertKnownCriteria(ctx: Ctx, ids: string[], field: string): void {
  const known = new Set(ctx.corpus.criteria.map((c) => c.id));
  const unknown = ids.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    throw new Error(`unknown ${field}: ${clip(unknown.join(", "))}`);
  }
}

/** Per-criterion results, the labels review counts. An unknown id or value would count as nothing, silently. */
function validateOutcomes(ctx: Ctx, args: Record<string, unknown>): Record<string, string> {
  const raw = args.outcomes;
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("outcomes must be an object of criterion id → outcome");
  }
  const entries = Object.entries(raw as Record<string, unknown>);
  const bad = entries.filter(
    ([, v]) => typeof v !== "string" || !(CRITERION_OUTCOMES as readonly string[]).includes(v),
  );
  if (bad.length > 0) {
    throw new Error(
      `outcomes values must be one of ${CRITERION_OUTCOMES.join("/")} — got ${clip(JSON.stringify(bad[0]?.[1] ?? null))} for ${clip(bad[0]?.[0] ?? "")}`,
    );
  }
  assertKnownCriteria(
    ctx,
    entries.map(([k]) => k),
    "outcomes ids",
  );
  return Object.fromEntries(entries) as Record<string, string>;
}

/**
 * A ruled_out row is the reusable knowledge ("not AiTM: MFA was never
 * satisfied"). Without the observation, it cannot be told apart from a guess,
 * and without a target it rules out nothing.
 */
function assertRuledOut(
  falsifier: string | null,
  refs: { scenario: string | null; criteria_ids: string[] },
  outcomes: Record<string, string>,
): void {
  if (falsifier === null || falsifier.trim().length === 0) {
    throw new Error(
      "routing ruled_out needs falsifier — the observation that ruled the reading out. " +
        "If the hunts could not run, the routing is not_evaluable.",
    );
  }
  if (
    refs.scenario === null &&
    refs.criteria_ids.length === 0 &&
    Object.keys(outcomes).length === 0
  ) {
    throw new Error("routing ruled_out must name what was ruled out — scenario or criteria_ids");
  }
  // A reading is ruled out by a check that came back met or not_met. Inconclusive and
  // not_evaluable checks rule nothing out. When criteria_ids names what was ruled out,
  // the determinate check must be one of those, not some other criterion.
  const named = refs.criteria_ids.length > 0 ? new Set(refs.criteria_ids) : null;
  const entries = Object.entries(outcomes);
  const determinate = entries.some(
    ([id, v]) => (v === "met" || v === "not_met") && (named === null || named.has(id)),
  );
  if (entries.length > 0 && !determinate) {
    throw new Error(
      named === null
        ? "routing ruled_out needs at least one outcome met or not_met — with only inconclusive or not_evaluable checks, nothing was ruled out"
        : "routing ruled_out needs an outcome met or not_met for one of the named criteria_ids — the check that ruled it out",
    );
  }
}

function optionalString(args: Record<string, unknown>, key: string): string | null {
  const v = args[key];
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") throw new Error(`${key} must be a string`);
  return v;
}

/** Validated on every tool: a case id that cannot match itself on the next call joins nothing. */
function optionalCaseId(args: Record<string, unknown>): string | null {
  const v = args.case_id;
  if (v === undefined || v === null) return null;
  if (typeof v !== "string" || !CASE_ID.test(v)) {
    throw new Error(
      "case_id must be 1–80 letters, digits and . _ : # ~ - , starting with a letter, digit, ~ or # " +
        `— got ${clip(JSON.stringify(v))}`,
    );
  }
  return v;
}

const TOOL_ARGS = new Map<string, string[]>(
  TOOL_SCHEMAS.map((t) => [t.name, Object.keys(t.inputSchema.properties)]),
);

/**
 * The SDK does not enforce additionalProperties: an argument no tool reads would
 * be acknowledged, logged as if it meant something, and joined on by nothing.
 */
function assertKnownArgs(name: string, args: Record<string, unknown>): void {
  const known = TOOL_ARGS.get(name);
  if (known === undefined) throw new Error(`unknown tool: ${clip(name)}`);
  const extra = Object.keys(args).filter((k) => !known.includes(k));
  if (extra.length > 0) {
    throw new Error(
      `unknown argument(s) for ${name}: ${clip(extra.join(", "))} — known: ${known.join(", ")}`,
    );
  }
}

/**
 * The SDK does not enforce the schemas' maxLength: refuse here, before anything
 * runs or is logged. Every string at any depth, and every key, counts.
 */
function assertTextLimits(args: Record<string, unknown>): void {
  let units = 0;
  const visit = (v: unknown, at: string): void => {
    if (typeof v === "string") {
      units += v.length;
      if ([...v].length > MAX_TEXT_CHARS) {
        throw new Error(
          `${clip(at)} is over ${MAX_TEXT_CHARS} characters — summarise it, or send the key lines only`,
        );
      }
    } else if (Array.isArray(v)) {
      for (const x of v) visit(x, at);
    } else if (v !== null && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        units += k.length;
        visit(x, k);
      }
    }
  };
  visit(args, "arguments");
  if (units > MAX_CALL_TEXT_UNITS) {
    throw new Error(
      `this call carries ${units} characters of text, over the ${MAX_CALL_TEXT_UNITS} one call may — split or summarise it`,
    );
  }
}

export async function handleTool(
  name: string,
  args: Record<string, unknown>,
  ctx: Ctx,
): Promise<unknown> {
  // Oversized calls are refused before anything is logged: the log must not be floodable.
  assertTextLimits(args);
  const tool = clip(name);
  let result: unknown;
  try {
    assertKnownArgs(name, args);
    optionalCaseId(args);
    result = await route(name, args, ctx);
  } catch (err) {
    const error = clip((err as Error).message);
    // A refused call is logged too, but a failed write must not replace the refusal the caller needs.
    await appendProvenance(ctx.provenanceLog, {
      ts: new Date().toISOString(),
      tool,
      args,
      surfaced: {},
      error,
    }).catch((logErr: Error) => {
      throw new Error(
        `${(err as Error).message} (provenance write also failed: ${logErr.message})`,
      );
    });
    throw err;
  }
  await appendProvenance(ctx.provenanceLog, {
    ts: new Date().toISOString(),
    tool,
    args,
    surfaced: summarise(result),
  });
  return result;
}

/**
 * What the provenance log keeps per delivery. Ids, not counts: "surfaced and
 * never acted on", "surfaced before a contradicting decision" and "never
 * surfaced at all" (SPEC, outbound loop) are all joins on individual ids —
 * a count can answer none of them. Exported so the contract is testable.
 */
export function summarise(result: unknown): Record<string, unknown> {
  const r = (result ?? {}) as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  const record = (key: string, id: (x: Record<string, unknown>) => string) => {
    const arr = r[key];
    if (!Array.isArray(arr)) return;
    out[`${key}_count`] = arr.length;
    out[`${key}_ids`] = (arr as Record<string, unknown>[]).map(id);
  };
  record("candidates", (c) => scenarioKey(String(c.playbook), String(c.id)));
  record("criteria", (c) => String(c.id));
  record("hunts", (h) => String(h.id));
  record("results", (c) => String(c.id));
  record("actions", (a) => `${a.playbook}/${a.platform}/${a.name}`);
  const sc = r.scenario as { playbook?: unknown; id?: unknown; key?: unknown } | undefined;
  if (sc && typeof sc.key === "string") out.scenario_id = sc.key;
  // Alternatives are surfaced readings too (SPEC invariant 2): a decision that
  // matches one must be joinable to the brief that showed it.
  if (sc) record("alternatives", (a) => scenarioKey(String(sc.playbook), String(a.id)));
  return out;
}

/**
 * A hunt brief for one reading. Without stage_ord it is a map: threat model,
 * which stages carry hunts and on which platforms, and the competing readings —
 * no criteria, so nothing is logged as surfaced that was not shown, and the
 * response stays small. With stage_ord it returns that stage's hunts plus the
 * adjacent stages, so the stage call stays open (SPEC § The risk). The scenario
 * carries no stage of its own; the discriminator says where to look.
 */
function brief(ctx: Ctx, args: Record<string, unknown>): Record<string, unknown> {
  const pb = assertPlaybook(ctx, args.playbook);
  if (pb === null) {
    throw new Error(
      "playbook is required — take it from the ir_classify candidate you are briefing " +
        `(known: ${ctx.corpus.playbooks.map((p) => p.slug).join(", ")}). For a stage lookup without a reading, use ir_criteria.`,
    );
  }
  const platform = assertPlatform(ctx, pb, args.platform);
  const ord = optionalStageOrd(args);
  const branches = ctx.corpus.scenarios.filter((s) => s.playbook === pb);
  const scenario = resolveScenario(branches, pb, args.scenario);
  const inScope = ctx.corpus.criteria.filter(
    (c) => c.playbook === pb && (platform === null || c.platform === platform),
  );
  const stages = stageMap(inScope);

  const base = {
    scenario: {
      playbook: pb,
      id: scenario?.id ?? null,
      // What ir_log takes as `scenario`. Null when there is no reading to log against.
      key: scenario === null ? null : scenarioKey(pb, scenario.id),
      name: scenario?.name ?? ctx.corpus.playbooks.find((p) => p.slug === pb)?.title ?? pb,
    },
    threat_model:
      scenario === null
        ? null
        : {
            indicators: scenario.indicators,
            discriminator: scenario.discriminator,
            attack: scenario.attack,
          },
    alternatives: branches
      .filter((s) => s.id !== scenario?.id)
      .map((s) => ({ id: s.id, name: s.name, discriminator: s.discriminator })),
    output: OUTPUT_CONTRACT,
  };
  const note = [
    "A brief, not a script: each 'why' says what a correct conclusion looks like, 'fp' what would make it benign.",
    "alternatives are the competing readings in this playbook; the other ir_classify candidates compete too.",
    "time_window null means no window is authored for this scenario — not 'search all time'.",
    scenario === null
      ? `${pb} has no scenario branches, so this brief carries no threat model — author scenarios rather than reading the hunts as one.`
      : "",
  ];

  if (ord === null) {
    return {
      ...base,
      scope: {
        platforms: [...new Set(stages.flatMap((s) => s.platforms))],
        stage_ord: null,
        time_window: scenario?.window ?? null,
      },
      stages: stages.map((s) => {
        const cov = coverageOf(
          ctx,
          inScope.filter((c) => c.stage_ord === s.stage_ord),
          false,
        );
        // unknown is listed per stage too: an empty gap list must not read as "covered"
        // when the snapshot predates the stage's techniques.
        return cov.available ? { ...s, coverage_gaps: cov.gaps, coverage_unknown: cov.unknown } : s;
      }),
      coverage: coverageOf(ctx, inScope, false),
      note: ["Stage map only: call again with stage_ord to get that stage's hunts.", ...note]
        .filter(Boolean)
        .join(" "),
    };
  }

  assertStageExists(
    ord,
    stages.map((s) => s.stage_ord),
    platform === null ? pb : `${pb} on ${platform}`,
  );
  const hunts = inScope
    .filter((c) => c.stage_ord === ord)
    .sort((a, b) => a.platform.localeCompare(b.platform) || a.id.localeCompare(b.id));
  return {
    ...base,
    scope: {
      platforms: [...new Set(hunts.map((h) => h.platform))],
      stage_ord: ord,
      time_window: scenario?.window ?? null,
    },
    hunts: hunts.map((c) => ({
      id: c.id,
      stage_ord: c.stage_ord,
      stage: c.stage,
      platform: c.platform,
      title: c.title,
      why: c.why,
      fp: c.fp,
      how: c.how,
      query: c.query,
      attack: c.attack,
      tested: c.tested,
      verified: c.tested !== null,
    })),
    adjacent: stages.filter((s) => s.stage_ord !== ord && Math.abs(s.stage_ord - ord) <= 2),
    coverage: coverageOf(ctx, hunts, true),
    note: [
      "verified mirrors the authored 'tested' date: a query nobody ran in a real tenant is reference, not truth.",
      "adjacent lists the neighbouring stages so the stage call stays open.",
      ...note,
    ]
      .filter(Boolean)
      .join(" "),
  };
}

async function route(name: string, args: Record<string, unknown>, ctx: Ctx): Promise<unknown> {
  const vecFor = vectorLookup(ctx.index);

  switch (name) {
    case "ir_classify": {
      const evidence = requireEvidence(args);
      const qv = usableQueryVector(await ctx.embed(evidence), ctx.index);
      const ranked = rank({
        // Ranked under the key: rank breaks ties by id, and the index stores scenario vectors under it.
        items: ctx.corpus.scenarios.map((s) => ({ ...s, id: scenarioKey(s.playbook, s.id) })),
        // Evidence and indicators are prose that says what is absent. ir_search keeps tokens():
        // its item text includes query code, where "not" is an operator.
        queryTokens: polarTokens(evidence),
        queryVector: qv,
        vectorFor: (s) => vecFor(s.id),
        textFor: (s) => `${s.name}. ${s.indicators}`,
        tokenize: polarTokens,
      });
      // SPEC: "throws below 2". Enforced here, not left to the corpus happening
      // to be large enough — the single invariant the design exists for.
      if (ranked.length < MIN_CANDIDATES) {
        throw new Error(
          `only ${ranked.length} candidate scenario(s) in the corpus — refusing to surface a ` +
            "single reading; author more scenario branches rather than weakening this guard",
        );
      }
      const candidates = ranked.slice(0, TOP_N);
      return {
        evidence,
        semantic_ranking: qv !== null,
        candidates: candidates.map((c) => ({
          playbook: c.playbook,
          id: parseScenarioKey(c.id)?.id ?? c.id,
          key: c.id,
          name: c.name,
          score: c.score,
          matched_indicators: c.matched,
          indicators: c.indicators,
          discriminator: c.discriminator,
        })),
        coverage: {
          scenarios_total: ctx.corpus.scenarios.length,
          no_scenarios: ctx.corpus.playbooks
            .filter((p) => p.scenario_count === 0)
            .map((p) => p.slug),
        },
        note:
          "Ranked readings, not a verdict. Read each discriminator and decide what evidence would rule it out. " +
          "Playbooks under coverage.no_scenarios contribute no branches — absence there is missing content, not exclusion.",
      };
    }

    case "ir_search": {
      const evidence = requireEvidence(args);
      const pb = assertPlaybook(ctx, args.playbook);
      const qv = usableQueryVector(await ctx.embed(evidence), ctx.index);
      const items = ctx.corpus.criteria.filter((c) => pb === null || c.playbook === pb);
      const ranked = rank({
        items,
        queryTokens: tokens(evidence),
        queryVector: qv,
        vectorFor: (c) => vecFor(c.id),
        // Exact-token side includes the query body and ATT&CK ids: tool names,
        // process names and technique ids are verbatim-match signals (SPEC §3).
        // The embedding side stays title+why — embedText and the index hash are untouched.
        textFor: (c) => `${c.title}. ${c.why}\n${c.query}\n${c.attack.join(" ")}`,
      });
      return {
        evidence,
        semantic_ranking: qv !== null,
        results: ranked.slice(0, TOP_N).map((c) => ({
          id: c.id,
          playbook: c.playbook,
          stage: c.stage,
          stage_ord: c.stage_ord,
          platform: c.platform,
          title: c.title,
          why: c.why,
          fp: c.fp,
          attack: c.attack,
          score: c.score,
          matched: c.matched,
        })),
        note: "Each 'why' is the authored judgment criterion. Ranked by evidence overlap, not by confidence in a verdict.",
      };
    }

    case "ir_criteria": {
      const pb = assertPlaybook(ctx, args.playbook);
      const ord = requireStageOrd(args);
      const scope = ctx.corpus.criteria.filter((c) => pb === null || c.playbook === pb);
      const present = [...new Set(scope.map((c) => c.stage_ord))].sort((a, b) => a - b);
      assertStageExists(ord, present, pb ?? "any playbook");
      return {
        playbook: pb,
        stage_ord: ord,
        // Titles, not bare stage numbers — an integer keeps nothing open.
        adjacent: present
          .filter((p) => p !== ord && Math.abs(p - ord) <= 2)
          .map((p) => {
            const cs = scope.filter((c) => c.stage_ord === p);
            return {
              stage_ord: p,
              stage: cs[0]?.stage ?? `Stage ${p}`,
              titles: [...new Set(cs.map((c) => c.title))],
            };
          }),
        criteria: scope
          .filter((c) => c.stage_ord === ord)
          .map((c) => ({
            id: c.id,
            playbook: c.playbook,
            stage: c.stage,
            platform: c.platform,
            title: c.title,
            why: c.why,
            fp: c.fp,
            attack: c.attack,
          })),
        note: "Adjacent stages are listed so the stage call stays open — the evidence may sit earlier or later than assumed.",
      };
    }

    case "ir_hunt":
      return brief(ctx, args);

    case "ir_actions": {
      const pb = assertPlaybook(ctx, args.playbook);
      const platform = assertPlatform(ctx, pb, args.platform);
      return {
        playbook: pb,
        actions: ctx.corpus.actions
          .filter(
            (a) =>
              (pb === null || a.playbook === pb) && (platform === null || a.platform === platform),
          )
          .map((a) => ({ ...a, proposal_only: a.tier !== "read" })),
        note:
          "These blocks carry no authored judgment criterion. Anything not read-only is a proposal for a human " +
          "to approve, never a next step. tier_inferred means the tier was guessed, not authored.",
      };
    }

    case "ir_log": {
      const routing =
        args.routing === undefined || args.routing === null ? null : String(args.routing);
      if (routing !== null && !(ROUTINGS as readonly string[]).includes(routing)) {
        throw new Error(`routing must be one of ${ROUTINGS.join("/")} — got ${clip(routing)}`);
      }
      const refs = validateLogRefs(ctx, args);
      const outcomes = validateOutcomes(ctx, args);
      const falsifier = optionalString(args, "falsifier");
      if (routing === "ruled_out") assertRuledOut(falsifier, refs, outcomes);
      return {
        logged: true,
        decision: String(args.decision ?? ""),
        rationale: String(args.rationale ?? ""),
        routing,
        falsifier,
        outcomes,
        case_id: optionalCaseId(args),
        ...refs,
      };
    }

    case "ir_propose": {
      const pb = assertPlaybook(ctx, args.playbook);
      if (pb === null) {
        throw new Error("playbook is required — a draft must name its owning playbook file");
      }
      const title = String(args.title ?? "").trim();
      const why = String(args.why ?? "").trim();
      const source = String(args.source ?? "").trim();
      if (title.length === 0 || why.length === 0 || source.length === 0) {
        throw new Error(
          "title, why and source are all required — a criterion without provenance cannot be reviewed",
        );
      }
      const path = await writeDraft(
        {
          playbook: pb,
          title,
          why,
          source,
          platform: args.platform === undefined ? undefined : String(args.platform),
          stage_ord: optionalStageOrd(args) ?? undefined,
          query: args.query === undefined ? undefined : String(args.query),
        },
        ctx.inboxDir,
      );
      return {
        draft: path,
        status: "draft",
        note: "Written to the inbox only. No read tool can return it until a human promotes it with 'bun run review'.",
      };
    }

    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

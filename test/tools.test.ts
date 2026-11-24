import { afterAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadIndex } from "../src/index/load.ts";
import { loadCorpus } from "../src/load.ts";
import { MAX_TEXT_CHARS, TOOL_SCHEMAS } from "../src/schemas.ts";
import type { Ctx } from "../src/tools.ts";
import { handleTool, summarise } from "../src/tools.ts";
import { ROUTINGS } from "../src/types.ts";

const root = join(import.meta.dir, "..");
// One temp dir per ctx holds both the inbox and the provenance log; all removed after the file.
const tmpDirs: string[] = [];
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

// Embeddings are stubbed: these tests pin the tool contract, not retrieval quality.
async function ctx(): Promise<Ctx> {
  const corpus = await loadCorpus(join(root, "criteria"));
  const dir = mkdtempSync(join(tmpdir(), "irnav-test-"));
  tmpDirs.push(dir);
  return {
    corpus,
    index: await loadIndex(join(root, "index", "vectors.json"), corpus),
    embed: async () => null,
    inboxDir: join(dir, "inbox"),
    provenanceLog: join(dir, "provenance.jsonl"),
    coverage: null,
  };
}

test("ir_classify never returns fewer than 2 candidates", async () => {
  const r = (await handleTool(
    "ir_classify",
    { evidence: "ransom notes appearing" },
    await ctx(),
  )) as {
    candidates: { discriminator: string }[];
  };
  expect(r.candidates.length).toBeGreaterThanOrEqual(2);
  for (const c of r.candidates) expect(c.discriminator.length).toBeGreaterThan(0);
});

test("ir_classify throws rather than surface a single reading", async () => {
  // The invariant must live in the code, not in the corpus happening to hold 30 scenarios.
  const c = await ctx();
  const lone = { ...c, corpus: { ...c.corpus, scenarios: c.corpus.scenarios.slice(0, 1) } };
  await expect(handleTool("ir_classify", { evidence: "ransom notes" }, lone)).rejects.toThrow(
    /single reading/i,
  );
});

test("ir_classify is global — candidates span more than one playbook", async () => {
  const r = (await handleTool(
    "ir_classify",
    { evidence: "suspicious scheduled task powershell" },
    await ctx(),
  )) as { candidates: { playbook: string }[] };
  expect(new Set(r.candidates.map((c) => c.playbook)).size).toBeGreaterThan(1);
});

test("ir_classify does not match a term the evidence negates", async () => {
  const r = (await handleTool(
    "ir_classify",
    { evidence: "Backdoor on a file server. No ransom note, no encryption, no extortion contact." },
    await ctx(),
  )) as { candidates: { key: string; matched_indicators: string[] }[] };
  for (const c of r.candidates) {
    expect(c.matched_indicators).not.toContain("ransom");
    expect(c.matched_indicators).not.toContain("encryption");
    expect(c.matched_indicators).not.toContain("extortion");
  }
});

test("ir_classify names playbooks that contribute no branches", async () => {
  const r = (await handleTool("ir_classify", { evidence: "invoice fraud" }, await ctx())) as {
    coverage: { no_scenarios: string[] };
  };
  expect(r.coverage.no_scenarios).toEqual(["bec-response", "device-code-response"]);
});

test("classify and search say when semantic ranking was unavailable", async () => {
  const c = await ctx(); // embed stubbed to null — exactly the embedding-host-down case
  const cl = (await handleTool("ir_classify", { evidence: "ransom notes appearing" }, c)) as {
    semantic_ranking: boolean;
  };
  const se = (await handleTool("ir_search", { evidence: "anydesk" }, c)) as {
    semantic_ranking: boolean;
  };
  expect(cl.semantic_ranking).toBe(false);
  expect(se.semantic_ranking).toBe(false);
});

test("ir_actions marks every non-read action proposal_only", async () => {
  const r = (await handleTool(
    "ir_actions",
    { playbook: "ransomware-response", platform: "Defender XDR / Sentinel" },
    await ctx(),
  )) as { actions: { tier: string; proposal_only: boolean }[] };
  expect(r.actions.some((a) => a.tier === "destructive")).toBe(true);
  for (const a of r.actions) expect(a.proposal_only).toBe(a.tier !== "read");
});

type Stage = { stage_ord: number; stage: string; hunt_count: number; platforms: string[] };
type Brief = {
  scenario: { playbook: string; id: string | null; key: string | null; name: string };
  threat_model: { indicators: string; discriminator: string; attack: string[] } | null;
  scope: { platforms: string[]; stage_ord: number | null; time_window: string | null };
  stages?: Stage[];
  adjacent?: Stage[];
  hunts?: {
    id: string;
    stage_ord: number;
    platform: string;
    verified: boolean;
    tested: string | null;
    query: string;
    why: string;
  }[];
  alternatives: { id: string; name: string; discriminator: string }[];
  output: { routing: string[]; record_with: string };
  note: string;
};

const RW = { playbook: "ransomware-response", scenario: "2" };
const hunt = async (extra: Record<string, unknown> = {}, c?: Ctx) =>
  (await handleTool("ir_hunt", { ...RW, ...extra }, c ?? (await ctx()))) as Brief;

test("ir_hunt without a stage is a map: threat model and stages, no criteria", async () => {
  const c = await ctx();
  const r = await hunt({}, c);
  expect(r.scenario).toEqual({
    playbook: "ransomware-response",
    id: "2",
    key: "ransomware-response/scenario-2",
    name: "Discovered Before Encryption",
  });
  // Threat model is the scenario's own authored text, not a summary of the hunts.
  expect(r.threat_model?.indicators).toContain("C2 beacons");
  expect(r.threat_model?.discriminator).toContain("Don't tip them off");
  expect(r.hunts).toBeUndefined();
  expect(r.stages?.map((s) => s.stage_ord)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const total = c.corpus.criteria.filter((x) => x.playbook === "ransomware-response").length;
  expect(r.stages?.reduce((n, s) => n + s.hunt_count, 0)).toBe(total);
  expect(r.scope.platforms.length).toBe(7);
  // The time window is not authored yet and must say so rather than read as "all time".
  expect(r.scope.time_window).toBeNull();
  expect(r.note).toMatch(/not 'search all time'/);
});

test("an unnarrowed brief logs no criteria as surfaced, so --stale stays meaningful", async () => {
  const s = summarise(await hunt());
  expect(s.hunts_ids).toBeUndefined();
  expect(s.scenario_id).toBe("ransomware-response/scenario-2");
});

test("ir_hunt keeps the competing readings in view, and logs them", async () => {
  const r = await hunt();
  // One brief is one reading. The other branches ride along so the call stays open.
  expect(r.alternatives.map((a) => a.id)).toEqual(["1", "3", "4", "5", "6"]);
  for (const a of r.alternatives) expect(a.discriminator.length).toBeGreaterThan(0);
  expect(summarise(r).alternatives_ids).toEqual(
    ["1", "3", "4", "5", "6"].map((id) => `ransomware-response/scenario-${id}`),
  );
});

test("ir_hunt with a stage returns its hunts and the adjacent stages", async () => {
  const r = await hunt({ stage_ord: 4 });
  expect(r.hunts?.length).toBeGreaterThan(0);
  for (const h of r.hunts ?? []) expect(h.stage_ord).toBe(4);
  expect(r.adjacent?.map((a) => a.stage_ord)).toEqual([2, 3, 5, 6]);
  expect(r.scope.stage_ord).toBe(4);
});

test("ir_hunt narrows by platform and reports only platforms it returned", async () => {
  const r = await hunt({ platform: "Defender XDR / Sentinel", stage_ord: 2 });
  expect(r.hunts?.length).toBeGreaterThan(0);
  for (const h of r.hunts ?? []) expect(h.platform).toBe("Defender XDR / Sentinel");
  expect(r.scope.platforms).toEqual(["Defender XDR / Sentinel"]);
  // Unfiltered by platform, scope lists only platforms that actually have hunts at this stage.
  const all = await hunt({ stage_ord: 2 });
  expect(all.scope.platforms.sort()).toEqual(
    [...new Set((all.hunts ?? []).map((h) => h.platform))].sort(),
  );
});

test("ir_hunt mirrors the authored tested date into verified", async () => {
  const r = await hunt({ stage_ord: 2 });
  expect(r.hunts?.length).toBeGreaterThan(0);
  for (const h of r.hunts ?? []) expect(h.verified).toBe(h.tested !== null);
  // Nothing in the corpus is tested yet — the hedge must hold everywhere today.
  for (const h of r.hunts ?? []) expect(h.verified).toBe(false);
});

test("ir_hunt names the output contract, and the schema enum matches it", async () => {
  const r = await hunt({ stage_ord: 2 });
  expect(r.output.routing).toEqual([...ROUTINGS]);
  expect(r.output.record_with).toBe("ir_log");
  const log = TOOL_SCHEMAS.find((t) => t.name === "ir_log");
  const props = log?.inputSchema.properties as Record<string, { enum?: readonly string[] }>;
  expect(props.routing?.enum).toEqual([...ROUTINGS]);
});

test("ir_hunt on a playbook with no scenario branches briefs without a threat model", async () => {
  const r = (await handleTool("ir_hunt", { playbook: "bec-response" }, await ctx())) as Brief;
  expect(r.scenario.id).toBeNull();
  expect(r.threat_model).toBeNull();
  expect(r.alternatives).toEqual([]);
  expect(r.stages?.length).toBeGreaterThan(0);
  expect(r.note).toMatch(/no scenario branches/i);
  await expect(
    handleTool("ir_hunt", { playbook: "bec-response", scenario: "1" }, await ctx()),
  ).rejects.toThrow(/no scenario branches — omit scenario/);
});

test("ir_hunt fails loud on a missing or unknown scenario when branches exist", async () => {
  const c = await ctx();
  await expect(handleTool("ir_hunt", { playbook: "ransomware-response" }, c)).rejects.toThrow(
    /scenario is required.*1, 2, 3, 4, 5, 6/s,
  );
  await expect(hunt({ scenario: "99" }, c)).rejects.toThrow(
    /unknown scenario 99.*1, 2, 3, 4, 5, 6/s,
  );
  await expect(handleTool("ir_hunt", { scenario: "2" }, c)).rejects.toThrow(
    /playbook is required.*ransomware-response.*ir_criteria/s,
  );
});

test("a null stage_ord means no stage, and a stage with no hunts fails loud", async () => {
  const c = await ctx();
  const r = await hunt({ stage_ord: null }, c);
  expect(r.hunts).toBeUndefined();
  expect(r.stages?.length).toBe(10);
  await expect(hunt({ stage_ord: 11 }, c)).rejects.toThrow(
    /stage_ord 11 has no hunts.*stages with hunts: 1, 2, 3/s,
  );
});

test("stage_ord accepts an integer or digit string, nothing Number() would coerce", async () => {
  const c = await ctx();
  expect((await hunt({ stage_ord: "2" }, c)).scope.stage_ord).toBe(2);
  for (const bad of [true, false, "", "0x2", [2], 2.5, "x".repeat(5000)]) {
    await expect(hunt({ stage_ord: bad }, c)).rejects.toThrow(/stage_ord must be an integer/);
  }
  await expect(hunt({ stage_ord: "x".repeat(5000) }, c)).rejects.toThrow(/…$/);
});

test("ir_criteria fails loud on a missing, null or nonexistent stage", async () => {
  const c = await ctx();
  const crit = (a: Record<string, unknown>) =>
    handleTool("ir_criteria", { playbook: "ransomware-response", ...a }, c);
  await expect(crit({ stage_ord: null })).rejects.toThrow(/stage_ord must be an integer/);
  await expect(crit({ stage_ord: 11 })).rejects.toThrow(/stage_ord 11 has no hunts/);
  await expect(crit({ stage_ord: 0 })).rejects.toThrow(/stages with hunts: 1, 2/);
});

test("the brief's scenario.key is exactly what ir_log accepts and summarise logs", async () => {
  const c = await ctx();
  const r = await hunt({}, c);
  const key = r.scenario.key as string;
  expect(summarise(r).scenario_id).toBe(key);
  const ok = (await handleTool("ir_log", { decision: "x", scenario: key }, c)) as {
    scenario: string;
  };
  expect(ok.scenario).toBe(key);
  const none = (await handleTool("ir_hunt", { playbook: "bec-response" }, c)) as Brief;
  expect(none.scenario.key).toBeNull();
});

test("an unknown playbook is clipped when echoed", async () => {
  await expect(
    handleTool("ir_criteria", { playbook: "p".repeat(5000), stage_ord: 1 }, await ctx()),
  ).rejects.toThrow(/…/);
});

test("an unknown platform filter fails loud instead of returning an empty brief", async () => {
  const c = await ctx();
  await expect(hunt({ platform: "Nope" }, c)).rejects.toThrow(/unknown platform/i);
  await expect(
    handleTool("ir_actions", { playbook: "ransomware-response", platform: "Nope" }, c),
  ).rejects.toThrow(/unknown platform/i);
});

test("ir_log accepts a joinable routing decision", async () => {
  const c = await ctx();
  const id = c.corpus.criteria.find((x) => x.playbook === "ransomware-response")?.id as string;
  const r = (await handleTool(
    "ir_log",
    {
      decision: "escalate",
      rationale: "beacon confirmed",
      scenario: "ransomware-response/scenario-2",
      routing: "analyst_review",
      criteria_ids: [id],
    },
    c,
  )) as { logged: boolean; routing: string | null; scenario: string; criteria_ids: string[] };
  expect(r.logged).toBe(true);
  expect(r.routing).toBe("analyst_review");
  expect(r.scenario).toBe("ransomware-response/scenario-2");
  expect(r.criteria_ids).toEqual([id]);
});

test("ir_log rejects keys that could never join to a delivery", async () => {
  const c = await ctx();
  const log = (a: Record<string, unknown>) => handleTool("ir_log", { decision: "x", ...a }, c);
  await expect(log({ routing: "verdict" })).rejects.toThrow(/routing must be one of/i);
  await expect(log({ scenario: "2" })).rejects.toThrow(/playbook\/scenario-<id>/);
  await expect(log({ scenario: "ransomware-response/scenario-99" })).rejects.toThrow(
    /active playbook\/scenario/,
  );
  await expect(log({ criteria_ids: "a,b" })).rejects.toThrow(/must be an array/);
  await expect(log({ criteria_ids: [["nested"]] })).rejects.toThrow(/id strings/);
  await expect(log({ scenario: ["ransomware-response/scenario-2"] })).rejects.toThrow(
    /must be a string key/,
  );
  await expect(log({ criteria_ids: ["made-up-id"] })).rejects.toThrow(
    /unknown criteria_ids: made-up-id/,
  );
  await expect(log({ routing: "x".repeat(5000) })).rejects.toThrow(/…$/);
});

test("deliveries go to the injected provenance log, never the repo's", async () => {
  const c = await ctx();
  await hunt({ stage_ord: 2 }, c);
  const lines = (await Bun.file(c.provenanceLog).text()).trim().split("\n");
  expect(lines).toHaveLength(1);
  expect(JSON.parse(lines[0] as string).tool).toBe("ir_hunt");
});

test("ir_criteria always includes adjacent stages with their titles", async () => {
  const r = (await handleTool(
    "ir_criteria",
    { stage_ord: 4, playbook: "ransomware-response" },
    await ctx(),
  )) as {
    stage_ord: number;
    adjacent: { stage_ord: number; stage: string; titles: string[] }[];
    criteria: unknown[];
  };
  expect(r.stage_ord).toBe(4);
  const ords = r.adjacent.map((a) => a.stage_ord);
  expect(ords).toContain(3);
  expect(ords).toContain(5);
  for (const a of r.adjacent) expect(a.titles.length).toBeGreaterThan(0);
  expect(r.criteria.length).toBeGreaterThan(0);
});

test("ir_search ranks criteria across the whole corpus", async () => {
  const r = (await handleTool(
    "ir_search",
    { evidence: "anydesk screenconnect first seen" },
    await ctx(),
  )) as { results: { id: string; why: string }[] };
  expect(r.results.length).toBeGreaterThan(0);
  expect(r.results[0]?.why.length).toBeGreaterThan(0);
});

test("ir_search exact side matches ATT&CK technique ids", async () => {
  const r = (await handleTool("ir_search", { evidence: "T1078 valid accounts" }, await ctx())) as {
    results: { matched: string[]; attack: string[] }[];
  };
  expect(r.results[0]?.matched).toContain("t1078");
  expect(r.results[0]?.attack).toContain("T1078");
});

test("ir_search exact side matches tool names that live only in query bodies", async () => {
  // 'DeviceNetworkEvents' is query vocabulary, not prose.
  const r = (await handleTool("ir_search", { evidence: "DeviceNetworkEvents" }, await ctx())) as {
    results: { matched: string[] }[];
  };
  expect(r.results[0]?.matched).toContain("devicenetworkevents");
});

test("empty evidence and a missing or non-integer stage_ord fail loud", async () => {
  // The SDK does not validate args server-side; without these guards a NaN
  // filter returns an empty result that reads as "nothing applies".
  const c = await ctx();
  await expect(handleTool("ir_classify", { evidence: "   " }, c)).rejects.toThrow(/evidence/i);
  await expect(handleTool("ir_search", {}, c)).rejects.toThrow(/evidence/i);
  await expect(handleTool("ir_criteria", { playbook: "ransomware-response" }, c)).rejects.toThrow(
    /stage_ord/i,
  );
  await expect(
    handleTool("ir_hunt", { playbook: "ransomware-response", scenario: "2", stage_ord: "x" }, c),
  ).rejects.toThrow(/stage_ord/i);
});

test("an unknown playbook filter fails loud", async () => {
  await expect(
    handleTool("ir_criteria", { stage_ord: 2, playbook: "nope" }, await ctx()),
  ).rejects.toThrow(/unknown playbook/i);
});

test("the provenance summary records surfaced ids, not just counts", async () => {
  const r = await handleTool(
    "ir_hunt",
    { playbook: "ransomware-response", scenario: "2", stage_ord: 2 },
    await ctx(),
  );
  const s = summarise(r);
  expect(s.hunts_count as number).toBeGreaterThan(0);
  expect((s.hunts_ids as string[]).every((id) => id.startsWith("ransomware-response/"))).toBe(true);
  // The brief's own reading is an id too — the outbound loop joins briefs to ir_log on it.
  expect(s.scenario_id).toBe("ransomware-response/scenario-2");
});

test("a text argument over the limit is refused before the tool runs or is logged", async () => {
  const c = await ctx();
  await expect(
    handleTool("ir_classify", { evidence: "x".repeat(MAX_TEXT_CHARS + 1) }, c),
  ).rejects.toThrow(/evidence is over/);
  await expect(
    handleTool(
      "ir_log",
      { decision: "d", rationale: "r", criteria_ids: ["y".repeat(MAX_TEXT_CHARS + 1)] },
      c,
    ),
  ).rejects.toThrow(/criteria_ids is over/);
  await expect(
    handleTool(
      "ir_log",
      { decision: "d", rationale: "r", criteria_ids: Array(9).fill("z".repeat(MAX_TEXT_CHARS)) },
      c,
    ),
  ).rejects.toThrow(/over the \d+ one call may/);
  await expect(
    handleTool(
      "ir_classify",
      { evidence: "ok", extra: { a: "x".repeat(30_000), b: "x".repeat(15_000) } },
      c,
    ),
  ).rejects.toThrow(/over the \d+ one call may/);
  await expect(
    handleTool(
      "ir_classify",
      { evidence: "ok", ["k".repeat(1000)]: "x".repeat(MAX_TEXT_CHARS + 1) },
      c,
    ),
  ).rejects.toThrow(/^k{200}… is over/);
  expect(await Bun.file(c.provenanceLog).exists()).toBe(false);
  // 20,000 emoji are 20,000 characters to JSON Schema's maxLength, not 40,000.
  expect(await handleTool("ir_classify", { evidence: "😀".repeat(20_000) }, c)).toBeDefined();
  const r = await handleTool("ir_classify", { evidence: "x".repeat(MAX_TEXT_CHARS) }, c);
  expect(r).toBeDefined();
});

const logRows = async (c: Ctx) =>
  (await Bun.file(c.provenanceLog).text())
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l) as Record<string, unknown>);

test("an argument the tool does not take is refused, and the refusal is logged", async () => {
  const c = await ctx();
  await expect(handleTool("ir_log", { decision: "x", decided_by: "analyst" }, c)).rejects.toThrow(
    /unknown argument\(s\) for ir_log: decided_by — known: decision/,
  );
  await expect(handleTool("ir_nope", {}, c)).rejects.toThrow(/unknown tool: ir_nope/);
  const rows = await logRows(c);
  expect(rows.map((r) => r.tool)).toEqual(["ir_log", "ir_nope"]);
  expect(rows[0]?.error).toMatch(/decided_by/);
  expect(rows[0]?.surfaced).toEqual({});
});

test("every row carries the schema version, and credentials never reach the log", async () => {
  const c = await ctx();
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ2aWN0aW0ifQ.c2lnbmF0dXJlLXZhbHVl"; // gitleaks:allow — fake fixture token
  await handleTool(
    "ir_log",
    { decision: "escalate", rationale: `replayed Authorization: Bearer ${jwt} from 203.0.113.7` },
    c,
  );
  await expect(
    handleTool(
      "ir_criteria",
      { stage_ord: "x", playbook: `Cookie: ESTSAUTH=${"a".repeat(30)}` },
      c,
    ),
  ).rejects.toThrow();
  const raw = await Bun.file(c.provenanceLog).text();
  expect(raw).not.toContain(jwt);
  expect(raw).not.toContain("a".repeat(30));
  // The evidence around the secret is what the log is for, and stays.
  expect(raw).toContain("203.0.113.7");
  const rows = await logRows(c);
  for (const r of rows) expect(r.schema_version).toBe(2);
  expect(rows[1]?.error).toBeDefined();
});

test("the provenance log is owner-only, including one that existed before", async () => {
  const { chmodSync, statSync, writeFileSync } = await import("node:fs");
  const c = await ctx();
  await handleTool("ir_classify", { evidence: "ransom notes appearing" }, c);
  expect(statSync(c.provenanceLog).mode & 0o777).toBe(0o600);
  const old = await ctx();
  writeFileSync(old.provenanceLog, "");
  chmodSync(old.provenanceLog, 0o644);
  await handleTool("ir_classify", { evidence: "ransom notes appearing" }, old);
  expect(statSync(old.provenanceLog).mode & 0o777).toBe(0o600);
});

test("a token cut by the error clip is redacted first, not left as a stub", async () => {
  const c = await ctx();
  // The unknown playbook is echoed clipped at 200 characters; the token straddles that cut.
  const token = `npm_${"Q".repeat(36)}`;
  await expect(
    handleTool("ir_criteria", { stage_ord: 1, playbook: `${"p".repeat(170)} ${token}` }, c),
  ).rejects.toThrow(/unknown playbook/);
  const raw = await Bun.file(c.provenanceLog).text();
  expect(raw).not.toContain("Q".repeat(20));
});

test("a refused call's unknown keys are redacted too", async () => {
  const c = await ctx();
  const key = `ghp_${"K9".repeat(18)}`;
  await expect(handleTool("ir_log", { decision: "x", [key]: "y" }, c)).rejects.toThrow(
    /unknown argument/,
  );
  expect(await Bun.file(c.provenanceLog).text()).not.toContain(key);
});

test("case_id is validated on every tool and echoed by ir_log", async () => {
  const c = await ctx();
  const r = (await handleTool("ir_log", { decision: "x", case_id: "~41040" }, c)) as {
    case_id: string;
  };
  expect(r.case_id).toBe("~41040");
  expect(
    await handleTool("ir_classify", { evidence: "ransom notes", case_id: "INC-2026-114" }, c),
  ).toBeDefined();
  for (const bad of ["", "has space", "../x", 42, "x".repeat(81)]) {
    await expect(
      handleTool("ir_classify", { evidence: "ransom notes", case_id: bad }, c),
    ).rejects.toThrow(/case_id must be/);
  }
  for (const t of TOOL_SCHEMAS) {
    expect(Object.keys(t.inputSchema.properties)).toContain("case_id");
  }
});

test("ruled_out needs the observation that ruled it out, and a target", async () => {
  const c = await ctx();
  const log = (a: Record<string, unknown>) =>
    handleTool("ir_log", { decision: "close", routing: "ruled_out", ...a }, c);
  const key = "identity-breach-response/scenario-2";
  await expect(log({ scenario: key })).rejects.toThrow(/needs falsifier.*not_evaluable/s);
  await expect(log({ scenario: key, falsifier: "   " })).rejects.toThrow(/needs falsifier/);
  await expect(log({ falsifier: "MFA never satisfied" })).rejects.toThrow(/must name what/);
  const ok = (await log({
    scenario: key,
    falsifier: "MFA was never satisfied on any sign-in",
  })) as {
    falsifier: string;
  };
  expect(ok.falsifier).toBe("MFA was never satisfied on any sign-in");
  // Could not check is its own routing, and needs no falsifier.
  const ne = (await handleTool(
    "ir_log",
    { decision: "no sign-in logs retained", routing: "not_evaluable", scenario: key },
    c,
  )) as { routing: string };
  expect(ne.routing).toBe("not_evaluable");
});

test("ruled_out with no check that came back met or not_met is refused", async () => {
  const c = await ctx();
  const [a, b] = c.corpus.criteria.map((x) => x.id) as [string, string];
  const log = (outcomes: Record<string, string>) =>
    handleTool(
      "ir_log",
      { decision: "close", routing: "ruled_out", falsifier: "no data", outcomes },
      c,
    );
  for (const outcomes of [
    { [a]: "not_evaluable", [b]: "not_evaluable" },
    { [a]: "inconclusive" },
    { [a]: "inconclusive", [b]: "not_evaluable" },
  ]) {
    await expect(log(outcomes)).rejects.toThrow(/needs at least one outcome met or not_met/);
  }
  expect(await log({ [a]: "not_evaluable", [b]: "not_met" })).toBeDefined();
  expect(await log({ [a]: "inconclusive", [b]: "met" })).toBeDefined();
});

test("ruled_out on named criteria needs the determinate check to be one of them", async () => {
  const c = await ctx();
  const [a, b] = c.corpus.criteria.map((x) => x.id) as [string, string];
  const log = (outcomes: Record<string, string>) =>
    handleTool(
      "ir_log",
      {
        decision: "close",
        routing: "ruled_out",
        falsifier: "MFA never satisfied",
        criteria_ids: [a],
        outcomes,
      },
      c,
    );
  await expect(log({ [a]: "not_evaluable", [b]: "not_met" })).rejects.toThrow(
    /met or not_met for one of the named criteria_ids/,
  );
  expect(await log({ [a]: "not_met", [b]: "not_evaluable" })).toBeDefined();
});

test("outcomes take known criterion ids and the fixed outcome vocabulary only", async () => {
  const c = await ctx();
  const id = c.corpus.criteria[0]?.id as string;
  const log = (outcomes: unknown) => handleTool("ir_log", { decision: "x", outcomes }, c);
  const r = (await log({ [id]: "not_evaluable" })) as { outcomes: Record<string, string> };
  expect(r.outcomes).toEqual({ [id]: "not_evaluable" });
  await expect(log({ [id]: "maybe" })).rejects.toThrow(/outcomes values must be one of met/);
  await expect(log({ "made-up": "met" })).rejects.toThrow(/unknown outcomes ids: made-up/);
  await expect(log([id])).rejects.toThrow(/must be an object/);
  await expect(log("met")).rejects.toThrow(/must be an object/);
});

test("read tools are annotated read-only; the two writers local and non-destructive", () => {
  for (const t of TOOL_SCHEMAS) {
    const a = t.annotations as { readOnlyHint: boolean; destructiveHint?: boolean };
    const writes = t.name === "ir_log" || t.name === "ir_propose";
    expect(a.readOnlyHint).toBe(!writes);
    if (writes) expect(a.destructiveHint).toBe(false);
  }
});

test("every string in every tool schema advertises the text limit", () => {
  const strings: unknown[] = [];
  const walk = (n: unknown): void => {
    if (Array.isArray(n)) n.forEach(walk);
    else if (n && typeof n === "object") {
      const o = n as Record<string, unknown>;
      if (o.type === "string") strings.push(o.maxLength);
      Object.values(o).forEach(walk);
    }
  };
  walk(TOOL_SCHEMAS);
  expect(strings.length).toBeGreaterThan(10);
  expect(strings.every((m) => m === MAX_TEXT_CHARS)).toBe(true);
});

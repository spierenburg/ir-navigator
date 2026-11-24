import { expect, test } from "bun:test";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { REVOKED_INTO } from "../src/coverage/snapshot.ts";
import { loadCorpus, loadPlaybook } from "../src/load.ts";
import { STATUSES, type Status } from "../src/types.ts";
import { DEMO_PLAYBOOK, tmp } from "./fixtures.ts";

test("parses a playbook file and preserves query line breaks", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const pb = await loadPlaybook(join(d, "demo.yaml"));
  expect(pb.playbook).toBe("demo");
  expect(pb.criteria[0]?.stage).toBe("Stage 2 · Foothold");
  expect(pb.criteria[0]?.status).toBe("active");
  expect(pb.criteria[0]?.attack).toEqual(["T1219"]);
  expect(pb.criteria[0]?.query).toContain("\n");
  expect(pb.criteria[0]?.query).toContain("Timestamp > ago(14d)");
  rmSync(d, { recursive: true, force: true });
});

test("loadCorpus tags every item with its playbook", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK });
  const c = await loadCorpus(d);
  expect(c.criteria[0]?.playbook).toBe("demo");
  expect(c.scenarios[0]?.playbook).toBe("demo");
  expect(c.playbooks[0]?.scenario_count).toBe(1);
  rmSync(d, { recursive: true, force: true });
});

test("loadCorpus serves active only by default — a draft never reaches an analyst", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK.replaceAll('"active"', '"draft"') });
  const c = await loadCorpus(d);
  expect(c.criteria).toHaveLength(0);
  expect(c.scenarios).toHaveLength(0);
  expect(c.playbooks[0]?.scenario_count).toBe(0);
  rmSync(d, { recursive: true, force: true });
});

test("a record with an unknown status fails loud, not silently unserved", async () => {
  const d = tmp({ "demo.yaml": DEMO_PLAYBOOK.replaceAll('status: "active"', 'status: "activ"') });
  await expect(loadPlaybook(join(d, "demo.yaml"))).rejects.toThrow(/status/i);
  rmSync(d, { recursive: true, force: true });
});

test("duplicate criterion ids across the corpus fail loud", async () => {
  const d = tmp({
    "a.yaml": DEMO_PLAYBOOK,
    "b.yaml": DEMO_PLAYBOOK.replace('playbook: "demo"', 'playbook: "demo2"'),
  });
  await expect(loadCorpus(d)).rejects.toThrow(/duplicate/i);
  rmSync(d, { recursive: true, force: true });
});

test("throws on a malformed playbook rather than loading partial data", async () => {
  const d = tmp({ "bad.yaml": 'playbook: "x"\ntitle: "X"\n' });
  await expect(loadPlaybook(join(d, "bad.yaml"))).rejects.toThrow(/missing|invalid/i);
  rmSync(d, { recursive: true, force: true });
});

test("the migrated corpus loads: 9 playbooks, full criteria set, coverage gaps visible", async () => {
  const c = await loadCorpus(join(import.meta.dir, "..", "criteria"));
  expect(c.playbooks).toHaveLength(9);
  // Floors, not exact pins: promotions legitimately grow the corpus after the fork.
  expect(c.criteria.length).toBeGreaterThanOrEqual(392);
  expect(c.scenarios.length).toBeGreaterThanOrEqual(30);
  expect(c.steps.length).toBeGreaterThanOrEqual(48);
  expect(c.actions.length).toBeGreaterThanOrEqual(176);
  expect(c.playbooks.filter((p) => p.scenario_count === 0).map((p) => p.slug)).toEqual([
    "bec-response",
    "device-code-response",
  ]);
});

test("no record in the corpus carries an ATT&CK id that has been revoked", async () => {
  const c = await loadCorpus(join(import.meta.dir, "..", "criteria"), [...STATUSES] as Status[]);
  const used = [...c.criteria, ...c.scenarios, ...c.actions].flatMap((x) => x.attack);
  expect(used.filter((t) => t in REVOKED_INTO)).toEqual([]);
});

test("throws when the criteria directory is empty", async () => {
  const d = tmp({});
  await expect(loadCorpus(d)).rejects.toThrow(/no playbook/i);
  rmSync(d, { recursive: true, force: true });
});

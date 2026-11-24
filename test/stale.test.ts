import { expect, test } from "bun:test";
import { staleReport } from "../src/review.ts";

const criteria = ["a", "b", "c", "d", "e"].map((id) => ({ id }));
const row = (r: Record<string, unknown>) => JSON.stringify(r);
const delivery = (ids: string[]) => row({ tool: "ir_search", surfaced: { results_ids: ids } });
const decision = (args: Record<string, unknown>) => row({ tool: "ir_log", args, surfaced: {} });

const section = (lines: string[], title: RegExp): string[] => {
  const at = lines.findIndex((l) => title.test(l));
  expect(at).toBeGreaterThanOrEqual(0);
  const rest = lines.slice(at + 1);
  const end = rest.findIndex((l) => !l.startsWith("  "));
  return (end === -1 ? rest : rest.slice(0, end)).map((l) => l.trim());
};

test("each section counts what it says, from successful rows only", () => {
  const log = [
    delivery(["a", "b"]),
    delivery(["a", "b"]),
    delivery(["a", "b", "c"]),
    // A refused call surfaced nothing, whatever its row carries.
    row({ tool: "ir_search", error: "unknown playbook", surfaced: { results_ids: ["e"] } }),
    decision({ criteria_ids: ["b"] }),
    decision({ outcomes: { c: "not_evaluable", d: "not_met" } }),
    decision({ outcomes: { c: "not_evaluable", d: "inconclusive" } }),
  ].join("\n");
  const lines = staleReport(criteria, log);
  expect(lines[0]).toBe("2/5 active criteria never surfaced since the log began");
  expect(section(lines, /never surfaced/)).toEqual(["d", "e"]);
  expect(section(lines, /never cited/)).toEqual(["a (surfaced 3)"]);
  expect(section(lines, /mostly not_evaluable/)).toEqual(["c (2/2)"]);
  // c was never evaluable, so it is not counted as never met; d was, twice.
  expect(section(lines, /never met/)).toEqual(["d (0/2 met)"]);
});

test("an empty log reports every criterion as never surfaced and nothing else", () => {
  const lines = staleReport(criteria, "");
  expect(section(lines, /never surfaced/)).toHaveLength(5);
  expect(section(lines, /never cited/)).toEqual([]);
  expect(section(lines, /never met/)).toEqual([]);
  expect(lines.some((l) => /unreadable/.test(l))).toBe(false);
});

test("a torn or non-object line is counted and skipped, not fatal", () => {
  const log = [delivery(["a"]), '{"tool":"ir_sea', "null", "[1]", delivery(["a"])].join("\n");
  const lines = staleReport(criteria, log);
  expect(section(lines, /never surfaced/)).toEqual(["b", "c", "d", "e"]);
  expect(lines.at(-1)).toBe("3 log line(s) unreadable and skipped");
});

test("a log that is gone is said before the report, so it cannot pass for an empty one", async () => {
  const { staleLines } = await import("../src/review.ts");
  const gone = staleLines(criteria, null, "/x/provenance.jsonl");
  expect(gone[0]).toBe(
    "no provenance log at /x/provenance.jsonl — every criterion below reads as never surfaced",
  );
  expect(gone.slice(1)).toEqual(staleReport(criteria, ""));
  // An empty log that exists gets no note.
  expect(staleLines(criteria, "", "/x/provenance.jsonl")).toEqual(staleReport(criteria, ""));
});

import { expect, test } from "bun:test";
import { emitYaml } from "../src/emit.ts";
import type { PlaybookFile } from "../src/types.ts";

// No HTML/YAML-source dependency, so it outlives the migration and keeps the
// emitter pinned for the review CLI's promotion path.
const PB: PlaybookFile = {
  playbook: "demo",
  title: "Demo",
  platforms: ["Defender XDR / Sentinel"],
  scenarios: [
    {
      id: "1",
      status: "active",
      source: "landing-page@2026-10-10",
      validated_at: null,
      supersedes: null,
      name: "Encryption in Progress",
      indicators: "ransom notes appearing",
      discriminator: "Speed beats precision. Exception: single host.",
      attack: [],
      window: "14d back from the first indicator",
    },
  ],
  criteria: [
    {
      id: "demo/defender/s2-rmm-tools-first-seen",
      status: "active",
      source: "landing-page@2026-10-10",
      validated_at: null,
      supersedes: null,
      stage: "Stage 2 · Foothold",
      stage_ord: 2,
      platform: "Defender XDR / Sentinel",
      title: "RMM tools, first seen",
      why: "Operators install legitimate RMM tools.",
      how: null,
      fp: "Helpdesk hosts use AnyDesk legitimately.",
      query: "DeviceProcessEvents\n| where Timestamp > ago(14d)",
      tested: null,
      attack: ["T1219"],
    },
  ],
  steps: [{ ord: 1, time: "T+0–15 min", title: "Declare", why: "one owner", critical: true }],
  actions: [
    {
      platform: "Defender XDR / Sentinel",
      label: "T+15–30 · Isolate",
      name: "Isolate every host",
      tier: "destructive",
      tier_inferred: false,
      why: "piecemeal isolation tips the operator",
      how: "Console: device page › Isolate device (Full)",
      body: 'POST /api/machines/{id}/isolate\n{"IsolationType": "Full"}',
      attack: ["T1489"],
    },
  ],
};

test("a long id in first list-item position survives the round-trip", () => {
  const longId =
    "clickfix-response/crowdstrike/s2-the-pasted-command-from-the-run-dialog-the-exploit-chain";
  const longWhy =
    "A deliberately long single-line why field that exceeds eighty characters to pin the quoted-scalar path for prose.";
  const pb: PlaybookFile = {
    ...PB,
    criteria: [
      { ...(PB.criteria[0] as NonNullable<(typeof PB.criteria)[0]>), id: longId, why: longWhy },
    ],
  };
  const back = Bun.YAML.parse(emitYaml(pb)) as PlaybookFile;
  expect(back.criteria[0]?.id).toBe(longId);
  expect(back.criteria[0]?.why).toBe(longWhy);
});

test("emitYaml writes block style that round-trips with lifecycle and line breaks intact", () => {
  const yaml = emitYaml(PB);
  expect(yaml).not.toContain("\\n");
  const back = Bun.YAML.parse(yaml) as PlaybookFile;
  expect(back.criteria[0]?.status).toBe("active");
  expect(back.criteria[0]?.validated_at).toBeNull();
  expect(back.criteria[0]?.supersedes).toBeNull();
  expect(back.criteria[0]?.how).toBeNull();
  expect(back.criteria[0]?.query).toContain("\n");
  expect(back.criteria[0]?.attack).toEqual(["T1219"]);
  expect(back.scenarios[0]?.discriminator).toContain("Exception:");
  expect(back.scenarios[0]?.window).toBe("14d back from the first indicator");
  expect(back.actions[0]?.body).toContain('"Full"');
  expect(back.steps[0]?.critical).toBe(true);
});

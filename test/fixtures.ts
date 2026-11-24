import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const DEMO_PLAYBOOK = `playbook: "demo"
title: "Demo"
platforms:
  - "Defender XDR / Sentinel"
scenarios:
  - id: "1"
    status: "active"
    source: "landing-page-2026-10-10"
    validated_at: null
    supersedes: null
    name: "Encryption in Progress"
    indicators: "ransom notes, mass file renames"
    discriminator: "Speed beats precision."
    attack: []
    window: null
criteria:
  - id: "demo/defender/s2-rmm-tools-first-seen"
    status: "active"
    source: "landing-page-2026-10-10"
    validated_at: null
    supersedes: null
    stage: "Stage 2 · Foothold"
    stage_ord: 2
    platform: "Defender XDR / Sentinel"
    title: "RMM tools, first seen"
    why: "Operators install legitimate RMM tools."
    how: null
    fp: "Helpdesk hosts use AnyDesk legitimately."
    query: |
      DeviceProcessEvents
      | where Timestamp > ago(14d)
    tested: null
    attack: ["T1219"]
steps: []
actions: []
`;

export function tmp(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "irnav-"));
  for (const [n, c] of Object.entries(files)) writeFileSync(join(d, n), c);
  return d;
}

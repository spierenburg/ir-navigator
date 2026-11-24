#!/usr/bin/env bun
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadCorpus } from "../load.ts";
import { buildSnapshot, type CallTool, corpusTechniques, isGap } from "./snapshot.ts";

const ROOT = join(import.meta.dir, "..", "..");
const OUT = join(ROOT, "index", "coverage.json");

/** No default for an infrastructure dependency or its credentials — absence fails loud. */
function requireEnv(name: string, hint: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set — ${hint}`);
  return v;
}

const url = new URL(
  requireEnv(
    "IRNAV_DETECTIONS_URL",
    "point it at the Security Detections MCP streamable-HTTP endpoint, e.g. https://detections.example.org/mcp",
  ),
);
const auth = requireEnv(
  "IRNAV_DETECTIONS_AUTH",
  "set it to user:password for the server's basic auth",
);
if (!auth.includes(":")) throw new Error("IRNAV_DETECTIONS_AUTH must be user:password");

const corpus = await loadCorpus(join(ROOT, "criteria"));
const ids = corpusTechniques(corpus);

const client = new Client({ name: "ir-navigator-coverage", version: "0.1.0" });
await client.connect(
  new StreamableHTTPClientTransport(url, {
    requestInit: { headers: { Authorization: `Basic ${btoa(auth)}` } },
  }),
);

// The server behind supergateway starts a fresh process per request; under its
// memory limit that process is sometimes SIGKILLed while loading ATT&CK data,
// and the request is never answered. Requests are read-only, so pace them and
// retry a timeout rather than wait out a reply that will not come. A layer
// takes ~10 s when it does run.
const TIMEOUT_MS = 90_000;
const PAUSE_MS = 5_000;
const ATTEMPTS = 3;

type ToolResult = { isError?: boolean; content?: { type: string; text?: string }[] };

async function callWithRetry(name: string, args: Record<string, unknown>): Promise<ToolResult> {
  for (let attempt = 1; ; attempt++) {
    await Bun.sleep(PAUSE_MS);
    try {
      return (await client.callTool({ name, arguments: args }, undefined, {
        timeout: TIMEOUT_MS,
      })) as ToolResult;
    } catch (e) {
      const msg = (e as Error).message;
      if (attempt >= ATTEMPTS || !/timed out/i.test(msg)) {
        throw new Error(`${name} ${JSON.stringify(args)} (attempt ${attempt}/${ATTEMPTS}): ${msg}`);
      }
      process.stderr.write(
        `[build:coverage] ${name} ${JSON.stringify(args)} timed out — retry ${attempt + 1}/${ATTEMPTS}\n`,
      );
    }
  }
}

let calls = 0;
const call: CallTool = async (name, args) => {
  const r = await callWithRetry(name, args);
  calls += 1;
  const text = r.content?.find((c) => c.type === "text")?.text;
  if (r.isError || text === undefined) {
    throw new Error(`${name} ${JSON.stringify(args)} failed: ${text ?? "no text content"}`);
  }
  const body = JSON.parse(text) as { error?: boolean; message?: string };
  if (body?.error) throw new Error(`${name} ${JSON.stringify(args)}: ${body.message ?? "error"}`);
  process.stderr.write(`[build:coverage] ${calls}/8 ${name} ${JSON.stringify(args)}\n`);
  return body;
};

try {
  const snap = await buildSnapshot(ids, call, url.host);
  await Bun.write(OUT, `${JSON.stringify(snap, null, 2)}\n`);
  const rows = Object.values(snap.techniques);
  const gaps = Object.entries(snap.techniques)
    .filter(([, c]) => isGap(c))
    .map(([id]) => id);
  process.stderr.write(
    `[build:coverage] ${ids.length} techniques, ${calls} calls, ` +
      `${rows.filter((c) => c.count > 0).length} with exact detections, ${gaps.length} gaps → ${OUT}\n` +
      (gaps.length > 0 ? `[build:coverage] gaps: ${gaps.join(", ")}\n` : ""),
  );
} finally {
  await client.close();
}

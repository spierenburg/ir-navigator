#!/usr/bin/env bun
import { join } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { loadCoverage } from "./coverage/snapshot.ts";
import { EMBED_MODEL, embedBatch } from "./index/embed.ts";
import { loadIndex } from "./index/load.ts";
import { loadCorpus } from "./load.ts";
import { provenancePath } from "./provenance.ts";
import { TOOL_SCHEMAS } from "./schemas.ts";
import { type Ctx, handleTool } from "./tools.ts";

const ROOT = join(import.meta.dir, "..");

// No fallback: a missing or stale corpus/index must stop the server, never serve wrong criteria.
const corpus = await loadCorpus(join(ROOT, "criteria"));
// The model is checked only when queries are embedded: an exact-only server never compares vectors.
const index = await loadIndex(
  join(ROOT, "index", "vectors.json"),
  corpus,
  process.env.IRNAV_EMBED_URL ? EMBED_MODEL : null,
);
// Optional by design: absent means every brief says coverage is unavailable.
const coverage = await loadCoverage(join(ROOT, "index", "coverage.json"), corpus);
if (coverage === null) {
  process.stderr.write(
    "[ir-navigator] no coverage snapshot — briefs report coverage unavailable\n",
  );
} else if (coverage.outdated) {
  process.stderr.write(
    `[ir-navigator] coverage snapshot is outdated (${coverage.outdated}): every technique reads as unknown\n`,
  );
} else if (coverage.stale) {
  process.stderr.write(
    `[ir-navigator] coverage snapshot is stale: ${coverage.missing.length} technique(s) unknown — run 'bun run build:coverage'\n`,
  );
}

const embedConfigured = Boolean(process.env.IRNAV_EMBED_URL);
if (!embedConfigured) {
  process.stderr.write(
    "[ir-navigator] IRNAV_EMBED_URL not set — semantic ranking off, exact-term only. " +
      "Every response carries semantic_ranking:false.\n",
  );
}

const ctx: Ctx = {
  corpus,
  index,
  inboxDir: join(ROOT, "criteria", "_inbox"),
  provenanceLog: provenancePath(),
  coverage,
  // Query-time embedding is best-effort: if the embedding host is down, ranking
  // degrades to exact-term only rather than failing the call. Every response
  // carries semantic_ranking so the degradation is visible per call, not only on stderr.
  embed: async (text: string) => {
    if (!embedConfigured) return null;
    try {
      return (await embedBatch([text]))[0] ?? null;
    } catch {
      process.stderr.write("[ir-navigator] embed unavailable — exact-term ranking only\n");
      return null;
    }
  },
};

const server = new Server(
  { name: "ir-navigator", version: "0.1.0" },
  { capabilities: { tools: {} } },
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_SCHEMAS }));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  try {
    const result = await handleTool(name, args as Record<string, unknown>, ctx);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return { content: [{ type: "text", text: (err as Error).message }], isError: true };
  }
});

process.stderr.write(
  `[ir-navigator] ${corpus.playbooks.length} playbooks, ${corpus.criteria.length} criteria, ` +
    `${corpus.scenarios.length} scenarios, ${TOOL_SCHEMAS.length} tools, provenance=${provenancePath()}\n`,
);
/**
 * The largest message a client may send. The SDK default is 10 MiB, enough for
 * an initialize request whose unbounded `icons` list makes zod build one issue
 * per entry (CVE-2023-54404, unfixed in zod for lists with no maximum). A call
 * within MAX_CALL_TEXT_UNITS (schemas.ts) always fits; one over it gets a tool
 * error, not this cap. Only a message over 256 KiB itself closes the session.
 */
const MAX_MESSAGE_BYTES = 256 * 1024;

const transport = new StdioServerTransport(process.stdin, process.stdout, {
  maxBufferSize: MAX_MESSAGE_BYTES,
});
// An over-cap message closes the transport (SDK behaviour): say so and exit
// non-zero, rather than end the session silently with status 0. Other transport
// errors (a line that is not JSON-RPC) are logged; the SDK carries on after them.
transport.onerror = (err) => {
  const closing = err.message.includes("ReadBuffer exceeded");
  process.stderr.write(
    `[ir-navigator] transport error${closing ? ", closing" : ""}: ${err.message}\n`,
  );
  if (closing) process.exitCode = 1;
};
await server.connect(transport);

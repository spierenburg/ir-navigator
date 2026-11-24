import { join } from "node:path";
import { loadCorpus } from "../load.ts";
import { embedBatch, EMBED_MODEL as MODEL } from "./embed.ts";
import { corpusHash, embedText } from "./load.ts";

const CRITERIA = join(import.meta.dir, "..", "..", "criteria");
const OUT = join(import.meta.dir, "..", "..", "index", "vectors.json");

const corpus = await loadCorpus(CRITERIA);
const ids = [
  ...corpus.criteria.map((c) => c.id),
  ...corpus.scenarios.map((s) => `${s.playbook}/scenario-${s.id}`),
];
const texts = [...corpus.criteria.map(embedText), ...corpus.scenarios.map(embedText)];

const vectors = await embedBatch(texts);
const dims = vectors[0]?.length ?? 0;
if (dims === 0) throw new Error("embedding produced zero-dimensional vectors");
await Bun.write(
  OUT,
  `${JSON.stringify({ hash: corpusHash(corpus), model: MODEL, dims, ids, vectors })}\n`,
);
process.stderr.write(`[build:index] wrote ${ids.length} vectors (${dims} dims) to ${OUT}\n`);

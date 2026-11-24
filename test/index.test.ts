import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { corpusHash, loadIndex, usableQueryVector } from "../src/index/load.ts";
import { loadCorpus } from "../src/load.ts";

const CRITERIA = join(import.meta.dir, "..", "criteria");
const INDEX = join(import.meta.dir, "..", "index", "vectors.json");

test("the committed index matches the committed corpus", async () => {
  const corpus = await loadCorpus(CRITERIA);
  const idx = await loadIndex(INDEX, corpus);
  expect(idx.dims).toBeGreaterThan(0);
  expect(idx.ids.length).toBe(corpus.criteria.length + corpus.scenarios.length);
  expect(idx.vectors[0]).toHaveLength(idx.dims);
});

test("corpusHash changes when any criterion text changes", async () => {
  const corpus = await loadCorpus(CRITERIA);
  const before = corpusHash(corpus);
  const first = corpus.criteria[0];
  expect(first).toBeDefined();
  if (first) first.why = `${first.why} edited`;
  expect(corpusHash(corpus)).not.toBe(before);
});

test("loadIndex throws on a stale index rather than ranking wrong", async () => {
  const d = mkdtempSync(join(tmpdir(), "irnav-idx-"));
  const corpus = await loadCorpus(CRITERIA);
  await Bun.write(
    join(d, "vectors.json"),
    JSON.stringify({ hash: "0".repeat(64), model: "x", dims: 768, ids: [], vectors: [] }),
  );
  await expect(loadIndex(join(d, "vectors.json"), corpus)).rejects.toThrow(/stale|build:index/i);
  rmSync(d, { recursive: true, force: true });
});

test("loadIndex throws when the index is absent", async () => {
  const d = mkdtempSync(join(tmpdir(), "irnav-idx-"));
  const corpus = await loadCorpus(CRITERIA);
  await expect(loadIndex(join(d, "vectors.json"), corpus)).rejects.toThrow(/not found/i);
  rmSync(d, { recursive: true, force: true });
});

test("loadIndex refuses an index built with another model than queries will use", async () => {
  const corpus = await loadCorpus(CRITERIA);
  const idx = await loadIndex(INDEX, corpus);
  await expect(loadIndex(INDEX, corpus, `${idx.model}-other`)).rejects.toThrow(/built with/);
  // The matching model, or no query-time embedding at all, loads.
  expect((await loadIndex(INDEX, corpus, idx.model)).dims).toBe(idx.dims);
  expect((await loadIndex(INDEX, corpus, null)).dims).toBe(idx.dims);
});

test("loadIndex refuses vectors that do not match dims", async () => {
  const d = mkdtempSync(join(tmpdir(), "irnav-idx-"));
  const corpus = await loadCorpus(CRITERIA);
  const idx = await loadIndex(INDEX, corpus);
  const bad = { ...idx, vectors: [idx.vectors[0]?.slice(1), ...idx.vectors.slice(1)] };
  await Bun.write(join(d, "vectors.json"), JSON.stringify(bad));
  await expect(loadIndex(join(d, "vectors.json"), corpus)).rejects.toThrow(/malformed/);
  rmSync(d, { recursive: true, force: true });
});

test("a query vector of the wrong length or with NaN ranks exact-term only", async () => {
  const corpus = await loadCorpus(CRITERIA);
  const idx = await loadIndex(INDEX, corpus);
  const ok = Array.from({ length: idx.dims }, () => 0.1);
  expect(usableQueryVector(ok, idx)).toBe(ok);
  expect(usableQueryVector(ok.slice(0, 64), idx)).toBeNull();
  expect(usableQueryVector([...ok.slice(1), Number.NaN], idx)).toBeNull();
  expect(usableQueryVector(null, idx)).toBeNull();
});

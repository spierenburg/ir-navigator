import type { Corpus } from "../types.ts";

export type VectorIndex = {
  hash: string;
  model: string;
  dims: number;
  ids: string[];
  vectors: number[][];
};

/** Text each item is embedded from — must match build and hash exactly. */
export function embedText(item: {
  title?: string;
  why?: string;
  name?: string;
  indicators?: string;
}): string {
  if (item.indicators !== undefined) return `${item.name ?? ""}. ${item.indicators}`.trim();
  return `${item.title ?? ""}. ${item.why ?? ""}`.trim();
}

export function corpusHash(corpus: Corpus): string {
  const h = new Bun.CryptoHasher("sha256");
  for (const c of corpus.criteria) h.update(`${c.id}\u0000${embedText(c)}\u0000`);
  for (const s of corpus.scenarios) h.update(`${s.playbook}/${s.id}\u0000${embedText(s)}\u0000`);
  return h.digest("hex");
}

/**
 * `model` is the embedding model queries will use, or null when nothing is embedded at query
 * time. A query vector from another model is the same length or near it and scores as noise,
 * so a mismatch stops the server at boot the way a stale corpus hash does.
 */
export async function loadIndex(
  path: string,
  corpus: Corpus,
  model: string | null = null,
): Promise<VectorIndex> {
  const file = Bun.file(path);
  if (!(await file.exists())) {
    throw new Error(`vector index not found: ${path} — run 'bun run build:index'`);
  }
  const idx = (await file.json()) as VectorIndex;
  const expected = corpusHash(corpus);
  if (idx.hash !== expected) {
    throw new Error(
      "vector index is stale: criteria changed since it was built " +
        `(index ${idx.hash.slice(0, 12)}, corpus ${expected.slice(0, 12)}) — run 'bun run build:index'`,
    );
  }
  const shapeOk =
    Number.isInteger(idx.dims) &&
    idx.dims > 0 &&
    Array.isArray(idx.ids) &&
    Array.isArray(idx.vectors) &&
    idx.ids.length === idx.vectors.length &&
    idx.vectors.every((v) => isVector(v, idx.dims));
  if (!shapeOk) {
    throw new Error(
      `vector index is malformed: every vector must be ${idx.dims} finite numbers, one per id — run 'bun run build:index'`,
    );
  }
  if (model !== null && idx.model !== model) {
    throw new Error(
      `vector index was built with ${idx.model}, but queries would be embedded with ${model} — ` +
        "set IRNAV_EMBED_MODEL to match, or rebuild with 'bun run build:index'",
    );
  }
  return idx;
}

const isVector = (v: unknown, dims: number): boolean =>
  Array.isArray(v) && v.length === dims && v.every((x) => Number.isFinite(x));

/**
 * A query vector the index cannot be compared with (wrong length, or NaN from a broken host)
 * is dropped, so the call ranks exact-term only and says semantic_ranking:false, instead of
 * scoring a partial or meaningless cosine as if it were hybrid.
 */
export function usableQueryVector(v: number[] | null, idx: VectorIndex): number[] | null {
  if (v === null) return null;
  if (isVector(v, idx.dims)) return v;
  process.stderr.write(
    `[ir-navigator] query embedding has ${v.length} dims or non-finite values, index has ${idx.dims} — exact-term ranking only\n`,
  );
  return null;
}

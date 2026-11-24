export const EMBED_MODEL = process.env.IRNAV_EMBED_MODEL ?? "nomic-embed-text";
const MODEL = EMBED_MODEL; // short local name for the request body and errors
const BATCH = 32;
/** A host that accepts the connection and never answers must fail, not hang every query. */
const TIMEOUT_MS = 15_000;

/** No fallback URL for an infrastructure dependency — absence must fail loud. */
export function embedUrl(): string {
  const url = process.env.IRNAV_EMBED_URL;
  if (!url) {
    throw new Error(
      "IRNAV_EMBED_URL is not set — point it at an OpenAI-compatible /v1/embeddings " +
        "server (e.g. llama.cpp at http://localhost:8082)",
    );
  }
  return url.replace(/\/$/, "");
}

type EmbedResponse = { data?: { embedding?: number[] }[] };

export async function embedBatch(texts: string[]): Promise<number[][]> {
  const base = embedUrl();
  const out: number[][] = [];
  for (let i = 0; i < texts.length; i += BATCH) {
    const slice = texts.slice(i, i + BATCH);
    const res = await fetch(`${base}/v1/embeddings`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: MODEL, input: slice }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) {
      throw new Error(`embedding failed (${res.status}) against ${base} model=${MODEL}`);
    }
    const body = (await res.json()) as EmbedResponse;
    const vectors = (body.data ?? []).map((d) => d.embedding);
    if (vectors.length !== slice.length || vectors.some((v) => !v || v.length === 0)) {
      throw new Error(
        `embedding returned ${vectors.length} vectors for ${slice.length} inputs (model=${MODEL})`,
      );
    }
    out.push(...(vectors as number[][]));
    process.stderr.write(`[build:index] embedded ${out.length}/${texts.length}\n`);
  }
  return out;
}

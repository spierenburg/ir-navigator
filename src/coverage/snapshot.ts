import type { Corpus } from "../types.ts";

/**
 * Detection coverage per ATT&CK technique, taken from the Security Detections
 * MCP corpus at build time. It counts public rules that exist, not rules
 * deployed or tested in any tenant.
 */
export type TechniqueCoverage = {
  /** Detections tagged with exactly this id. */
  count: number;
  /** Per rule format, detections tagged with exactly this id. Formats with none are omitted. */
  by_source: Record<string, number>;
  /** For a parent id: its sub-techniques that have at least one detection. Exact-id counts miss these. */
  covered_subtechniques: string[];
  /**
   * Detections tagged with an id revoked into this one (or, for a parent, into one of its
   * sub-techniques), per old id. Omitted when there are none.
   */
  revoked_ids?: Record<string, number>;
};

/**
 * ATT&CK v19 (2026-04-14) revocations of techniques that were live until then,
 * old id → successor, from the revoked-by relationships in enterprise-attack-20.0.json.
 * Public rule sets lag MITRE: a corpus on current ids would otherwise read as
 * gaps where hundreds of rules exist under the old id.
 */
export const REVOKED_INTO: Readonly<Record<string, string>> = {
  T1562: "T1685",
  "T1562.001": "T1685",
  "T1562.002": "T1685.001",
  "T1562.003": "T1690",
  "T1562.004": "T1686",
  "T1562.006": "T1685",
  "T1562.007": "T1686.001",
  "T1562.008": "T1685.002",
  "T1562.009": "T1688",
  "T1562.010": "T1689",
  "T1562.011": "T1685.003",
  "T1562.012": "T1685.004",
  "T1562.013": "T1686.002",
  "T1070.001": "T1685.005",
  "T1070.002": "T1685.006",
  "T1574.002": "T1574.001",
  T1656: "T1684.001",
  T1672: "T1684.002",
};

/** Whether rules tagged `old` count for `id`: it was revoked into `id`, or into a sub-technique of parent `id`. */
function credits(old: string, id: string): boolean {
  if (!Object.hasOwn(REVOKED_INTO, old)) return false;
  const successor = REVOKED_INTO[old] as string;
  return successor === id || (!id.includes(".") && successor.startsWith(`${id}.`));
}

/** Rules under revoked predecessors of `id`, or of its sub-techniques when `id` is a parent. */
function revokedCounts(id: string, all: Map<string, number>): Record<string, number> | null {
  const out: Record<string, number> = {};
  for (const old of Object.keys(REVOKED_INTO)) {
    const n = all.get(old) ?? 0;
    if (credits(old, id) && n > 0) out[old] = n;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/** sha256 of the REVOKED_INTO table a snapshot was built with: a changed table changes the credit. */
export function revokedHash(): string {
  const h = new Bun.CryptoHasher("sha256");
  for (const old of Object.keys(REVOKED_INTO).sort())
    h.update(`${old}\u0000${REVOKED_INTO[old]}\u0000`);
  return h.digest("hex");
}

export type CoverageSnapshot = {
  /** 3 = carries revoked_ids and revoked_hash. Older snapshots read as stale, never as gaps. */
  version: 3;
  revoked_hash: string;
  /** sha256 of the sorted corpus technique ids the snapshot was built for. */
  techniques_hash: string;
  built_at: string;
  /** Host only — never the credentials. */
  source_host: string;
  techniques: Record<string, TechniqueCoverage>;
};

export const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;

export function corpusTechniques(corpus: Corpus): string[] {
  const ids = new Set<string>();
  for (const c of corpus.criteria) for (const t of c.attack) ids.add(t);
  for (const s of corpus.scenarios) for (const t of s.attack) ids.add(t);
  return [...ids].filter((t) => TECHNIQUE_ID.test(t)).sort();
}

export function techniquesHash(ids: string[]): string {
  const h = new Bun.CryptoHasher("sha256");
  for (const id of [...ids].sort()) h.update(`${id}\u0000`);
  return h.digest("hex");
}

/** One MCP tool call against the detections server, result already JSON-parsed. */
export type CallTool = (name: string, args: Record<string, unknown>) => Promise<unknown>;

export const SOURCES = [
  "sigma",
  "splunk_escu",
  "elastic",
  "kql",
  "sublime",
  "crowdstrike_cql",
  "jamf_protect",
] as const;

// The navigator layer carries the exact count only in its comment ("52 detection(s)");
// its score is capped at 100. Anything else in the comment fails the build.
const COUNT_COMMENT = /^(\d+) detection\(s\)$/;

/** technique id → exact detection count, from one generate_navigator_layer answer. */
function layerCounts(result: unknown, label: string): Map<string, number> {
  const techniques = (result as { techniques?: unknown })?.techniques;
  if (!Array.isArray(techniques)) {
    throw new Error(`generate_navigator_layer (${label}) returned no techniques array`);
  }
  const out = new Map<string, number>();
  for (const t of techniques as { techniqueID?: unknown; comment?: unknown }[]) {
    // The layer also lists non-technique ids (groups); those never reach the snapshot.
    // Remote text that is not a T-id must not reach the client's context through it.
    if (typeof t.techniqueID === "string" && !TECHNIQUE_ID.test(t.techniqueID)) continue;
    const m = COUNT_COMMENT.exec(String(t.comment ?? ""));
    const n = m ? Number(m[1]) : Number.NaN;
    if (typeof t.techniqueID !== "string" || !Number.isSafeInteger(n)) {
      throw new Error(
        `generate_navigator_layer (${label}) entry without a parseable count: ${JSON.stringify(t).slice(0, 200)}`,
      );
    }
    out.set(t.techniqueID, n);
  }
  return out;
}

/**
 * Eight calls: one navigator layer over every rule, one per rule format.
 * The detections server behind supergateway starts a fresh process for every
 * request, so one call per technique (~110) exhausted its memory mid-build.
 * Any malformed answer throws — a snapshot built on a partial read would
 * report false gaps.
 */
export async function buildSnapshot(
  ids: string[],
  call: CallTool,
  sourceHost: string,
  now: () => Date = () => new Date(),
): Promise<CoverageSnapshot> {
  const layer = (args: Record<string, unknown>) =>
    call("generate_navigator_layer", { name: "ir-navigator coverage", ...args });
  const all = layerCounts(await layer({}), "all");
  // An empty layer means the server has no rules loaded, not that nothing is covered.
  if (all.size === 0) {
    throw new Error(
      "generate_navigator_layer (all) returned no techniques — the server has no rules loaded",
    );
  }
  const bySource = new Map<string, Map<string, number>>();
  for (const src of SOURCES) {
    const counts = layerCounts(await layer({ source_type: src }), src);
    for (const [id, n] of counts) {
      if (n > (all.get(id) ?? 0)) {
        throw new Error(
          `generate_navigator_layer (${src}) counts ${n} for ${id}, more than the ${all.get(id) ?? 0} of the unfiltered layer`,
        );
      }
    }
    bySource.set(src, counts);
  }

  const techniques: Record<string, TechniqueCoverage> = {};
  for (const id of ids) {
    const by_source: Record<string, number> = {};
    for (const src of SOURCES) {
      const n = bySource.get(src)?.get(id) ?? 0;
      if (n > 0) by_source[src] = n;
    }
    const revoked = revokedCounts(id, all);
    techniques[id] = {
      count: all.get(id) ?? 0,
      by_source,
      // A revoked id still tagged in rule sets is credited once, under revoked_ids.
      covered_subtechniques: id.includes(".")
        ? []
        : [...all.keys()]
            .filter(
              (t) =>
                t.startsWith(`${id}.`) && (all.get(t) ?? 0) > 0 && !Object.hasOwn(REVOKED_INTO, t),
            )
            .sort(),
      ...(revoked ? { revoked_ids: revoked } : {}),
    };
  }
  return {
    version: 3,
    revoked_hash: revokedHash(),
    techniques_hash: techniquesHash(ids),
    built_at: now().toISOString(),
    source_host: sourceHost,
    techniques,
  };
}

export type CoverageView = {
  snapshot: CoverageSnapshot;
  /** Corpus techniques the snapshot was not built for — shown as unknown, never as gaps. */
  missing: string[];
  /** The corpus technique set changed since the build: rerun 'bun run build:coverage'. */
  stale: boolean;
  /** Why none of the snapshot's rows is served, when it was built by older code or another REVOKED_INTO. */
  outdated?: string;
};

const REBUILD = "rebuild with 'bun run build:coverage'";
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
// What URL.host can hold: a name (Docker service names carry '_'), IPv4, or bracketed IPv6.
const HOST = /^(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9._-]{1,253})(:\d{1,5})?$/;

/**
 * Absent snapshot = coverage unavailable, not an error: the server still
 * serves criteria, and every brief says coverage is off. A stale snapshot is
 * served with the techniques it lacks named, so they read as unknown, not as gaps.
 * An outdated one (older version, other REVOKED_INTO) credits the wrong rules, so
 * none of its rows is served: every technique reads as unknown.
 * Every served field reaches the client or decides a gap, so a malformed file throws.
 */
export async function loadCoverage(path: string, corpus: Corpus): Promise<CoverageView | null> {
  const file = Bun.file(path);
  if (!(await file.exists())) return null;
  const raw = (await file.json()) as Record<string, unknown> | null;
  const ids = corpusTechniques(corpus);
  const v = raw?.version;
  const otherTable = typeof raw?.revoked_hash === "string" && raw.revoked_hash !== revokedHash();
  if (v === 1 || v === 2 || (v === 3 && otherTable)) {
    const why =
      v === 3
        ? "built with a different REVOKED_INTO table"
        : `version ${v}, built before revoked-id credit`;
    return { snapshot: outdated(raw), missing: ids, stale: true, outdated: `${why} — ${REBUILD}` };
  }
  const snap = assertSnapshot(path, raw);
  const missing = ids.filter((t) => !Object.hasOwn(snap.techniques, t));
  return { snapshot: snap, missing, stale: snap.techniques_hash !== techniquesHash(ids) };
}

/** An outdated snapshot keeps only its validated build time and host. */
function outdated(raw: Record<string, unknown> | null): CoverageSnapshot {
  const at = String(raw?.built_at ?? "");
  const host = String(raw?.source_host ?? "");
  return {
    version: 3,
    revoked_hash: "",
    techniques_hash: "",
    built_at: isIsoUtc(at) ? at : "unknown",
    source_host: HOST.test(host) ? host : "unknown",
    techniques: {},
  };
}

function malformed(path: string, what: string): Error {
  return new Error(`coverage snapshot ${path} is malformed: ${what} — ${REBUILD}`);
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

const isCount = (n: unknown, min: number) => Number.isSafeInteger(n) && (n as number) >= min;

/** The shape alone lets 9999-99-99 through; it must also be a real instant. */
const isIsoUtc = (s: string) => ISO_UTC.test(s) && !Number.isNaN(Date.parse(s));

const ROW_KEYS = new Set(["count", "by_source", "covered_subtechniques", "revoked_ids"]);

function assertSnapshot(path: string, raw: Record<string, unknown> | null): CoverageSnapshot {
  if (raw?.version !== 3 || !isRecord(raw.techniques))
    throw malformed(path, "not a version 3 snapshot");
  if (typeof raw.techniques_hash !== "string") throw malformed(path, "techniques_hash");
  // A mismatching string was already routed to outdated; anything else here has no table tie.
  if (raw.revoked_hash !== revokedHash()) throw malformed(path, "revoked_hash");
  if (typeof raw.built_at !== "string" || !isIsoUtc(raw.built_at)) {
    throw malformed(path, "built_at");
  }
  if (typeof raw.source_host !== "string" || !HOST.test(raw.source_host)) {
    throw malformed(path, "source_host");
  }
  for (const [id, row] of Object.entries(raw.techniques)) assertTechnique(path, id, row);
  return raw as unknown as CoverageSnapshot;
}

function assertTechnique(path: string, id: string, c: unknown): void {
  if (!TECHNIQUE_ID.test(id) || !isRecord(c)) throw malformed(path, `technique ${id}`);
  // Rows are served to the client: an extra key would carry its text along.
  const extra = Object.keys(c).find((k) => !ROW_KEYS.has(k));
  if (extra !== undefined) throw malformed(path, `${id} has an unknown field`);
  if (!isCount(c.count, 0)) throw malformed(path, `${id} count`);
  const count = c.count as number;
  const sources = c.by_source;
  const okSources =
    isRecord(sources) &&
    Object.entries(sources).every(
      ([src, n]) =>
        (SOURCES as readonly string[]).includes(src) && isCount(n, 1) && (n as number) <= count,
    );
  if (!okSources) throw malformed(path, `${id} by_source`);
  const subs = c.covered_subtechniques;
  // A revoked id is credited once, under revoked_ids — never as a live sub-technique.
  const okSubs =
    Array.isArray(subs) &&
    new Set(subs).size === subs.length &&
    subs.every(
      (t) =>
        typeof t === "string" &&
        TECHNIQUE_ID.test(t) &&
        t.startsWith(`${id}.`) &&
        !Object.hasOwn(REVOKED_INTO, t),
    );
  if (!okSubs) throw malformed(path, `${id} covered_subtechniques`);
  // revoked_ids can only turn a gap into "covered": each old id must credit this technique.
  const revoked = c.revoked_ids;
  if (revoked === undefined) return;
  const okRevoked =
    isRecord(revoked) &&
    Object.keys(revoked).length > 0 &&
    Object.entries(revoked).every(([old, n]) => credits(old, id) && isCount(n, 1));
  if (!okRevoked) throw malformed(path, `${id} revoked_ids`);
}

export type CoverageRow = TechniqueCoverage & { technique: string; gap: boolean };

/** No rule under the id, its sub-techniques, or any id revoked into them. */
export function isGap(c: TechniqueCoverage): boolean {
  return c.count === 0 && c.covered_subtechniques.length === 0 && !c.revoked_ids;
}

/** Null when the technique is unknown to the snapshot: unknown is not a gap. */
export function coverageFor(view: CoverageView, id: string): CoverageRow | null {
  if (!Object.hasOwn(view.snapshot.techniques, id)) return null;
  const c = view.snapshot.techniques[id] as TechniqueCoverage;
  // Named fields only: nothing else from the file reaches the client.
  return {
    technique: id,
    count: c.count,
    by_source: c.by_source,
    covered_subtechniques: c.covered_subtechniques,
    ...(c.revoked_ids ? { revoked_ids: c.revoked_ids } : {}),
    gap: isGap(c),
  };
}

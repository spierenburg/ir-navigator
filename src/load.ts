import { readdir } from "node:fs/promises";
import { basename, join } from "node:path";
import { type Corpus, type PlaybookFile, SERVED_STATUS, STATUSES, type Status } from "./types.ts";

const REQUIRED = ["playbook", "title", "platforms", "scenarios", "criteria", "steps", "actions"];

// Lifecycle is validated per record, not trusted: loadCorpus filters on status,
// so a missing or typo'd status would silently unserve the record. Fail loud instead.
function assertLifecycle(
  kind: string,
  item: { id?: unknown; status?: unknown },
  path: string,
): void {
  if (typeof item.id !== "string" || item.id.length === 0) {
    throw new Error(`invalid ${kind} in ${basename(path)}: missing id`);
  }
  if (typeof item.status !== "string" || !STATUSES.has(item.status)) {
    throw new Error(
      `invalid ${kind} ${item.id} in ${basename(path)}: status must be one of ` +
        `${[...STATUSES].join("/")} — got ${JSON.stringify(item.status ?? null)}`,
    );
  }
}

export async function loadPlaybook(path: string): Promise<PlaybookFile> {
  const file = Bun.file(path);
  if (!(await file.exists())) throw new Error(`playbook file not found: ${path}`);
  return parsePlaybook(await file.text(), path);
}

/** The checks loadPlaybook applies, on text not yet written — promote verifies its output with it. */
export function parsePlaybook(text: string, path: string): PlaybookFile {
  const parsed = Bun.YAML.parse(text) as Record<string, unknown>;
  if (parsed === null || typeof parsed !== "object") {
    throw new Error(`invalid playbook file (not a mapping): ${path}`);
  }
  const missing = REQUIRED.filter((k) => parsed[k] === undefined);
  if (missing.length > 0) {
    throw new Error(`invalid playbook ${basename(path)}: missing keys ${missing.join(", ")}`);
  }
  const pb = parsed as unknown as PlaybookFile;
  for (const s of pb.scenarios) assertLifecycle("scenario", s, path);
  for (const c of pb.criteria) assertLifecycle("criterion", c, path);
  // window was added after migration; files that predate it mean "not authored", not "invalid".
  pb.scenarios = pb.scenarios.map((s) => ({ ...s, window: s.window ?? null }));
  return pb;
}

/**
 * Default is served-only. A caller that wants drafts or retired records must ask
 * for them by name — the fail-safe direction is that a draft never reaches an analyst.
 */
export async function loadCorpus(
  dir: string,
  include: Status[] = [SERVED_STATUS],
): Promise<Corpus> {
  // Top level only: criteria/_inbox/ is a subdirectory and must never be served.
  const names = (await readdir(dir)).filter((n) => n.endsWith(".yaml")).sort();
  if (names.length === 0)
    throw new Error(`no playbook YAML files in ${dir} — run 'bun run migrate'`);

  const keep = new Set<Status>(include);
  const corpus: Corpus = { playbooks: [], scenarios: [], criteria: [], steps: [], actions: [] };

  for (const name of names) {
    const pb = await loadPlaybook(join(dir, name));
    const scenarios = pb.scenarios.filter((s) => keep.has(s.status));
    const criteria = pb.criteria.filter((c) => keep.has(c.status));

    corpus.playbooks.push({
      slug: pb.playbook,
      title: pb.title,
      scenario_count: scenarios.length,
      platforms: pb.platforms,
    });
    for (const s of scenarios) corpus.scenarios.push({ ...s, playbook: pb.playbook });
    for (const c of criteria) corpus.criteria.push({ ...c, playbook: pb.playbook });
    for (const s of pb.steps) corpus.steps.push({ ...s, playbook: pb.playbook });
    for (const a of pb.actions) corpus.actions.push({ ...a, playbook: pb.playbook });
  }

  // Hand-edited ids collide silently otherwise: the vector lookup would serve one of the two.
  const seen = new Set<string>();
  for (const c of corpus.criteria) {
    if (seen.has(c.id)) throw new Error(`duplicate criterion id across corpus: ${c.id}`);
    seen.add(c.id);
  }
  return corpus;
}

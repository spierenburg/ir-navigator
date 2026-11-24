export type ActionTier = "read" | "write" | "destructive";

/** Lifecycle vocabulary. draft = agent wrote it. */
export type Status = "draft" | "active" | "superseded" | "archived";

export const SERVED_STATUS: Status = "active";

/** For per-record validation at load time — a typo'd status must fail loud, not silently unserve. */
export const STATUSES: ReadonlySet<string> = new Set(["draft", "active", "superseded", "archived"]);

/**
 * Lifecycle travels on every criterion and scenario from the first migration.
 * Retrofitting these after ~400 hand-edited records exist means touching all of them.
 */
export type Lifecycle = {
  status: Status;
  source: string;
  validated_at: string | null;
  supersedes: string | null;
};

export type Scenario = Lifecycle & {
  id: string;
  name: string;
  indicators: string;
  discriminator: string;
  attack: string[];
  /** Authored time window the brief covers, e.g. "14d back from the first indicator". Null = not authored. */
  window: string | null;
};

/**
 * Where a finding goes once the human has read the brief. Fixed vocabulary so
 * the provenance log can be joined on it; the decision itself stays human.
 */
export const ROUTINGS = [
  "analyst_review",
  "tracked_observation",
  "ruled_out",
  // Checked and negative is ruled_out; could not check (no data, no access) is
  // this. Logged as ruled_out, a hunt that never ran reads as a negative result.
  "not_evaluable",
] as const;
export type Routing = (typeof ROUTINGS)[number];

/**
 * What one criterion came to in a logged decision. inconclusive (ran, could
 * not tell) and not_evaluable (could not run) are kept apart from not_met so
 * review never counts a missing log source as evidence against a criterion.
 */
export const CRITERION_OUTCOMES = ["met", "not_met", "inconclusive", "not_evaluable"] as const;

export type Criterion = Lifecycle & {
  id: string;
  stage: string;
  stage_ord: number;
  platform: string;
  title: string;
  why: string;
  /** Operating note for the query: table caveats, console path, retention. */
  how: string | null;
  /** Tuning / false-positive note. */
  fp: string | null;
  query: string;
  /** ISO date the query last ran against a real tenant — authored upstream, never set by this tool. */
  tested: string | null;
  attack: string[];
};

export type Step = {
  ord: number;
  time: string | null;
  title: string;
  why: string;
  critical: boolean;
};

export type Action = {
  platform: string;
  /** Timing label, e.g. "T+15–30 · Isolate". */
  label: string | null;
  name: string;
  tier: ActionTier;
  tier_inferred: boolean;
  why: string | null;
  how: string | null;
  body: string;
  attack: string[];
};

export type PlaybookFile = {
  playbook: string;
  title: string;
  platforms: string[];
  scenarios: Scenario[];
  criteria: Criterion[];
  steps: Step[];
  actions: Action[];
};

/** All playbooks flattened. Playbook is a tag on each item, not a container. */
export type Corpus = {
  playbooks: { slug: string; title: string; scenario_count: number; platforms: string[] }[];
  scenarios: (Scenario & { playbook: string })[];
  criteria: (Criterion & { playbook: string })[];
  steps: (Step & { playbook: string })[];
  actions: (Action & { playbook: string })[];
};

import type { PlaybookFile } from "./types.ts";

/**
 * Block-style YAML writer. Bun.YAML.stringify emits flow style with escaped
 * newlines, which makes a 400-criterion file unreadable and uneditable by hand
 * — the whole point of the fork into YAML. Only our known schema is handled,
 * so a promotion re-canonicalises the file it rewrites.
 *
 * Lives outside src/migrate/: the review CLI re-emits playbook files after a
 * promotion, so the writer outlives the one-time migration.
 */

// YAML 1.2 breaks lines on \r as well as \n. Inside a block scalar a \r ends
// the line early, so text after it is parsed as YAML: a draft's free text
// could then set its own playbook, id or tested date. U+0085/U+2028/U+2029
// are line breaks to YAML 1.1 parsers (not to Bun's), so they get the same
// treatment for any editor or tool that reads these files.
const OTHER_BREAKS = /[\r\u0085\u2028\u2029]/;
// Control characters a block scalar cannot carry (NUL fails Bun's parse).
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

/** Double-quoted form: JSON escapes controls; the YAML 1.1 line breaks are escaped explicitly. */
function quoted(value: string): string {
  // A lone surrogate cannot be written as UTF-8 or parsed back from a \u escape.
  return JSON.stringify(value.toWellFormed()).replace(
    /[\u0085\u2028\u2029]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function scalar(value: string, indent: string): string {
  // Block form ONLY for genuinely multiline values it carries exactly. A long
  // single-line string stays quoted: `|-` in the first key of a list item
  // ("  - id: |-") emits a body indented left of the mapping and breaks the parse.
  // |- strips a trailing newline, so a value ending in one is quoted too.
  const block =
    value.includes("\n") &&
    !value.endsWith("\n") &&
    !OTHER_BREAKS.test(value) &&
    !CONTROL.test(value) &&
    value.isWellFormed();
  if (!block) return quoted(value);
  const body = value
    .split("\n")
    .map((l) => (l.length > 0 ? `${indent}  ${l}` : ""))
    .join("\n");
  // YAML takes a block's indentation from its first non-empty line. When that
  // line may start with a space (the value starts with a space or a newline),
  // the explicit indicator pins the indentation to two, relative to the key.
  return `${/^[ \n]/.test(value) ? "|2-" : "|-"}\n${body}`;
}

export function field(
  key: string,
  value: string | number | boolean | null,
  indent: string,
): string {
  if (value === null) return `${indent}${key}: null`;
  if (typeof value === "string") return `${indent}${key}: ${scalar(value, indent)}`;
  return `${indent}${key}: ${String(value)}`;
}

/**
 * The first key of a list item ("  - id: ..."). A block scalar cannot sit
 * there — its body would be indented left of the mapping — so a string is
 * always quoted, whatever it contains.
 */
function itemKey(key: string, value: string | number): string {
  return `  - ${key}: ${typeof value === "string" ? quoted(value) : String(value)}`;
}

export function strList(key: string, items: string[], indent: string): string {
  if (items.length === 0) return `${indent}${key}: []`;
  return [`${indent}${key}:`, ...items.map((i) => `${indent}  - ${quoted(i)}`)].join("\n");
}

export function emitYaml(pb: PlaybookFile): string {
  const out: string[] = [
    "# Source of truth for this playbook's IR criteria.",
    "# Hand-edit freely. Re-run 'bun run build:index' after any change.",
    field("playbook", pb.playbook, ""),
    field("title", pb.title, ""),
    strList("platforms", pb.platforms, ""),
  ];

  out.push(pb.scenarios.length === 0 ? "scenarios: []" : "scenarios:");
  for (const s of pb.scenarios) {
    out.push(
      itemKey("id", s.id),
      field("status", s.status, "    "),
      field("source", s.source, "    "),
      field("validated_at", s.validated_at, "    "),
      field("supersedes", s.supersedes, "    "),
      field("name", s.name, "    "),
      field("indicators", s.indicators, "    "),
      field("discriminator", s.discriminator, "    "),
      strList("attack", s.attack, "    "),
      field("window", s.window, "    "),
    );
  }

  out.push(pb.criteria.length === 0 ? "criteria: []" : "criteria:");
  for (const c of pb.criteria) {
    out.push(
      itemKey("id", c.id),
      field("status", c.status, "    "),
      field("source", c.source, "    "),
      field("validated_at", c.validated_at, "    "),
      field("supersedes", c.supersedes, "    "),
      field("stage", c.stage, "    "),
      field("stage_ord", c.stage_ord, "    "),
      field("platform", c.platform, "    "),
      field("title", c.title, "    "),
      field("why", c.why, "    "),
      field("how", c.how, "    "),
      field("fp", c.fp, "    "),
      field("query", c.query, "    "),
      field("tested", c.tested, "    "),
      strList("attack", c.attack, "    "),
    );
  }

  out.push(pb.steps.length === 0 ? "steps: []" : "steps:");
  for (const s of pb.steps) {
    out.push(
      itemKey("ord", s.ord),
      field("time", s.time, "    "),
      field("title", s.title, "    "),
      field("why", s.why, "    "),
      field("critical", s.critical, "    "),
    );
  }

  out.push(pb.actions.length === 0 ? "actions: []" : "actions:");
  for (const a of pb.actions) {
    out.push(
      itemKey("platform", a.platform),
      field("label", a.label, "    "),
      field("name", a.name, "    "),
      field("tier", a.tier, "    "),
      field("tier_inferred", a.tier_inferred, "    "),
      field("why", a.why, "    "),
      field("how", a.how, "    "),
      field("body", a.body, "    "),
      strList("attack", a.attack, "    "),
    );
  }

  return `${out.join("\n")}\n`;
}

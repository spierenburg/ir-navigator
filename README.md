# ir-navigator

A workbench for distilling incident-response playbooks from real incidents and
public threat reporting, and an MCP server that serves the result to an
analyst mid-incident so the corpus is tested against real evidence. A
playbook here is a set of scenarios, each with the indicators an analyst would
see and the discriminator that tells it from its neighbours, plus the judgment
criteria and hunts that go with each stage. The server **surfaces criteria and
never decides**: no tool returns a single verdict, and nothing it returns is an
instruction to act.

> **Experimental.** The hunt queries are authored reference material. None has
> yet been run against a real tenant (every criterion carries `tested: null`).
> Read a query before you run it, and expect to adapt it to your schema.

## Two uses, one corpus

### Mid-incident: ask the corpus what the evidence means

The analyst has evidence and an MCP client with this server attached. The
tools answer four questions and record the fifth:

| You want to | Call | You get |
|---|---|---|
| Triage a new case | `ir_classify(evidence)` | At least two candidate readings across all playbooks, each with the discriminator that would rule it out. |
| Work one reading | `ir_hunt(playbook, scenario)` | A brief: threat model, scope and time window, every stage with its hunts, detection-coverage gaps per technique, the competing readings, and the output contract. |
| Hunt one stage | `ir_hunt(…, stage_ord)` or `ir_criteria(stage_ord)` | That stage's criteria and queries, always with the adjacent stages so the stage call stays open. |
| Check one hunch | `ir_search(evidence)` | Individual criteria ranked against the evidence. |
| See what containment the playbook knows | `ir_actions(playbook, platform)` | Platform action blocks, tier-tagged; every block that is not read-only is marked `proposal_only`. |
| Record what you decided | `ir_log(decision, routing, criteria_ids, outcomes, falsifier)` | One line in `provenance.jsonl`, joined to the deliveries by `case_id`. |

Nothing here decides, and nothing executes. The queries are reference
material to read and adapt, not to run blind.

### Between incidents: harvest playbooks from cases and reporting

The corpus grows from three kinds of source: a real case that the serving
loop could not read, the author's own case material, and public threat
reporting. Three ways in, all through one review gate:

| You want to | Do | Result |
|---|---|---|
| Capture one finding from a case or a report you are reading | `ir_propose(playbook, title, why, source, query?)` from the MCP client | A draft in `criteria/_inbox/`. Nothing serves it. |
| Distil a whole playbook for a class of incident the corpus has no reading for | The method in [`docs/distilling-playbooks.md`](docs/distilling-playbooks.md): scope doc → draft scenarios → criteria from sources → review → eval cases | A new `criteria/<playbook>.yaml`, served when its scenarios go `active`. |
| Review, promote, decline | `bun run review`, `--promote`, `--reject` | Drafts become served criteria only here, after a human has read every field as it will be served. |
| Retire what never earns its place | `bun run review --stale` | Counts from the provenance log: never surfaced, surfaced and never cited, never met when evaluable. |
| Measure the ranking | `bun run eval` | Top-1, recall@2, recall@8 and MRR on labelled cases, ratcheted against a committed baseline. |

The two uses feed each other. A logged decision that says "no playbook fit"
is the signal that starts a distillation, and the distilled playbook is
finished only when a real case runs through the serving loop and the logged
decision cites its criteria. The eighth playbook, `edge-exploitation-response`,
was built that way from two logged cases and three notes from the author's
own case material, with public CTI confirming the gap. The scope docs in
`docs/` are the worked examples.

## Architecture

```
                 HARVEST                                     SERVE
                                                   ┌──────────────────────┐
 incident / report / runbook                       │  MCP client (analyst)│
        │                                          └──────────┬───────────┘
        ├─▶ ir_propose ──▶ criteria/_inbox/  (drafts)         │ stdio
        │                        │                            ▼
        └─▶ docs/<playbook>-scope.md                 ┌──────────────────────┐
                 │                                   │  ir-navigator server │
                 ▼                                   │  src/server.ts       │
         draft scenarios in                          │  7 tools, src/tools.ts
         criteria/<playbook>.yaml                    └──┬────────┬───────┬──┘
                 │                                      │        │       │
                 ▼                                   reads     reads   appends
       bun run review --promote --sha256                │        │       │
                 │                                      ▼        ▼       ▼
                 ▼                            criteria/   index/     provenance.jsonl
   ┌─────────────────────────────┐            *.yaml      vectors.json   (deliveries +
   │ criteria/*.yaml             │◀───────────────┘       coverage.json   decisions)
   │ 9 playbooks, source of truth│                            ▲               │
   └──────────────┬──────────────┘                            │               │
                  │ bun run build:index  (embeddings host)    │               │
                  ├──────────────────────────────────────────▶│               │
                  │ bun run build:coverage (Security Detections MCP)          │
                  └──────────────────────────────────────────▶│               │
                                                                              │
   eval/cases.ts + baseline.json ◀── bun run eval                             │
   "no playbook fit" / review --stale ◀───────────────────────────────────────┘
```

- **Corpus** (`criteria/`): 9 playbooks, 434 criteria, 43 served scenarios
  and 11 in draft, 56 IR steps, 187 platform actions, all hand-editable YAML.
  392 criteria were forked from the author's published playbooks on
  2026-10-10; 42 have since been distilled from reports, cases and runbooks,
  each naming its source. Read tools serve `status: active` only.
- **Index** (`index/vectors.json`): committed embeddings, hash-guarded against
  the corpus. Ranking is hybrid: exact-term with negation ("nothing is
  encrypted" does not match the encryption scenario) plus semantic similarity
  when an embedding host is reachable.
- **Coverage** (`index/coverage.json`): a committed snapshot of how many public
  detection rules carry each ATT&CK technique id in the corpus, from the
  Security Detections MCP. Optional; absent, briefs say so.
- **Provenance** (`provenance.jsonl`): one line per delivery and per decision,
  local and git-ignored. It is the only feedback channel: `review --stale`
  and the next scope doc both read it.
- **Inbox** (`criteria/_inbox/`): the single write path from an MCP client.
  Nothing serves it; `bun run review` is the only way out.

### What ATT&CK does here

Every criterion carries `attack` technique ids, except the nine
edge-exploitation criteria and two supply-chain criteria, which have none
yet. Scenarios have the same field, but only the eleven draft BEC and
device-code scenarios fill it. The ids are used for two things: they travel
with every result, and they join the corpus to the coverage snapshot, so a
brief can say which techniques in a stage have public detection rules and
which do not.

They are **not** the structure. Each playbook has its own authored stage
ladder (ransomware runs Initial access to Extortion; identity-breach runs
First sign-in to Still active; edge-exploitation runs Exposure to Inward),
and the tools navigate by those stages. Nothing maps a technique to a stage,
`ir_classify` ranks on text rather than technique overlap, and no tool takes a
technique id as a filter. Using the ids as a cross-playbook join or to diff a
report's techniques against the corpus is possible with the data as it stands
and is not built.

Design rationale, the as-built record, and the review-gate contract are in
[`docs/SPEC.md`](docs/SPEC.md).

## Quick start

Requires [Bun](https://bun.sh) 1.x.

```bash
bun install
bun test                     # whole suite, no network needed
bun run start                # MCP server on stdio
```

The server boots with no environment at all. It then runs with exact-term
ranking only and says so on stderr and in every response
(`semantic_ranking: false`). Set `IRNAV_EMBED_URL` for semantic ranking.

### Register with Claude Code

```bash
claude mcp add ir-navigator -s user \
  -e IRNAV_EMBED_URL=http://localhost:8082 \
  -- bun run /path/to/ir-navigator/src/server.ts
```

After the code or corpus changes, reconnect the server (`/mcp`) to load it.

## Configuration

| Variable | Used by | Required | Meaning |
|---|---|---|---|
| `IRNAV_EMBED_URL` | server, `build:index` | for `build:index`; optional for the server | OpenAI-compatible `/v1/embeddings` host (e.g. llama.cpp). No default. |
| `IRNAV_EMBED_MODEL` | server, `build:index` | no | Embedding model, default `nomic-embed-text` (768-dim). Must match the model the index was built with. |
| `IRNAV_DETECTIONS_URL` | `build:coverage` | yes | Security Detections MCP endpoint (streamable HTTP). No default. |
| `IRNAV_DETECTIONS_AUTH` | `build:coverage` | yes | `user:password` for that server's basic auth. Never commit it. |

Nothing falls back silently. If an embed host is down at query time, ranking
degrades to exact-term for that call and the response says so. A missing or
stale vector index stops the server at boot.

## Tools

| Tool | Purpose | Key arguments |
|---|---|---|
| `ir_classify` | Rank candidate readings across all playbooks. Always ≥2, each with its discriminator. | `evidence` |
| `ir_search` | Rank individual criteria against evidence. | `evidence`, `playbook?` |
| `ir_criteria` | Criteria for one stage, always with the adjacent stages. | `stage_ord`, `playbook?` |
| `ir_hunt` | Hunt brief for one candidate. Without `stage_ord`: threat model, stage map with coverage gaps, alternatives, output contract. With it: that stage's hunts plus neighbours. | `playbook`, `scenario`, `platform?`, `stage_ord?` |
| `ir_actions` | Platform action blocks, tier-tagged. Anything not read-only is `proposal_only: true`. | `playbook?`, `platform?` |
| `ir_log` | Record the decision a human took, with routing (`analyst_review` / `tracked_observation` / `ruled_out` / `not_evaluable`), the criteria it rests on and what each came to. `ruled_out` requires a `falsifier` (the observation that ruled it out) and a scenario or criteria. | `decision`, `rationale?`, `scenario?`, `routing?`, `criteria_ids?`, `outcomes?`, `falsifier?` |
| `ir_propose` | Write a draft criterion to the review inbox. Never served. | `playbook`, `title`, `why`, `source`, `platform?`, `stage_ord?`, `query?` |

Every tool also takes `case_id`, the incident's ticket or case id, so the
deliveries and decisions of one incident join on it rather than on timing.
`outcomes` maps criterion ids to `met` / `not_met` / `inconclusive` (ran, could
not tell) / `not_evaluable` (could not run). Read tools are annotated
`readOnlyHint: true`; `ir_log` and `ir_propose` are local, non-destructive writes.

Read tools serve `status: active` scenarios and criteria only. Unknown
playbooks, platforms, scenarios, routings, outcomes, criterion ids and
arguments throw instead of returning an empty result, because "nothing
matched" and "you misspelled it" must not look the same.

## Workflows

### Distill a playbook from incidents and CTI

The full method is [`docs/distilling-playbooks.md`](docs/distilling-playbooks.md).
In short:

1. Find the gap: an `ir_log` decision with no playbook fit, or `ir_classify`
   scoring every reading in a flat band on a real case.
2. Write `docs/<playbook>-scope.md`: signals, boundary with existing
   playbooks, platforms, stages, scenarios with discriminators, candidate
   criteria with sources, what no source covers yet.
3. Add `criteria/<playbook>.yaml` with scenarios as `status: draft`.
4. Draft criteria from the sources, through `ir_propose` or by hand.
5. `bun run review --promote <file> --sha256 <hex>` with the digest the
   listing printed, flip scenarios to `active`, rebuild the index.
6. Add eval cases in an analyst's words; `bun test` ratchets the baseline.
7. Run a real case through the serving loop and log the decision.

### Edit the corpus

1. Edit `criteria/<playbook>.yaml` by hand.
2. `IRNAV_EMBED_URL=… bun run build:index`. The server refuses to boot until
   the index matches the corpus hash.
3. Commit the YAML and `index/vectors.json` together.

### Review proposed criteria

`ir_propose` writes `criteria/_inbox/<timestamp>-<slug>-<tag>.yaml` (`status:
draft`). The inbox is local state: it is untracked, so do not commit it.

```bash
bun run review                       # list every draft, every field it would serve
bun run review --promote <file> --sha256 <hex>   # the hex the listing printed for it: validate,
                                     # append to the playbook, delete the draft
bun run review --reject <file> [--inbox <dir>]  # delete the draft, record it in the inbox's rejected.jsonl
bun run review --stale               # never surfaced; surfaced 3+ times and never cited;
                                     # mostly not_evaluable; never met when evaluable
```

`--stale` only counts. It feeds the promote and retire decision and never
changes ranking: folding outcome history into ranking would favour the common
reading over the rare one (SPEC invariant 1).

Approval names bytes, not a path. The listing prints a `sha256` for each
draft, and `--promote` takes the whole digest and refuses if the file no
longer hashes to it, so a draft rewritten after the listing cannot be
promoted on your approval of the old one. The whole digest, not a prefix: the
client that wrote the listed draft can also write the swap, and two drafts
sharing a short prefix are cheap to find. Edit a draft freely before promoting
it, then list again for its new digest.
`--promote` also refuses anything that would not
be served exactly as listed: wrong field types, a malformed or clashing id, a
non-integer `stage_ord`, a platform the playbook does not list, no stage
(`stage_ord` 0 or stage `Unassigned`, the draft defaults), a `stage` name and
`stage_ord` that do not pair up the way the playbook's served criteria already
pair them, or a playbook that would not
read back identically. A refusal changes nothing. After a promote, rebuild the index and commit.

Draft text comes from an AI client and is treated as adversarial: the listing
escapes control, invisible and (in executed or matched fields) non-ASCII
characters, and hard-wraps so no line can pose as a field. The full contract
is in SPEC → *What review guarantees*.

### Refresh detection coverage

```bash
IRNAV_DETECTIONS_URL=https://detections.example.org/mcp \
  IRNAV_DETECTIONS_AUTH=user:password bun run build:coverage
```

This writes `index/coverage.json`. The snapshot is optional:
- With no snapshot, briefs say coverage is unavailable.
- With a stale snapshot, techniques newer than it read as `unknown`, never as
  gaps. The server warns at boot when that happens.

Counts are public rules that exist, not rules deployed or tested in your
tenant.

### Measure ranking quality

```bash
bun run eval                                   # exact-term arm; also gated by bun test
IRNAV_EMBED_URL=… bun run eval --semantic      # hybrid arm, needs the embedding host
bun run eval [--semantic] --write-baseline     # accept the current scores
```

`eval/cases.ts` holds 46 labelled evidence → expected scenario cases, written in
an analyst's words rather than copied from the indicators. Some also name a
confusable reading the evidence must not put first. The run reports top-1,
recall@2 (whether invariant 1's two readings include the right one), recall@8
and MRR. It fails when any score falls below `eval/baseline.json`, when a case
that passed drops out of the top two, or when a new confusable-first appears.
The baseline is a ratchet: after an improvement, write a new one and commit it.
Eval calls log to a temp file, never to `provenance.jsonl`.

### Provenance

Every tool call that passes the size limit appends one JSON line to
`provenance.jsonl` in the repo root (git-ignored, mode 0600): `schema_version`,
timestamp, tool, arguments, and the ids surfaced. A refused call is logged with
`error` and nothing surfaced. Credentials in arguments are redacted before the
write; the rules and their known limits are in
[`docs/redaction.md`](docs/redaction.md). The log is opened like an inbox
file: a symlink at its path is not followed, a planted hard link, FIFO or
directory is refused, and a delivery whose row cannot be written fails. These
guards stop a planted file from redirecting a row; the log directory itself is
the trust boundary. `review --stale` refuses a log over 64 MiB and asks you to
rotate it, and says so when there is no log at all. Evidence sent to the embedding host
is not redacted, so keep that host local. `ir_log` entries join the log to
decisions, and `review --stale` reads it.

## Repository layout

```
criteria/            playbook YAML, the source of truth (one file per playbook)
  _inbox/            draft criteria awaiting review (untracked local state)
index/
  vectors.json       embedding index, hash-guarded against the corpus
  coverage.json      detection coverage snapshot (optional)
eval/                labelled ranking cases and the committed baseline
src/
  server.ts          MCP stdio entrypoint: loads corpus, index, coverage
  schemas.ts         tool input schemas
  tools.ts           tool handlers and argument validation
  rank.ts            hybrid exact-term + semantic ranking, with negation
  load.ts            corpus loading and per-record validation
  emit.ts            canonical YAML emitter (used by promote)
  inbox.ts           ir_propose draft writer
  review.ts          review CLI: list, promote, reject, stale
  regular-file.ts    the one way a planted file is opened: no symlink, no FIFO, bounded read
  shown.ts           terminal escaping for text an AI client wrote
  provenance.ts      delivery log
  redact.ts          credential redaction for the delivery log
  eval.ts            ranking eval: metrics and the baseline ratchet
  types.ts           corpus schema: Criterion, Scenario, Lifecycle, …
  index/             embedding client, index build and load
  coverage/          coverage build and snapshot load
test/                bun:test suites, fixtures in test/fixtures.ts
docs/
  distilling-playbooks.md        the method: from incident or report to served playbook
  edge-exploitation-scope.md     worked example, promoted 2026-10-31
  kubernetes-compromise-scope.md worked example, scoped and drafted 2026-11-07
  targeted-intrusion-scope.md    worked example, scoped and not yet drafted
  SPEC.md                        design, as-built deltas, review-gate contract
  redaction.md                   what provenance redaction catches and misses
  PRODUCT-DISCOVERY-CHECKPOINT.md, superpowers/specs/
                                 discovery record for a broader case-management
                                 product; nothing in this repo implements it
```

### Criterion schema

Each criterion carries lifecycle fields (`status` ∈ `draft` / `active` /
`superseded` / `archived`, `source`, `validated_at`, `supersedes`) plus `id`,
`stage`, `stage_ord`, `platform`, `title`, `why` (the judgment and what would
falsify it), `how` (operator note), `fp` (tuning note), `query`, `tested`
(ISO date the query last ran in a real tenant; `ir_hunt.verified` mirrors it)
and `attack` (ATT&CK technique ids). Scenarios carry the same lifecycle fields
plus `name`, `indicators`, `discriminator`, `attack` and an optional `window`.
Full types are in `src/types.ts`.

## Development

```bash
bun test            # tests (no network; fixtures and temp dirs only)
bun run eval        # ranking eval, exact arm
bun run lint        # biome check
bun run typecheck   # tsc --noEmit
```

- Tests must not write to `criteria/`, `criteria/_inbox/` or the real
  `provenance.jsonl`. Pass temp paths, as the existing suites do.
- Code style is Biome 2 (`biome.json`, 100-column lines). `index/coverage.json`
  is excluded, and `index/vectors.json` is skipped for size.
- Changes to `src/review.ts`, `src/inbox.ts` or `src/emit.ts` touch the
  injection boundary. Keep the SPEC review contract in step with them.

## Scope

This is a local lab build. It holds no customer or incident data: the cases
that prompted new playbooks are cited by ticket id and surface, never by
content, and no tool reads live case data. Deferred work (stage inference,
automated CTI ingest, steps and actions for the edge playbook, the
targeted-intrusion playbook) is listed in SPEC → *Out of scope*.

## License

Code is [MIT](LICENSE). The criteria corpus in `criteria/` is
[CC BY 4.0](criteria/LICENSE): reuse it with attribution. Criteria that adapt
third-party research name it in their `source` field.

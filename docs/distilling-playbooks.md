# Distilling a playbook from incidents and CTI

This is the loop the repo exists to run. It was run end to end once, for
`edge-exploitation-response` (scoped from 2026-10-26, drafted 2026-10-30,
promoted 2026-10-31), and partially for two supply-chain scenarios and the
M365 identity and BEC criteria promoted from the inbox on 2026-10-26. [`edge-exploitation-scope.md`](edge-exploitation-scope.md) and
[`targeted-intrusion-scope.md`](targeted-intrusion-scope.md) are the worked
examples; this page is the method they share.

Nothing here is automated. A cron that proposes criteria nobody reviews is the
capture-without-consumption failure the SPEC names, so every step below is run
by hand and every promotion is a human decision.

## 1. Find the gap

A playbook is worth distilling when the corpus has no reading for a class of
incident. Four signals, in order of weight:

1. **A logged decision with no fit.** `ir_log` rows in `provenance.jsonl`
   whose decision says the evidence matched no playbook. Two of the first
   eleven decisions did (an Ivanti Connect Secure case and a PHP web-app
   exploitation case), and they became the edge playbook.
2. **`ir_classify` on a hand-written summary of a real case or report.** When
   every reading scores in a flat band (0.24–0.29 on the edge cases, 0.24–0.27
   on the targeted-intrusion cases) and the top reading's discriminator asks a
   question the case cannot answer, the corpus has no reading, not a weak one.
3. **Own material.** Anonymised runbooks and detection notes that fit no
   playbook (the edge scope found five in own notes, three of them this
   surface).
4. **Public CTI.** Advisories and vendor reports on the same surface. These
   confirm the gap and supply sources for criteria; they rarely open a gap on
   their own.

Write the signals down with their evidence. A scope doc that says "three
signals name the same gap" and lists them is the record that the playbook was
pulled by cases, not pushed by a report.

## 2. Scope it before drafting anything

One markdown file in `docs/`, `<playbook>-scope.md`, with these sections:

- **Why this playbook** — the signals from step 1.
- **One playbook, not two** / **Boundary with existing playbooks** — what it
  owns and where it hands off (the edge playbook owns the device, hands the
  AD pivot to identity-breach, the ransomware stage to ransomware). Without
  this, the new scenarios compete with old ones in `ir_classify` instead of
  separating from them.
- **Platforms** — the existing six plus any new log source the surface needs
  (`Edge appliance logs`, `Web server logs`).
- **Stages** — the playbook's own stage ladder with ordinals. Stages are what
  `ir_hunt` briefs by and what promote validates against, so they are fixed
  here, not per criterion.
- **Scenarios** — each with the indicators an analyst would see and the
  discriminator that tells it from its neighbours. The discriminator is the
  part that matters; indicators without one make an anchoring machine.
- **Criteria the sources give** — one line per candidate, tagged with its
  stage and the source it comes from.
- **Not covered by any source** — stages and judgements that still need a
  primary source before anything is drafted.
- **Code touch points** — the YAML file, eval cases, index rebuild.

## 3. Draft scenarios in YAML, status `draft`

Create `criteria/<playbook>.yaml` with `playbook`, `title`, `platforms`,
`scenarios`, `criteria`, `steps` and `actions` (the last two may be empty
lists). Scenarios go in as `status: draft` with `source` naming the scope doc
and the reports behind them. `loadCorpus` serves `active` only, so a draft
scenario is loaded, validated, and invisible to every tool. The BEC and
device-code playbooks carry eleven draft scenarios today for exactly this
reason: authored, not yet trusted.

## 4. Draft criteria from the sources

Each criterion is one judgement: `why` says what the evidence means and what
would rule it out; `query` is the hunt; `source` names the report, advisory,
case id or runbook it came from, specifically enough that a reviewer can
check it. Two ways in:

- **`ir_propose` from an MCP client** that has read the report. It writes to
  `criteria/_inbox/` and nothing serves it until `bun run review --promote` with its digest.
  This is the normal path when the drafting is done in a session with the
  source open.
- **Hand-edit the playbook YAML** with `status: draft`. Equivalent, and
  simpler when several criteria come from one source.

The source string is the provenance. Of the corpus today, 392 criteria carry
`landing-page@2026-10-10` (the original fork) and 42 carry a report, case or
runbook reference. That second number is the distilled part of the corpus.

## 5. Review and promote

`bun run review` lists every draft with every field it would serve and a
`sha256` of its bytes; `--promote <file> --sha256 <hex>` takes that whole
digest and refuses if the file has changed since the listing it came from.
It also refuses anything that would not be served exactly as listed (stage,
platform, id, field types, round-trip). Flip a scenario from `draft`
to `active` by hand in the YAML when its criteria are in. Then
`IRNAV_EMBED_URL=… bun run build:index` and commit the YAML and index
together.

## 6. Write the eval cases

Add cases to `eval/cases.ts` in an analyst's words, never copied from the
scenario's indicator text, with `must_not_top1` naming the confusable
neighbour. The cases that showed the gap in step 1 are the first ones. `bun
test` gates the exact arm against `eval/baseline.json`; a new playbook that
scores should raise the baseline, and one that does not is a scope problem,
not a ranking problem.

## 7. Let the serving loop test it

The playbook is finished when a real case runs through `ir_classify` →
`ir_hunt` → `ir_log` and the logged decision cites its criteria. Until then
`tested` stays null on every criterion and the brief says so. `review --stale`
reads the log and lists criteria never surfaced, surfaced and never cited, or
never met when evaluable; those are the retire candidates for the next pass.

## What was tried and removed

**Importing drafts from a public hunt library.** In October 2026 a CLI read a
clone of a public library of machine-drafted hunts and wrote inbox drafts from
them. The hunts were campaign-specific, schema-checked
only, and matched playbooks on title keywords that mostly missed (26 of 35
identity matches shared no technique with the playbook). Eighteen BEC drafts
it wrote were rejected and no imported draft was ever promoted. The reports
behind the hunts are useful as sources for step 4; the hunts are not useful as
criteria. The code was removed on 2026-10-31; SPEC delta 10 keeps the record.

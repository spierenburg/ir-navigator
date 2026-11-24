# Scope: `targeted-intrusion-response` (9th playbook)

Status, 2026-10-30: scope only. Nothing below is in the corpus. Every
criterion still goes through `ir_propose` → inbox → `bun run review --promote … --sha256 …`.

## Why this playbook

The corpus has no reading for hands-on intrusion that aims to stay rather than
extort: an operator with implants, collecting mail and documents over weeks,
with no encryption and no claim. Four signals:

- **`ir_classify` finds no fit.** Four hand-written cases were tried on
  2026-10-30: a backdoor with weeks of interactive collection, an implant in a
  repurposed update utility, a Linux kernel implant after exploitation of a
  public service, and the VAPOR PANDA SAML/IMDS access. With negations removed
  from the first case, all 8 readings scored 0.24–0.27, close to the flat
  0.24–0.29 band the edge cases showed before that playbook existed. The top reading is
  ransomware scenario 3 (Data Theft Without Encryption), whose discriminator is
  about validating an extortion claim; no claim exists here. Ransomware
  scenario 2, which holds the closest guidance, did not rank in the top 8. The
  kernel-implant case ranked identity scenario 6 first, on the words "data",
  "public" and "service".
- **The corpus.** "espionage" appears in no playbook.
- **Public hunt reporting.** About a dozen published hunts of this shape
  named no subject any playbook covers: Gamaredon, FamousSparrow, MuddyRot,
  regional-government espionage, two APT28 hunts, UNC6201, CL-UNK-1211,
  VoidLink's kernel implant, and an implant in a repurposed update utility.
  Counted on 2026-10-30 by matching hunt titles in a public hunt library
  against per-playbook keyword lists, using an import tool since removed
  (SPEC delta 10); titles only, so it is a floor and not re-runnable as is.
- **CTI, 2026-10-30.** VAPOR PANDA (CrowdStrike, 2026-10-29): 200+ orgs
  targeted, 9 with post-exploitation, mailbox reads on a compromised mail
  server, an admin token forged from unrotated 2022 directory-export keys.
  UAT-11473 KeyDrift (Cisco Talos, 2026-10-28): implants in SD-WAN controllers
  harvesting key material.

The classify readings are calls on hand-written evidence, not eval cases. One
confound was controlled: `ir_classify` matched "ransom" and "encryption" out of
"no ransom note, no encryption", which lifted ransomware scenario 3 from 0.27
to 0.36. The 0.24–0.27 band above is the run without negations. That
negation-blindness is a tool issue, separate from this scope.

## Name

Named for what the analyst sees at triage, not for an attribution that is
rarely known then. "Espionage" is the usual motive; the playbook does not need
it to be proven.

## Boundary with existing playbooks

- **ransomware-response scenario 2** (Discovered Before Encryption) shares the
  rule "contain at least as wide as they could be, in one move". The difference
  is the clock. Scenario 2 says minutes to hours, because encryption may start
  at any moment. Here there is no destructive clock, so the analyst can take
  the time to map every foothold before acting, and should. The discriminator
  between the two is the operator's objective: backup consoles, shadow-copy
  deletion and payload staging point to ransomware; mail and document
  collection, staging archives and slow exfiltration point here.
- **edge-exploitation-response** owns the device. An implant on a VPN, firewall
  or SD-WAN controller is edge scenario 4. This playbook owns the intrusion
  behind it once more than one foothold exists.
- **identity-breach-response** owns a token or account. This playbook owns the
  campaign: several access methods, which have to be removed together.

## The judgement that defines it

CISA AA25-239A (on PRC state-sponsored actors; last revised 2025-09-03): "gaining a full
understanding of the APT actors' extent of access into networks followed by
simultaneous measures to remove them may be necessary to achieve a complete and
lasting eviction. Partial response actions may alert the actors to an ongoing
investigation and jeopardize the ability to conduct full eviction."

CISA AR21-134A (2021, SolarWinds/M365 eviction): three phases (pre-eviction,
eviction, post-eviction), and "use out-of-band communications for all
mitigation and remediation communications", because the mail and chat systems
are in scope.

## Platforms

The standard six. Network devices are edge's platform; whether this playbook
also needs `Edge appliance logs` is open until a criterion needs it.

## Stages (proposal)

| Ord | Stage | Question |
|---|---|---|
| 1 | Way in | How did they get in, and is that route still open? |
| 2 | Footholds | How many access methods do they hold: implants, web shells, accounts, tokens, devices? |
| 3 | Credentials and keys | Which credentials and signing keys do they hold, and which can forge new access? |
| 4 | Collection | What did they read: mailboxes, file shares, staged archives? |
| 5 | Exfiltration | What left, by which channel, over how long? |
| 6 | Eviction | Is the map complete enough to cut every foothold at once? |
| 7 | Re-entry | Are they trying to come back? |

## Scenarios (proposal)

1. **Implant found, no impact.** A backdoor or implant on one or more hosts,
   with no encryption and no claim. Discriminator: one find means more; do not
   remove it until stage 2 is mapped.
2. **Long-dwell collection.** Mail or document collection over weeks.
   Discriminator: scope from the first sign of the implant, not from detection;
   assume the mail system is read, so use out-of-band channels.
3. **Notified by a third party.** A national CERT, law enforcement or a
   vendor says you were compromised. Discriminator: the notifier often knows
   more than it can share, so ask what it can, and do not tip off the actor
   while you verify.
4. **Below the EDR.** A kernel implant, a hypervisor or network-device implant,
   or a host the operator chose because it has no EDR (VAPOR PANDA's agents
   were told to find Windows hosts without Falcon). Discriminator: hosts
   without coverage are scoped first, not last.
5. **Re-entry after eviction.** Activity after the cut. Discriminator: a
   missed foothold or a key that was not rotated; forged tokens from an
   unrotated signing key (VAPOR PANDA) survive every password reset.

## Criteria the sources give (draft candidates)

- **S6** Eviction is simultaneous and follows a complete foothold map
  (AA25-239A).
- **S6** Remediation is coordinated out of band (AR21-134A).
- **S3** Signing and export keys older than the intrusion are rotated, because
  a forged token outlives password resets (VAPOR PANDA, 2022 export keys).
- **S2** Hosts without EDR coverage are enumerated and scoped first
  (VAPOR PANDA).
- **S4** Mail-server and mailbox access by service or admin accounts in the
  window (VAPOR PANDA mailbox reads).
- **S7** Post-eviction monitoring reports residual risk and incomplete
  actions (AR21-134A post-eviction).

## Not covered by any source yet

The watch-or-evict decision: when to observe an operator rather than cut, and
how to coordinate that with law enforcement. That needs a primary source before
anything is drafted. Notification duties differ by jurisdiction and are not
scoped here.

## Code touch points

- `criteria/targeted-intrusion-response.yaml`: new file, scenarios as draft.
- `test/load.test.ts`, `test/tools.test.ts`: the pinned playbook count and
  no-scenarios list.
- `eval/cases.ts`: golden cases once scenarios are active.
- `bun run build:index` after the first promoted criterion.

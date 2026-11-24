# Scope: `kubernetes-compromise-response` (9th playbook)

Status, 2026-11-07: scoped and drafted in one pass. Scenarios and criteria
are authored `active` so the eval can measure them. Nothing has run through
`ir_classify` → `ir_hunt` → `ir_log` on a real case yet, so `tested` is null
on every criterion.

## Why this playbook

Four signals name the same gap:

- **A direct question with no answer in the corpus** (2026-11-06): is there a
  record of how to evict an ARTEX-driven intruder from a Kubernetes cluster?
  Own notes, the CTI store and this corpus were searched.
  ARTEX threat intelligence exists (own notes `4afc65a6`, `7727111e`; CTI
  report `artex-backdoored-docker-image-root`); no Kubernetes response
  material does.
- **`ir_classify` on a hand-written cluster case** (service account token
  used from outside the cluster, secrets listed across namespaces, a new
  cluster-admin binding, a privileged DaemonSet in kube-system). Readings
  scored 0.28–0.32 in a flat band, led by cloud-incident-response scenario 1
  and identity-breach-response scenario 6. Neither discriminator mentions a
  pod, a binding or a kubelet. That is no reading, not a weak one.
- **Own material.** Own cluster tooling and detection notes exist (`3a972b90`,
  Falco exec detection). None of it is written down as response criteria. `provenance.jsonl` holds no `ir_log`
  decision about a cluster; its Kubernetes mentions are image SBOM scans in
  supply-chain cases.
- **CTI.** Three ARTEX reports in three weeks (Microsoft 2026-10-21,
  CrowdStrike 2026-10-29, BadByte via THN 2026-11-05). They supply the
  overlay: how fast an agent-driven intrusion moves, which markers tie its
  findings together, and that the tool's own image can be the compromised
  component. The backbone of the playbook comes from Kubernetes'
  documentation, the only source that states what the API server does when a
  token is to be invalidated.

## One playbook, not two

A cluster playbook and a container-host playbook were considered and
rejected. The analyst's questions are the same whatever the entry: which
identity is acting through the API server, what can it reach, what did it
leave behind, and how is it actually cut off. The split lives in the
scenarios. Not owned here: exploitation of the application inside a pod
(edge-exploitation-response), provenance of a poisoned image
(supply-chain-response), the cloud account around the cluster
(cloud-incident-response).

## Boundary with existing playbooks

- **cloud-incident-response scenarios 1 and 5.** A cloud IAM identity mapped
  into the cluster is revoked in the cloud; that playbook owns the credential.
  This playbook owns what it did through the API server and the service
  accounts it reached. A pod reaching the cloud metadata service hands off to
  cloud scenario 5 for the node role.
- **edge-exploitation-response scenario 3** decides whether a web worker ran
  attacker code. Once that happened inside a pod, the pod's service account
  and node are the next identities and this playbook takes over.
- **supply-chain-response scenario 2** scopes a compromised package or image
  by "where was it installed". Scenario 5 here owns the pods that ran it and
  the secrets mounted into them.
- **ransomware-response.** Nothing is encrypted in any scenario here. A node
  compromise that becomes a host intrusion joins ransomware-response Stage 2+
  or identity-breach-response if the node is domain-joined.

## The judgement that defines it

Kubernetes keeps no central record of issued TokenRequest tokens and offers
no call to revoke one (service-accounts-admin, "Delete/invalidate a
short-lived ServiceAccount token"). A token bound to a Pod stops
authenticating when the Pod is deleted; one bound to a Secret when the Secret
is deleted; every token of a ServiceAccount when the ServiceAccount is
deleted and recreated, because its UID changes; a legacy token Secret never
expires until it is deleted. "Rotate the token" is not an action the API
server has. Every containment step is phrased against that, and Stage 9
tests whether it was applied: an authenticated request by a contained
identity after the containment timestamp means the token was bound to
something that was not deleted.

## Platforms

The existing six plus three that carry the evidence here:

- `Kubernetes audit logs` (kube-apiserver audit events, JSONL or managed
  export)
- `Falco` (runtime process, file and network events the audit log cannot see)
- `kubectl` (the action surface; every write is `proposal_only` via
  `ir_actions`)

## Stages

| Ord | Stage | Question | Seed |
|---|---|---|---|
| 1 | Exposure | Is there an audit log at all; does anything answer unauthenticated? | Kubernetes docs (auditing; kubelet authn/authz); nhimg |
| 2 | Identity | Which identity acts, from where, since when; human, service account, cloud-mapped or anonymous? | kubernetesforensics.com; Invictus |
| 3 | Discovery | Is a token being tested? | kubernetesforensics.com |
| 4 | Execution | Did it run commands, and which log can see that? | Invictus; kubelet docs; Falco (own notes `3a972b90`) |
| 5 | Credential access | Which secrets were read, which tokens minted, was the metadata service reached? | kubernetesforensics.com; Microsoft matrix; CrowdStrike |
| 6 | Escalation and escape | New cluster-wide rights; pods that reach the node | kubernetesforensics.com; kubelet docs; nhimg |
| 7 | Persistence | What stays after the first credential dies | Microsoft matrix; SA admin docs; EKS guidance |
| 8 | Evasion | Events deleted, audit stopped | Microsoft matrix; kubernetesforensics.com |
| 9 | Still active | Does the contained identity still authenticate; was closure reached? | SA admin docs; nhimg |

## Scenarios

1. **Token out of its pod.** Judgement: the token cannot be revoked; it dies
   with its bound object or on ServiceAccount recreation. Against cloud
   scenario 1: the credential is a Kubernetes JWT, the control plane is the
   API server.
2. **Exposed control-plane surface.** Judgement: the kubelet's own
   authentication and authorisation settings are read from the running
   kubelet, and kubelet-side activity leaves no API-server audit event, so the
   audit log cannot rule this out.
3. **Compromised workload as foothold.** Judgement: the pod's service account
   and the node's cloud identity are the identities to scope; the application
   exploit itself belongs to edge-exploitation.
4. **Cluster-admin or node reached.** Judgement: a node that ran a privileged
   or host-mounting pod is rebuilt, not cleaned; cluster-admin or etcd reach
   means the cluster CA and signing key are rotated or the cluster rebuilt.
5. **Poisoned image running.** Judgement: every pod on the image is
   compromised and every secret mounted into those pods is rotated; the image's
   provenance belongs to supply-chain.
6. **Agent-driven intrusion (ARTEX-class).** Judgement: findings arrive at
   machine speed across several paths at once, so containment is one wide
   move on the first confirmed finding; tool markers tie the findings into one
   intrusion.

## Criteria the sources give

See the YAML. Sources per criterion are named in `source`; the Kubernetes
documentation pages are cited by path so a reviewer can diff against the
current page.

## Not covered by any source

- Managed-service specifics (EKS authenticator log, GKE and AKS exports) are
  named only in `how` notes; no criterion depends on them.
- The ARTEX markers are campaign indicators as of 2026-10-29 and live in
  scenario 6's `indicators`; its discriminator is the machine-speed shape,
  which outlasts them. No criterion is specific to scenario 6.
- Nothing here has a `tested` date. The first real case sets it.

## Code touch points

- `criteria/kubernetes-compromise-response.yaml`: new file.
- `eval/cases.ts`: six cases in an analyst's words; `test/load.test.ts`
  playbook count 8 → 9.
- `IRNAV_EMBED_URL=… bun run build:index`; the index is hash-guarded.
- `IRNAV_DETECTIONS_URL=… IRNAV_DETECTIONS_AUTH=… bun run build:coverage` has
  not been run for this playbook: `index/coverage.json` dates from 2026-10-25
  and lacks the 13 technique ids only this playbook uses, and `ir_hunt` serves
  an unseen id as unknown.
- `bun run eval --write-baseline` once the new cases pass at recall@2.

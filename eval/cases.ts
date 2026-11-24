import type { EvalCase } from "../src/eval.ts";

/**
 * Evidence → expected reading, written as an analyst would describe a case and
 * deliberately NOT lifted from the scenarios' indicator text: cases copied from
 * the corpus measure string overlap with itself, not triage. Keep new cases in
 * your own words for the same reason.
 *
 * must_not_top1 marks the confusable neighbour this evidence must not be read
 * as first. BEC and device-code scenarios are drafts, not served, so no case
 * can expect them yet; bec-like evidence expects the served identity reading.
 */
export const CASES: EvalCase[] = [
  // ransomware-response
  {
    id: "rw-encrypting-now",
    expected: "ransomware-response/scenario-1",
    evidence:
      "Helpdesk is flooded: users cannot open documents, every file on the finance share now has a .lockbit extension and a README.txt sits in each folder. File server CPU is pinned.",
  },
  {
    id: "rw-recon-no-encryption",
    expected: "ransomware-response/scenario-2",
    must_not_top1: ["ransomware-response/scenario-1"],
    evidence:
      "EDR flagged AdFind and SharpHound on a domain controller run from a service account, a beacon-like process on two workstations calling out every 60s, and vssadmin delete shadows on a file server. Nothing is encrypted so far.",
  },
  {
    id: "rw-extortion-samples",
    expected: "ransomware-response/scenario-3",
    must_not_top1: ["ransomware-response/scenario-1"],
    evidence:
      "An email from a group claims they hold 200GB of our HR data and attached a zip of sample payslips. No encryption anywhere and the endpoints look clean.",
  },
  {
    id: "rw-vishing-remote-tool",
    expected: "ransomware-response/scenario-3",
    evidence:
      "An employee says someone posing as IT support phoned and walked them through installing a remote desktop tool; a week later an extortion demand arrived. No malware was found.",
  },
  {
    id: "rw-esxi-down",
    expected: "ransomware-response/scenario-4",
    evidence:
      "Every virtual machine on the ESXi cluster powered off at 02:00, datastore files carry a new extension, and SSH was enabled on the hosts outside any change.",
  },
  {
    id: "rw-backups-wiped",
    expected: "ransomware-response/scenario-5",
    must_not_top1: ["ransomware-response/scenario-1"],
    evidence:
      "The Veeam console shows restore points deleted and retention cut to one day, after a login from an account that never touches backups.",
  },
  {
    id: "rw-onedrive-hostage",
    expected: "ransomware-response/scenario-6",
    evidence:
      "Thousands of files in one user's OneDrive were modified within an hour and replaced with encrypted copies; a ransom note file appeared in SharePoint.",
  },
  // cloud-incident-response
  {
    id: "cl-key-in-repo",
    expected: "cloud-incident-response/scenario-1",
    evidence:
      "Secret scanning alerted that an AWS access key was committed to a public GitHub repo yesterday; CloudTrail shows ListBuckets calls with it from an IP in a country we do not operate in.",
  },
  {
    id: "cl-gpu-bill",
    expected: "cloud-incident-response/scenario-2",
    evidence:
      "Our AWS bill jumped 40x overnight: dozens of GPU instances in regions we never use, and a quota increase request nobody filed.",
  },
  {
    id: "cl-bucket-public",
    expected: "cloud-incident-response/scenario-3",
    evidence:
      "Someone removed an S3 bucket's public access block and the policy now grants allUsers read; an EBS snapshot was also shared with an external account id.",
  },
  {
    id: "cl-sse-c-ransom",
    expected: "cloud-incident-response/scenario-4",
    evidence:
      "Objects in our main S3 bucket were rewritten with SSE-C using a key we do not have, a lifecycle rule expiring everything was added, and a note demanding payment sits in the bucket root.",
  },
  {
    id: "cl-instance-creds-outside",
    expected: "cloud-incident-response/scenario-5",
    evidence:
      "GuardDuty says the EC2 instance role's credentials are being used from an IP outside AWS; the web app on that instance has an SSRF bug that reaches the metadata endpoint.",
  },
  {
    id: "cl-pipeline-role",
    expected: "cloud-incident-response/scenario-6",
    evidence:
      "Terraform applied changes that match no merged pull request; the deploy role was assumed from a GitHub runner we do not recognise, and its OIDC trust accepts any repository.",
  },
  {
    id: "cl-root-contacts",
    expected: "cloud-incident-response/scenario-7",
    evidence:
      "The root user signed in to the management account and changed the alternate security contact and the payment method; SCPs were detached from two OUs.",
  },
  // identity-breach-response
  {
    id: "id-spray-single-factor",
    expected: "identity-breach-response/scenario-1",
    must_not_top1: ["identity-breach-response/scenario-2"],
    evidence:
      "A user's account signed in from a VPS with single-factor auth because the app was excluded from MFA in Conditional Access; the same IP tried passwords against 300 other accounts.",
  },
  {
    id: "id-mfa-passed-proxy",
    expected: "identity-breach-response/scenario-2",
    must_not_top1: ["identity-breach-response/scenario-1"],
    evidence:
      "The sign-in passed MFA but came from a residential proxy with an unfamiliar browser fingerprint, minutes after the user clicked a link to a fake Microsoft login page.",
  },
  {
    id: "id-aitm-inbox-rule",
    expected: "identity-breach-response/scenario-2",
    evidence:
      "After a risky sign-in where MFA was satisfied, an inbox rule appeared moving all incoming mail to RSS Feeds and marking it read, and a new authenticator phone was registered.",
  },
  {
    id: "id-device-code-teams",
    expected: "identity-breach-response/scenario-3",
    evidence:
      "Entra sign-in logs show authenticationProtocol deviceCode for a user who says they joined a Teams meeting from an invite; there was no MFA prompt and tokens were requested right away from another IP.",
  },
  {
    id: "id-consent-mail-read",
    expected: "identity-breach-response/scenario-4",
    evidence:
      "A regular user consented to a new enterprise app asking for Mail.Read and Files.ReadWrite.All with offline_access; mailbox access carried on after we reset their password.",
  },
  {
    id: "id-keeps-coming-back",
    expected: "identity-breach-response/scenario-5",
    evidence:
      "The user says their account keeps getting taken over even after three password resets; sign-in logs show token use with no fresh authentication and an unknown device in their registered devices.",
  },
  {
    id: "id-api-key-stealer",
    expected: "identity-breach-response/scenario-6",
    evidence:
      "An OpenAI API key used by our CI pipeline turned up in an infostealer log, and the service principal it belongs to started making calls from a new ASN at 3am.",
  },
  {
    id: "id-global-admin-federation",
    expected: "identity-breach-response/scenario-7",
    must_not_top1: ["identity-breach-response/scenario-1"],
    evidence:
      "A Global Administrator account signed in from an unexpected country and a new federated domain was added to the tenant shortly after.",
  },
  {
    id: "id-vendor-guests",
    expected: "identity-breach-response/scenario-8",
    evidence:
      "A consultancy whose staff hold guest accounts in our tenant announced a breach, and one of their employees' credentials is in a stealer log.",
  },
  // clickfix-response
  {
    id: "cf-win-r",
    expected: "clickfix-response/scenario-1",
    evidence:
      "A user followed a fake CAPTCHA page telling them to press Win+R and paste; explorer.exe then launched mshta with a URL and a new RunMRU entry was written.",
  },
  {
    id: "cf-terminal-history",
    expected: "clickfix-response/scenario-2",
    must_not_top1: ["clickfix-response/scenario-1"],
    evidence:
      "PowerShell inside an already-open Windows Terminal downloaded and ran a script; RunMRU is empty but ConsoleHost_history.txt holds the pasted command.",
  },
  {
    id: "cf-explorer-address-bar",
    expected: "clickfix-response/scenario-3",
    must_not_top1: ["clickfix-response/scenario-1"],
    evidence:
      "The lure asked the user to paste a 'file path' into the File Explorer address bar; explorer.exe spawned PowerShell with a command ending in a comment that looks like a PDF path, and TypedPaths has a new value.",
  },
  {
    id: "cf-hta-download",
    expected: "clickfix-response/scenario-4",
    evidence:
      "Chrome saved an .hta file to Downloads and minutes later mshta.exe ran it with chrome.exe as the parent.",
  },
  {
    id: "cf-macos-stealer",
    expected: "clickfix-response/scenario-5",
    evidence:
      "On a MacBook the user pasted a curl | bash line into Terminal, then an osascript dialog asked for their password and a new binary appeared in /Users/Shared — looks like Atomic Stealer.",
  },
  {
    id: "cf-linux-dependency-fix",
    expected: "clickfix-response/scenario-6",
    must_not_top1: ["clickfix-response/scenario-5"],
    evidence:
      "A developer on Ubuntu pasted a 'dependency fix' that piped wget into bash; afterwards a new cron entry and an extra authorized_keys line appeared.",
  },
  // supply-chain-response
  {
    id: "sc-msp-rmm",
    expected: "supply-chain-response/scenario-1",
    evidence:
      "Our MSP told us their RMM platform was breached; we see scripts pushed through their agent to our servers outside any maintenance window.",
  },
  {
    id: "sc-npm-worm",
    expected: "supply-chain-response/scenario-2",
    must_not_top1: ["cloud-incident-response/scenario-6"],
    evidence:
      "A compromised npm package version was installed on our CI runners last night; node spawned trufflehog during npm install and new workflows appeared in our GitHub org.",
  },
  {
    id: "sc-signed-update",
    expected: "supply-chain-response/scenario-3",
    evidence:
      "The vendor says the signed desktop app update we rolled out last week was malicious; EDR flags the trusted app loading an odd DLL and calling unknown domains.",
  },
  // edge-exploitation-response. The first two are the logged cases closed as
  // "no playbook fit" (Ivanti advisory, PHP web app); the next three are the 2026-10-30
  // CTI alerts (Cisco SD-WAN, PHP2Shell on PAN-OS, VAPOR PANDA) as we first had them.
  {
    id: "edge-ivanti-advisory",
    expected: "edge-exploitation-response/scenario-1",
    evidence:
      "A threat report describes attackers chaining two unauthenticated zero-days in Ivanti Connect Secure VPN gateways. We have not checked whether we run one; nothing in our logs points at it yet.",
  },
  {
    id: "edge-php-crash-no-shell",
    expected: "edge-exploitation-response/scenario-2",
    must_not_top1: ["edge-exploitation-response/scenario-3"],
    evidence:
      "Our internet-facing RSS reader on PHP logs a burst of out-of-memory errors, huge session cookies and Apache child crashes from two scanning IPs. Process telemetry shows no shell or unexpected child under the web worker.",
  },
  {
    id: "edge-sdwan-advisory",
    expected: "edge-exploitation-response/scenario-1",
    evidence:
      "Cisco and Talos report limited exploitation of a Catalyst SD-WAN controller vulnerability, with custom malware dropped on the controllers to take IPsec keys. No hashes or IPs are published and we have not looked at our own network gear.",
  },
  {
    id: "edge-panos-rooted-report",
    expected: "edge-exploitation-response/scenario-1",
    evidence:
      "Researchers report two dozen Palo Alto firewalls rooted through a PHP flaw chained with a PAN-OS bug, now on the KEV list with a deadline today. We do not know yet whether any firewall of ours is that model or version.",
  },
  {
    id: "edge-vapor-panda-campaign",
    expected: "edge-exploitation-response/scenario-1",
    evidence:
      "A vendor attributes an AI-assisted espionage campaign to a China-nexus group: two hundred organisations targeted through their internet-facing services, a backdoor on nine. We have not checked what of ours is exposed.",
  },
  {
    id: "edge-php-fpm-shell",
    expected: "edge-exploitation-response/scenario-3",
    must_not_top1: ["edge-exploitation-response/scenario-2"],
    evidence:
      "Right after a malformed upload request, php-fpm on the public web server started sh, which ran curl to fetch a file into /tmp. The server is otherwise patched.",
  },
  {
    id: "edge-firewall-after-patch",
    expected: "edge-exploitation-response/scenario-4",
    evidence:
      "We patched the VPN firewall after the advisory, but the vendor's integrity tool still reports an extra line in an sshd service script and an unknown daemon set to start at boot.",
  },
  {
    id: "edge-tunnel-ip-other-account",
    expected: "edge-exploitation-response/scenario-5",
    must_not_top1: ["identity-breach-response/scenario-1"],
    evidence:
      "A domain controller logon came from an address in the VPN pool, but the account that logged on is not the VPN user who held that tunnel address at the time.",
  },
  // kubernetes-compromise-response. Written from the cases in docs/kubernetes-compromise-scope.md, not lifted from the
  // scenario indicators. The confusable neighbours are the cloud-key and non-human-identity
  // readings that ir_classify put first before this playbook existed.
  {
    id: "k8s-sa-token-from-outside",
    expected: "kubernetes-compromise-response/scenario-1",
    must_not_top1: ["cloud-incident-response/scenario-1"],
    evidence:
      "The kube-apiserver audit log shows one of our pods' service accounts listing secrets in several namespaces from a curl user agent on a public IP. The workload only ever talks to its own database. Nothing is encrypted.",
  },
  {
    id: "k8s-anonymous-kubelet",
    expected: "kubernetes-compromise-response/scenario-2",
    evidence:
      "A scan shows the kubelet on one worker node answering on port 10250 from outside, and anonymous requests as system:anonymous are being allowed. We never set --anonymous-auth=false. No audit events on the apiserver cover it.",
  },
  {
    id: "k8s-pod-metadata-service",
    expected: "kubernetes-compromise-response/scenario-3",
    must_not_top1: ["cloud-incident-response/scenario-5"],
    evidence:
      "Falco alerted that a container in a web app pod launched sh and then connected out to the instance metadata IP of the node's cloud account. The application itself was exploited through a file upload. The apiserver audit log shows nothing inside the container.",
  },
  {
    id: "k8s-cluster-admin-privileged-daemonset",
    expected: "kubernetes-compromise-response/scenario-4",
    must_not_top1: ["cloud-incident-response/scenario-1", "identity-breach-response/scenario-6"],
    evidence:
      "Audit events show a new ClusterRoleBinding to cluster-admin created by a workload identity, then a privileged DaemonSet with a hostPath mount of / scheduled into kube-system. One node ran it. Nothing is encrypted and there is no ransom note.",
  },
  {
    id: "k8s-backdoored-image",
    expected: "kubernetes-compromise-response/scenario-5",
    must_not_top1: ["supply-chain-response/scenario-2"],
    evidence:
      "We found pods in two namespaces running a container image whose registry digest no longer matches the one our pipeline built and signed. The running pods have database passwords and API keys mounted into their environment.",
  },
  {
    id: "k8s-agent-speed-parallel",
    expected: "kubernetes-compromise-response/scenario-6",
    evidence:
      "In under an hour one source drove tens of thousands of API calls against our cluster, hitting the web app, the cloud metadata service, several service account tokens and Active Directory at the same time, with the operator's own notes recovered from a dropped workspace tying all of it to one campaign. It went from first access to privileged in minutes.",
  },
];

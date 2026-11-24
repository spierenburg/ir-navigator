import { expect, test } from "bun:test";
import { cosine, polarTokens, rank, tokens } from "../src/rank.ts";

const ITEMS = [
  { id: "a", text: "ransom notes appearing, mass file renames, canary-token hits" },
  { id: "b", text: "C2 beacons, unexpected RMM tools such as anydesk, AD reconnaissance" },
  { id: "c", text: "large outbound transfers, archive staging with 7zip" },
];
const VEC: Record<string, number[]> = { a: [1, 0, 0], b: [0, 1, 0], c: [0, 0, 1] };

test("tokens ends on a letter or digit, so sentence punctuation never splits a match", () => {
  expect(tokens("the user ran mshta. then powershell.exe- and 10.0.0.5.")).toEqual([
    "user",
    "ran",
    "mshta",
    "then",
    "powershell.exe",
    "10.0.0.5",
  ]);
  expect(tokens("a.b ab- x-y")).toEqual(["a.b", "x-y"]);
});

test("tokens drops stopwords and short fragments", () => {
  expect(tokens("the ransom notes are on a server")).toEqual(["ransom", "notes", "server"]);
});

const n = (w: string) => `not ${w}`;
const POLAR_CASES: [string, string, string[]][] = [
  [
    "each negation covers its own clause",
    "No ransom note, no encryption, no extortion contact.",
    [n("ransom"), n("note"), n("encryption"), n("extortion"), n("contact")],
  ],
  [
    "or continues a negation; a contraction negates",
    "nothing destroyed or encrypted; files weren't touched",
    [n("destroyed"), n("encrypted"), "files", n("touched")],
  ],
  [
    "but ends it",
    "no encryption but ransom notes appeared",
    [n("encryption"), "ransom", "notes", "appeared"],
  ],
  [
    "a dash ends it",
    "no EDR alert — ransom notes appearing",
    [n("edr"), n("alert"), "ransom", "notes", "appearing"],
  ],
  [
    "a spaced hyphen ends it",
    "no evidence of encryption - files renamed",
    [n("evidence"), n("encryption"), "files", "renamed"],
  ],
  [
    "and starts a new clause",
    "No EDR alerts fired and the attacker encrypted the file servers",
    [n("edr"), n("alerts"), n("fired"), "attacker", "encrypted", "file", "servers"],
  ],
  [
    "not only is not a negation",
    "Not only were files encrypted but data was exfiltrated",
    ["only", "files", "encrypted", "data", "exfiltrated"],
  ],
  ["cannot negates", "logs cannot confirm encryption", ["logs", n("confirm"), n("encryption")]],
  [
    "a negation covers at most three words",
    "no persistence found on the hosts in finance",
    [n("persistence"), n("found"), n("hosts"), "finance"],
  ],
  [
    "a full stop before a quote ends it",
    `no "ransom." Files encrypted`,
    [n("ransom"), "files", "encrypted"],
  ],
  [
    "with or without is not a negation",
    "backups deleted, with or without encryption",
    ["backups", "deleted", "encryption"],
  ],
  [
    "dots inside a token never end it",
    "no powershell.exe on 10.0.0.5.",
    [n("powershell.exe"), n("10.0.0.5")],
  ],
  [
    "empty after a copula adds a negated subject and keeps the plain words",
    "Explorer launched it; RunMRU was empty",
    ["explorer", "launched", "runmru", n("runmru"), "empty"],
  ],
  [
    "a content-word copula or adverb is not the subject",
    "the RunMRU query returned empty; RunMRU is still empty",
    [
      "runmru",
      "query",
      "returned",
      n("runmru"),
      n("query"),
      "empty",
      "runmru",
      "still",
      n("runmru"),
      "empty",
    ],
  ],
  [
    "an absence inside an open negation cancels it",
    "No sign that the RunMRU key was empty",
    [n("sign"), "runmru", "key", "empty"],
  ],
  ["a stopword-only subject still keeps the absence word", "it is empty", ["empty"]],
  [
    "not empty is a double negative, not an absence",
    "The RunMRU key was not empty",
    ["runmru", "key", n("empty")],
  ],
  [
    "empty before a noun negates nothing before it",
    "Sign-in with an empty deviceId from a new ASN",
    ["sign-in", "empty", "deviceid", "new", "asn"],
  ],
  ["cleared is an event, not an absence", "security logs cleared", ["security", "logs", "cleared"]],
  [
    "text with no negation tokenises as tokens() does",
    "the ransom notes are on a server",
    tokens("the ransom notes are on a server"),
  ],
];

for (const [name, text, expected] of POLAR_CASES) {
  test(`polarTokens: ${name}`, () => expect(polarTokens(text)).toEqual(expected));
}

test("with polarTokens on both sides, a term matches only with the same polarity", () => {
  const items = [
    { id: "a", text: "ransom notes appearing" },
    { id: "b", text: "an extortion email, nothing encrypted" },
    { id: "c", text: "explorer launched it, nothing in RunMRU" },
  ];
  const match = (evidence: string) =>
    rank({
      items,
      queryTokens: polarTokens(evidence),
      queryVector: null,
      vectorFor: () => null,
      textFor: (i) => i.text,
      tokenize: polarTokens,
    });
  const r = match("no ransom note; nothing was encrypted");
  expect(r.find((x) => x.id === "a")?.matched).toEqual([]);
  expect(r.find((x) => x.id === "b")?.matched).toEqual([n("encrypted")]);
  expect(match("files encrypted").find((x) => x.id === "b")?.matched).toEqual([]);
  expect(match("RunMRU was empty").find((x) => x.id === "c")?.matched).toEqual([n("runmru")]);
});

test("cosine is 1 for identical and 0 for orthogonal vectors", () => {
  expect(cosine([1, 0], [1, 0])).toBeCloseTo(1, 6);
  expect(cosine([1, 0], [0, 1])).toBeCloseTo(0, 6);
});

test("exact term match outranks a weaker semantic match", () => {
  const r = rank({
    items: ITEMS,
    queryTokens: tokens("anydesk installed on two hosts"),
    queryVector: [0.6, 0.5, 0.6],
    vectorFor: (i) => VEC[i.id] ?? null,
    textFor: (i) => i.text,
  });
  expect(r[0]?.id).toBe("b");
  expect(r[0]?.matched).toContain("anydesk");
});

test("returns every item ranked — never truncates to the winner", () => {
  const r = rank({
    items: ITEMS,
    queryTokens: tokens("ransom"),
    queryVector: [1, 0, 0],
    vectorFor: (i) => VEC[i.id] ?? null,
    textFor: (i) => i.text,
  });
  expect(r).toHaveLength(3);
});

test("semantic score still ranks when no term matches", () => {
  const r = rank({
    items: ITEMS,
    queryTokens: tokens("files encrypted everywhere"),
    queryVector: [1, 0, 0],
    vectorFor: (i) => VEC[i.id] ?? null,
    textFor: (i) => i.text,
  });
  expect(r[0]?.id).toBe("a");
  expect(r[0]?.exact_score).toBe(0);
  expect(r[0]?.semantic_score).toBeGreaterThan(0);
});

test("ordering is deterministic for equal scores", () => {
  const opts = {
    items: ITEMS,
    queryTokens: tokens("printer offline"),
    queryVector: [0, 0, 0],
    vectorFor: (i: { id: string }) => VEC[i.id] ?? null,
    textFor: (i: { text: string }) => i.text,
  };
  expect(rank(opts).map((x) => x.id)).toEqual(rank(opts).map((x) => x.id));
});

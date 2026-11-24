const STOP = new Set([
  "the",
  "and",
  "a",
  "an",
  "of",
  "to",
  "in",
  "on",
  "at",
  "for",
  "with",
  "is",
  "are",
  "was",
  "were",
  "be",
  "been",
  "no",
  "not",
  "yet",
  "or",
  "that",
  "this",
  "it",
  "as",
  "by",
  "from",
  "nothing",
  "such",
  "two",
  "has",
  "have",
  "any",
]);

// A token ends on a letter or digit: "mshta." at the end of a sentence is "mshta".
const WORD = String.raw`[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?`;
const keep = (t: string) => t.length >= 3 && !STOP.has(t);

export function tokens(text: string): string[] {
  return (text.toLowerCase().match(new RegExp(WORD, "g")) ?? []).filter(keep);
}

const NEGATORS = new Set([
  "no",
  "not",
  "without",
  "never",
  "nor",
  "none",
  "nothing",
  "neither",
  "cannot",
  "nobody",
  "nowhere",
]);
// Words that start a new clause or turn it. "yet" is not one: "not yet encrypted" stays negated.
const SCOPE_END = new Set([
  "but",
  "however",
  "although",
  "though",
  "except",
  "and",
  "then",
  "while",
  "whereas",
  "because",
  "so",
]);
// "not only encrypted", "not all hosts": the claim is still made.
const NOT_A_NEGATION = new Set(["only", "just", "merely", "all", "necessarily"]);
// After a copula they also mark the words before it negated ("RunMRU was empty"). Not "cleared"
// or "wiped": "logs cleared" is an event.
const ABSENT = new Set(["empty", "absent", "blank"]);
const COPULA = new Set([
  "is",
  "was",
  "are",
  "were",
  "remains",
  "remained",
  "stays",
  "stayed",
  "returns",
  "returned",
]);
const COPULA_ADVERB = new Set(["still", "completely", "entirely"]);
const ABSENT_WORDS = 2;
// A negation covers at most this many content words. Stopping early falls back to tokens();
// running on inverts whatever the analyst says next.
const SCOPE_WORDS = 3;
// Clause punctuation: , ; : ! ? brackets, newline, dashes, and a full stop before a space,
// quote, bracket or the end — so powershell.exe and 10.0.0.5 stay one token.
const POLAR = new RegExp(
  String.raw`${WORD}|[,;:!?()\[\]\n—–]|(?<=\s)-+(?=\s)|\.(?=[\s"'’”)\]]|$)`,
  "g",
);

/** Index of the copula directly before words[i], allowing one adverb between ("is still"); -1 if none. */
function copulaBefore(words: string[], i: number): number {
  if (COPULA.has(words[i - 1] ?? "")) return i - 1;
  if (COPULA_ADVERB.has(words[i - 1] ?? "") && COPULA.has(words[i - 2] ?? "")) return i - 2;
  return -1;
}

function polarWords(text: string): { word: string; negated: boolean }[] {
  const words =
    text
      .toLowerCase()
      .replace(/n['’]t\b/g, " not")
      .match(POLAR) ?? [];
  const out: { word: string; negated: boolean }[] = [];
  let left = 0;
  let clauseStart = 0;
  for (const [i, w] of words.entries()) {
    if (NEGATORS.has(w)) {
      const notANegation =
        (w === "not" && NOT_A_NEGATION.has(words[i + 1] ?? "")) ||
        (w === "without" && words[i - 1] === "or" && words[i - 2] === "with");
      if (!notANegation) left = SCOPE_WORDS;
    } else if (SCOPE_END.has(w) || !/[a-z0-9]/.test(w)) {
      left = 0;
      clauseStart = out.length;
    } else if (ABSENT.has(w) && copulaBefore(words, i) >= 0) {
      // Additive: the subject keeps its plain token, so every match tokens() made survives, and
      // gains a negated one. Inside an open negation ("no sign that RunMRU was empty") the two
      // negations cancel. A copula or adverb that is itself a token is not the subject.
      let end = out.length;
      for (let k = i - 1; k >= copulaBefore(words, i); k--) if (keep(words[k] ?? "")) end--;
      for (let j = Math.max(clauseStart, end - ABSENT_WORDS); j < end; j++) {
        const p = out[j];
        if (!p) continue;
        if (p.negated) p.negated = false;
        else out.push({ word: p.word, negated: true });
      }
      left = 0;
      out.push({ word: w, negated: false });
      clauseStart = out.length;
    } else if (keep(w)) {
      out.push({ word: w, negated: left > 0 });
      if (left > 0) left--;
    }
  }
  return out;
}

/**
 * tokens(), with each word a negation covers marked "not <word>". "No ransom note" yields
 * "not ransom", which matches only another "not ransom" — tokens() drops "no" as a stopword
 * and would match "ransom" against indicators that say a note exists. Evidence and indicators
 * are tokenised alike, so "nothing encrypted" still agrees with "nothing encrypted".
 */
export function polarTokens(text: string): string[] {
  return polarWords(text).map((p) => (p.negated ? `not ${p.word}` : p.word));
}

export function cosine(a: number[], b: number[]): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    dot += x * y;
    na += x * x;
    nb += y * y;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

export type Scored<T> = T & {
  score: number;
  exact_score: number;
  semantic_score: number;
  matched: string[];
};

// Exact term hits are weighted above paraphrase similarity: a tool or process
// name matching verbatim is a stronger signal than prose that merely reads alike.
const EXACT_WEIGHT = 0.65;
const SEMANTIC_WEIGHT = 0.35;

export function rank<T extends { id: string }>(opts: {
  items: T[];
  queryTokens: string[];
  queryVector: number[] | null;
  vectorFor: (item: T) => number[] | null;
  textFor: (item: T) => string;
  /** How item text is tokenised; it must match how queryTokens were made. Defaults to tokens(). */
  tokenize?: (text: string) => string[];
}): Scored<T>[] {
  const q = new Set(opts.queryTokens);
  const tokenize = opts.tokenize ?? tokens;
  return opts.items
    .map((item) => {
      const matched = [...new Set(tokenize(opts.textFor(item)))].filter((t) => q.has(t)).sort();
      const exact = q.size === 0 ? 0 : matched.length / q.size;
      const vec = opts.vectorFor(item);
      const semantic = opts.queryVector && vec ? Math.max(0, cosine(opts.queryVector, vec)) : 0;
      return {
        ...item,
        matched,
        exact_score: Number(exact.toFixed(4)),
        semantic_score: Number(semantic.toFixed(4)),
        score: Number((EXACT_WEIGHT * exact + SEMANTIC_WEIGHT * semantic).toFixed(4)),
      };
    })
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
}

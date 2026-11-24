import { expect, test } from "bun:test";
import { redactText } from "../src/redact.ts";

/**
 * Properties, not examples: every regression in the redactor's review history was a
 * shape a hand-picked test missed and a 20k-sample fuzz caught in seconds (~14% of random
 * sk- keys, base64 ending in '=', unpadded base64 starting with '/', an empty '=' value
 * swallowing the next flag, exponential backtracking on backslash runs). Seeded, so a
 * failure reproduces. Values are synthetic.
 */
function rng(seed: number) {
  let s = seed;
  return () => {
    // Math.imul keeps the product in 32 bits; a plain multiply passes 2^53 and rounds
    // the low bits away, collapsing every seed into one short cycle.
    s = (Math.imul(s, 1103515245) + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE36 = "abcdefghijklmnopqrstuvwxyz0123456789";

function token(r: () => number, alphabet: string, length: number): string {
  let s = "";
  for (let i = 0; i < length; i++) s += alphabet[Math.floor(r() * alphabet.length)];
  return s;
}

function pick<T>(r: () => number, items: readonly T[]): T {
  return items[Math.floor(r() * items.length)] as T;
}

const N = 2000;

test("random sk- keys never survive, whatever the prefix or alphabet", () => {
  const r = rng(1);
  const bodies = [
    () => token(r, B64URL, 48),
    () => token(r, BASE36, 40),
    () => token(r, "0123456789abcdef", 64),
  ];
  for (const prefix of [
    "sk-",
    "sk-admin-",
    "sk-or-v1-",
    "sk-proj-",
    "sk-ant-api03-",
    "sk-svcacct-",
  ]) {
    let kept = 0;
    for (let i = 0; i < N; i++) {
      const key = `${prefix}${pick(r, bodies)()}`;
      if (redactText(`found ${key} in the paste`).includes(key)) kept++;
    }
    expect(kept, prefix).toBe(0);
  }
});

test("random flag values never survive, in any separator or encoding form", () => {
  const r = rng(2);
  const values = [
    () => token(r, B64, 43) + "=",
    () => token(r, B64, 40) + "==",
    () => token(r, B64, 48),
    () => `/${token(r, B64, 32)}`,
    () => `-${token(r, B64URL, 32)}`,
    () => `${token(r, BASE36, 10)}${Math.floor(r() * 1e6)}`,
  ];
  const flags = [
    "--password",
    "--client-secret",
    "--token",
    "--api-key",
    "--primary-key",
    "--sas-key",
  ];
  const seps = [" ", "=", " = ", "=\t", "\t"];
  for (const flag of flags) {
    let kept = 0;
    for (let i = 0; i < N; i++) {
      const sep = pick(r, seps);
      const value = pick(r, values)();
      // After a space a leading '-' is the next flag, not a value: by design.
      if (!sep.includes("=") && value.startsWith("-")) continue;
      if (redactText(`cmd ${flag}${sep}${value} run`).includes(value)) kept++;
    }
    expect(kept, flag).toBe(0);
  }
});

test("chained flags: no secret survives an empty or '-'-led value before it", () => {
  const r = rng(3);
  const names = [
    "--sas-key",
    "--account-key",
    "--password",
    "--api-key",
    "--client-secret",
    "--sas-token",
  ];
  const seps = [" ", "=", " = ", "=\t", "=  "];
  for (let i = 0; i < 20 * N; i++) {
    const secrets: string[] = [];
    const parts: string[] = [];
    for (let j = 0, n = 1 + Math.floor(r() * 4); j < n; j++) {
      const name = pick(r, names);
      const sep = pick(r, seps);
      if (r() < 0.25) {
        parts.push(`${name}${sep.includes("=") ? "=" : sep}`);
        continue;
      }
      const value = `${token(r, B64URL, 20)}Z9`;
      if (!sep.includes("=") && value.startsWith("-")) continue;
      secrets.push(value);
      parts.push(`${name}${sep}${value}`);
    }
    const input = parts.join(pick(r, [" ", "  ", " && "]));
    const out = redactText(input);
    for (const s of secrets) expect(out.includes(s), input).toBe(false);
  }
});

test("a second pass never changes the output", () => {
  const r = rng(4);
  const atoms = [
    "password",
    "api_key",
    "--token",
    "--sas-key",
    "=",
    ":",
    " ",
    '"',
    "'",
    "\\",
    "/",
    "@",
    ";",
    "&",
    "https://",
    "u:",
    "sk-",
    "Bearer ",
    "Cookie: a=",
    "[REDACTED:secret-value]",
    // One rule's tag can unblock another: these compose the shape main got wrong.
    "https://u:password=a/bc",
    "https://u:api_key=ab/cd",
    "token=Zx9/qr",
    "&@host",
    ";@host",
    "Zq9x",
    "a1B2c3D4e5F6g7H8",
  ];
  for (let i = 0; i < 25 * N; i++) {
    let input = "";
    for (let j = 0, n = 2 + Math.floor(r() * 10); j < n; j++) input += pick(r, atoms);
    const once = redactText(input);
    expect(redactText(once), input).toBe(once);
  }
});

test("worst-case inputs stay linear", () => {
  for (const fragment of [
    "a-",
    "a_",
    "a.",
    "-eyJ",
    "sk-",
    "sk-a1-",
    "--a-",
    "--a-b-key= ",
    "a://b@c:",
    "redis://:",
    'password="',
    '\\"password\\":\\"',
    "\\",
    "Cookie: a=b; ",
    "token='a ",
  ]) {
    const input = fragment.repeat(Math.ceil(64000 / fragment.length));
    const started = performance.now();
    redactText(input);
    expect(performance.now() - started, fragment).toBeLessThan(100);
  }
});

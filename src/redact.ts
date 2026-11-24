/**
 * Credentials an analyst pastes mid-incident (a bearer token from a request,
 * a cookie from a HAR, a key from a leaked repo) must not land verbatim in
 * provenance.jsonl. Secrets only: emails, UPNs, IPs, hostnames, key *ids*
 * (AKIA…) and cookie names are the evidence the log exists to join, so they
 * are kept — and so is prose. "Basic authentication/IMAP" and "password:
 * reset by helpdesk" are evidence, not credentials: rules that would match
 * prose check that the value is credential-shaped before replacing it.
 * Placeholders never match a rule again, so redaction is idempotent.
 */
type Replacer = (match: string, ...groups: string[]) => string;
const tag = (kind: string) => `[REDACTED:${kind}]`;

/**
 * A Basic credential is base64 of "user:password"; prose is not. Unpadded
 * base64 is re-padded: clients and copy-paste both drop the '='.
 */
function isBasicCredential(token: string): boolean {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(token)) return false;
  const padded = token.replace(/=+$/, "").padEnd(Math.ceil(token.length / 4) * 4, "=");
  try {
    return atob(padded).includes(":");
  } catch {
    return false;
  }
}

/** Opaque tokens mix letters and digits, or run long in mixed case; prose words do neither. */
const isOpaqueToken = (s: string) =>
  (/[A-Za-z]/.test(s) && /\d/.test(s)) || (s.length >= 20 && /[a-z]/.test(s) && /[A-Z]/.test(s));

/** Sentence punctuation is not part of the value: "password: reset." is a word and a full stop. */
const TRAILING_PUNCTUATION = /[.,!?;:]+$/;

/** Names that read as ordinary words in prose ("the password: reset by helpdesk"). */
const PROSE_NAME = /^(?:password|passwd|pwd|pass|secret|token|credentials?)$/i;

/**
 * '=' or a quote marks config or JSON syntax ("password":"changeme"), and the
 * value is redacted whatever it looks like; so is any compound name
 * (DB_PASSWORD, api_key), which is never prose. Only a bare prose name with an
 * unquoted ':' can be followed by a word, and then only a credential-shaped
 * value counts: a digit, a symbol other than '-' or '.', or long mixed case.
 */
function isSecretValue(name: string, separator: string, value: string): boolean {
  if (/[="']/.test(separator) || !PROSE_NAME.test(name)) return true;
  const v = value.replace(TRAILING_PUNCTUATION, "");
  // "<redacted>", "(n/a)", "<user.name>": a placeholder is letters and '/', '.', '_', '-'.
  // A digit anywhere makes it a value: "(Summer2024)" and "<Spr1ng!>" are passwords.
  if (/^[<([][A-Za-z][A-Za-z_./-]*[>)\]]$/.test(v)) return false;
  // "token: revoked)" and "(token: expired?)" close a parenthesis around a word: the
  // bracket and the punctuation inside it are not the value's.
  const w = v.replace(/[.,!?;:)\]>]+$/, "");
  return (
    /\d/.test(w) ||
    /[^A-Za-z0-9.-]/.test(w) ||
    (w.length >= 8 && /[a-z]/.test(w) && /[A-Z]/.test(w))
  );
}

/**
 * A quoted value, or an unclosed quote, is always a value, and a mask (********) never is.
 * There is no exemption for what looks like a reference ($DB_PASS, a path, an ARN):
 * unpadded base64 is a valid path and "$HUNTER2" a valid env var, so every such exemption
 * leaked real secrets; a redacted reference costs a little evidence, a kept secret does
 * not come back. A compound name (--client-secret) is never prose, and a bare --password
 * or --token is judged like "password:", so "a --password reset link" is kept.
 */
function isFlagSecret(name: string, separator: string, value: string): boolean {
  if (/^["']/.test(value)) return true;
  if (/^\*+$/.test(value)) return false;
  // --password=word is config syntax, like password=word: never prose.
  return isSecretValue(name, separator, value);
}

/** A flag name that carries a secret: every --\u2026-key flag except the evidence ones. */
const FLAG_NAME = String.raw`(?:[a-z0-9]+[-_]){0,5}(?:password|passwd|pwd|passphrase|token|secret|pass)|(?!(?:[a-z0-9]+[-_]){0,4}(?:sort|partition|hash|range|row|foreign|ssh|gpg|pgp|kms|public|run|object|idempotency)[-_]key(?:(?:[^\S\n]|=)|$))(?:[a-z0-9]+[-_]){1,5}key`;

/**
 * The next secret flag, not a value: in "--client-secret=  --sas-token = V" the empty '='
 * value of --client-secret must not take "--sas-token", or V is left with no flag name in
 * front of it and no rule redacts it.
 */
const NEXT_FLAG = String.raw`--?(?:${FLAG_NAME})(?:(?:[^\S\n]|=)|$)`;

/** Where a quoted value would run into the next secret flag: after spaces or a shell joiner. */
const FLAG_BOUNDARY = String.raw`(?:[^\S\n]{1,16}|[;&|][^\S\n]{0,16})${NEXT_FLAG}`;

/** Set-Cookie attributes are not cookies: Domain and Path are host evidence. */
const COOKIE_ATTRIBUTE = /^(?:path|domain|expires|max-age|samesite)=$/i;

/**
 * Values only: cookie names are evidence. The attribute exemption applies to Set-Cookie
 * only: a request cookie can be named Path or Domain, and its value is still a cookie.
 */
const redactCookiePairs = (pairs: string, setCookie = false) =>
  pairs.replace(/([^\s=;]+=)(?!\[REDACTED)[^\s;]+/g, (pair, name: string) =>
    setCookie && COOKIE_ATTRIBUTE.test(name) ? pair : `${name}${tag("cookie")}`,
  );

/** Horizontal whitespace of any kind (a pasted non-breaking space too), never a newline. */
const HS = String.raw`[^\S\n]`;

const COOKIES_OPEN = /"cookies"[^\S\n]*:[^\S\n]*\[/gi;
const HAR_VALUE = /("value"[^\S\n]*:[^\S\n]*")(?!\[REDACTED)(?:[^"\\\n]|\\.){1,8192}"/gi;

/**
 * HAR "cookies": [ … ] arrays, where every "value" is a cookie. Scanned rather than matched:
 * a ']' inside a string does not end the array, and the scan resumes where the last array
 * ended, so no start rescans the text after it (a regex with a bounded body was quadratic).
 */
function redactHarCookieArrays(text: string): string {
  let out = "";
  let last = 0;
  COOKIES_OPEN.lastIndex = 0;
  for (let m = COOKIES_OPEN.exec(text); m; m = COOKIES_OPEN.exec(text)) {
    const start = m.index + m[0].length;
    let i = start;
    let inString = false;
    for (; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (ch === "\\") i++;
        else if (ch === '"') inString = false;
      } else if (ch === '"') inString = true;
      else if (ch === "]") break;
    }
    i = Math.min(i, text.length);
    out +=
      text.slice(last, start) +
      text.slice(start, i).replace(HAR_VALUE, (_v, label: string) => `${label}${tag("cookie")}"`);
    last = i;
    COOKIES_OPEN.lastIndex = i;
  }
  return out + text.slice(last);
}

// "pass" only as a whole word or after a separator (DB_PASS), never inside bypass or compass.
const SECRET_NAME =
  "(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?key|account[_-]?key|secret[_-]?key|subscription[_-]?key|encryption[_-]?key|master[_-]?key|signing[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|private[_-]?key|storage[_-]?key|primary[_-]?key|shared[_-]?key|passphrase|credentials?|saml[_-]?response|sig|(?<![A-Za-z0-9])pass)";

const CDATA_OPEN = new RegExp(
  `<(?:[\\w-]{1,40}:)?[\\w-]{0,40}?${SECRET_NAME}(?:${HS}[^<>]{0,256})?>(?:\\s{0,64}<(?:[\\w-]{1,40}:)?Value>)?\\s{0,64}<!\\[CDATA\\[`,
  "gi",
);

/**
 * A secret element's CDATA section is redacted whole, up to its ']]>': CDATA exists to carry
 * '<', which ends the plain XML rule's value. Scanned, not matched, so the search for ']]>'
 * resumes after the last one and no start rescans the text.
 */
function redactXmlCdata(text: string): string {
  let out = "";
  let last = 0;
  CDATA_OPEN.lastIndex = 0;
  for (let m = CDATA_OPEN.exec(text); m; m = CDATA_OPEN.exec(text)) {
    const start = m.index + m[0].length;
    if (text.startsWith("[REDACTED", start)) continue;
    const end = text.indexOf("]]>", start);
    if (end < 0) break; // no later section can close either; the plain XML rule takes it
    out += `${text.slice(last, start)}${tag("secret-value")}`;
    last = end;
    CDATA_OPEN.lastIndex = end;
  }
  return out + text.slice(last);
}

const RULES: [pattern: RegExp, replace: Replacer][] = [
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
    () => tag("private-key"),
  ],
  // The character before eyJ must not be a token character, so a run of "-eyJ" is linear.
  [
    /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    () => tag("jwt"),
  ],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})/g, () => tag("github-token")],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, () => tag("npm-token")],
  [/\bxox[abeprs]-[A-Za-z0-9-]{10,}/g, () => tag("slack-token")],
  // Every sk- token of 20+ characters is a key unless it is a lowercase host or package
  // name: short words joined by hyphens (sk-prod-web-server-01, sk-learn-pipeline-v2),
  // with no long hex run and fewer than three hex segments (sk-lf-<uuid> is a key). Anything
  // else — mixed case, '_', one long lowercase run — is redacted: key bodies are random
  // base62/base64url or hex.
  [
    /\bsk-[A-Za-z0-9_-]{20,}/g,
    (m) =>
      /^sk-[a-z0-9]{1,16}(?:-[a-z0-9]{1,16})+$/.test(m) &&
      !/[0-9a-f]{32}/.test(m) &&
      (m.match(/-[0-9a-f]{4,}(?=-|$)/g)?.length ?? 0) < 3
        ? m
        : tag("api-key"),
  ],
  [/\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g, () => tag("stripe-key")],
  [/\bAIza[0-9A-Za-z_-]{35}/g, () => tag("google-api-key")],
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, () => tag("gitlab-token")],
  [/\bya29\.[A-Za-z0-9_-]{20,}/g, () => tag("google-oauth-token")],
  [/\bpypi-AgE[A-Za-z0-9_-]{20,}/g, () => tag("pypi-token")],
  // Basic credentials are short ("root:toor" is 12 characters of base64); a Bearer token
  // shorter than 16 is not told apart from a word, so the length floor stays on Bearer only.
  // A scheme word is never the value: "Basic Bearer <token>" must leave Bearer to match.
  // Only the bare word: "Bearer Basic.abc123…" is a token that starts with the letters.
  [
    /\b(Bearer|Basic)(\s+)(?!\[REDACTED|(?:Bearer|Basic)(?:\s|$))([A-Za-z0-9._~+/=-]{4,})/gi,
    (m, scheme = "", space = "", raw = "") => {
      // A sentence-final "." (or a stray -_~) is not part of the token, and is kept after the tag.
      const token = raw.replace(/[._~-]+$/, "");
      const basic = scheme.toLowerCase() === "basic";
      const secret = basic ? isBasicCredential(token) : token.length >= 16 && isOpaqueToken(token);
      return secret ? `${scheme}${space}${tag("auth-header")}${raw.slice(token.length)}` : m;
    },
  ],
  // In an Authorization header the label removes the ambiguity the rule above guards
  // against, so every value is a credential: any scheme (Bearer of any length, NTLM, SSWS,
  // token, Digest) or none (Authorization: <token>). The scheme name is kept as evidence.
  [
    new RegExp(
      // The value may be quoted, as in YAML or ini (Authorization: "Token …"); the quote is kept.
      String.raw`\b((?:Proxy-)?Authorization:${HS}*["']?)(?!\[REDACTED)(?:([A-Za-z][\w-]{0,30})(${HS}+)(?!\[REDACTED)|(?![A-Za-z][\w-]{0,30}${HS}+\S))([^\s"']{4,})`,
      "gi",
    ),
    (_m, label = "", scheme = "", space = "") => `${label}${scheme}${space}${tag("auth-header")}`,
  ],
  // The same header as JSON, a Python dict or escaped JSON ({"Authorization": …},
  // {'Authorization': …}, {\"Authorization\": …}) and as HAR's {"name": "Authorization", "value": …}.
  // The quote is captured once, with any backslashes before it, and matched again by reference.
  [
    new RegExp(
      String.raw`((\\{0,3}["'])(?:name\2${HS}*:${HS}*\2(?:Proxy-)?Authorization\2${HS}*,${HS}*\2value|(?:Proxy-)?Authorization)\2${HS}*:${HS}*\2)(?!\[REDACTED)(?:([A-Za-z][\w-]{0,30})(${HS}+)(?!\[REDACTED)|(?![A-Za-z][\w-]{0,30}${HS}+\S))(?:(?!\2)\S){4,}`,
      "gi",
    ),
    (_m, open = "", _quote = "", scheme = "", space = "") =>
      `${open}${scheme}${space}${tag("auth-header")}`,
  ],
  // Values only: cookie names are evidence, and so is the text after the cookie list.
  [
    /\b((?:Set-)?Cookie:[^\S\n]*)((?:[^\s=;]+=[^\s;]*;?[^\S\n]*)+)/gi,
    (_m, label = "", pairs = "") => label + redactCookiePairs(pairs, /^set-/i.test(label)),
  ],
  // The same cookies outside a header line: curl's -b / --cookie, a HAR Cookie header
  // object, and a HAR cookies array (whose entries are {"name": …, "value": …}).
  [
    /(?<![\w-])(-b|--cookie)([^\S\n]+|[^\S\n]*=[^\S\n]*)(?:(["'])((?:(?!\3)[^\n]){1,8192})\3|([^\s"']+))/g,
    (m, flag = "", sep = "", quote = "", quoted = "", bare = "") => {
      const value = quote ? quoted : bare;
      if (!value.includes("=")) return m; // -b cookies.txt names a file
      const redacted = redactCookiePairs(value);
      return `${flag}${sep}${quote}${redacted}${quote}`;
    },
  ],
  // A HAR Cookie header object, or a "cookie" / "Set-Cookie" key holding a cookie string, in
  // JSON or a Python dict. The value steps over escapes: a quoted cookie value (a=\"x\") is
  // part of the string, not its end, so the cookies after it are still read.
  [
    new RegExp(
      String.raw`((["'])(?:name\2${HS}*:${HS}*\2((?:Set-)?Cookie)\2${HS}*,${HS}*\2value|((?:set-)?cookies?))\2${HS}*:${HS}*\2)((?:\\.|(?!\2)[^\\\n])+)\2`,
      "gi",
    ),
    (_m, open = "", quote = "", harName = "", keyName = "", value = "") =>
      `${open}${redactCookiePairs(value, /^set-/i.test(harName || keyName))}${quote}`,
  ],
  // The same inside escaped JSON ({\"cookie\": \"…\"}): the quote is a run of backslashes and
  // a quote, captured once and matched by reference. Kept separate from the rule above, as one
  // rule doing both was quadratic on runs of escaped quotes.
  [
    new RegExp(
      String.raw`((\\{1,3}["'])(?:name\2${HS}*:${HS}*\2((?:Set-)?Cookie)\2${HS}*,${HS}*\2value|((?:set-)?cookies?))\2${HS}*:${HS}*\2)((?:(?!\2)[^\n])+)\2`,
      "gi",
    ),
    (_m, open = "", quote = "", harName = "", keyName = "", value = "") =>
      `${open}${redactCookiePairs(value, /^set-/i.test(harName || keyName))}${quote}`,
  ],
  [/[\s\S]+/g, (text) => redactHarCookieArrays(text)],
  [/[\s\S]+/g, (text) => redactXmlCdata(text)],
  // mysql's -p takes the password with no space (-pS3cret, -p'two words'); elsewhere -p
  // means a port or a path, so the rule is anchored on the mysql and mariadb clients.
  [
    /\b((?:[mM][yY][sS][qQ][lL]|[mM][aA][rR][iI][aA][dD][bB])(?:-?dump|-?admin|sh|-?import)?(?:\.exe)?\b[^\n|;&]{0,512}?[^\S\n])-p(?!\[REDACTED)(?:"[^"\n]{1,1024}"|'[^'\n]{1,1024}'|[^\s"'-][^\s"']*)/g,
    (_m, pre = "") => `${pre}-p${tag("secret-value")}`,
  ],
  // XML elements: <Password>…</Password>, namespaced (<wsse:Password>), in CDATA, and
  // unattend.xml's <Password><Value>…</Value>. The value runs to the next '<' or ']]>'.
  [
    new RegExp(
      `(<(?:[\\w-]{1,40}:)?[\\w-]{0,40}?${SECRET_NAME}(?:[^\\S\\n][^<>]{0,256})?>(?:\\s{0,64}<(?:[\\w-]{1,40}:)?Value>)?(?:\\s{0,64}<!\\[CDATA\\[)?)(?!\\[REDACTED|\\s*<)[^<]+?(?=\\]\\]>|<)`,
      "gi",
    ),
    (_m, open = "") => `${open}${tag("secret-value")}`,
  ],
  // The scheme is bounded so a long run of "a." is not rescanned from every position. The
  // username may itself be a UPN (ftp://alice@corp.com:pw@host) or empty (redis://:pw@host);
  // an IPv6 host ([fe80::1]) is not one. The password runs to the '@': pasted connection
  // strings are rarely percent-encoded, and '#', '?' or '&' in one is common. A port with a
  // path (host:443/…?login_hint=alice@corp) or inside JSON ("…:8443","upn":"a@corp") is
  // kept because '/' and '"' end the match. host:8080?login_hint=alice@corp, with no path,
  // reads exactly like bob:2024?Spring@db, and is redacted: lost evidence, not a leak.
  [
    // '/' or '@' inside the password (base64 passwords, P@ss/1) is taken only while another
    // '@' follows before any whitespace; a port followed by a path (:443/…) is never one.
    // Runs between them are matched atomically ((?=(…))\2), so a password of any length is
    // one step and a failed match does not backtrack through it. At most 64 '/' or '@'
    // segments bound how far one start can scan across later URLs on the same line.
    /\b([a-z][a-z0-9+.-]{0,31}:\/\/)(?!\[REDACTED)[^\s/:@"?#[\]]*(?:@[^\s/:@"?#[\]]+)?:(?!\d{1,5}(?:[/"]|$))(?:(?=([^\s/@"]+))\2|\/(?=[^\s@"]{0,256}@)|@(?=[^\s@"]{0,256}@)){1,64}(?=@)/gi,
    (_m, scheme = "") => `${scheme}${tag("url-credentials")}`,
  ],
  // A quoted value is redacted whole, up to its closing quote: "correct horse battery staple"
  // and "p&ssw0rd" carry characters the unquoted rule below stops at. A closing single
  // quote is never followed by a letter or digit: in "token: 'it's gone'" it is an apostrophe.
  [
    new RegExp(
      `(?<![A-Za-z0-9])([\\w-]{0,40}?${SECRET_NAME})(["']?[^\\S\\n]*(?:=>|:=|[=:])[^\\S\\n]*)(["'])(?!\\[REDACTED)((?:(?!\\3|${FLAG_BOUNDARY})[^\\\\\\n]|\\\\.){1,1024})\\3(?!(?<=')[A-Za-z0-9])`,
      "gi",
    ),
    (_m, name = "", separator = "", quote = "") =>
      `${name}${separator}${quote}${tag("secret-value")}${quote}`,
  ],
  // JSON escaped inside a log line: {\"password\":\"correct horse\"}. A quote escaped once
  // more inside the value (\\\") does not end it; an escaped backslash (\\\\) before the
  // closing \" is part of the value, not an escape of the quote. The alternatives never
  // overlap on a run of backslashes: overlapping, a truncated value full of Windows path
  // separators backtracks exponentially, hits the engine's limit and the rule stops applying.
  [
    new RegExp(
      String.raw`(?<![A-Za-z0-9])([\w-]{0,40}?${SECRET_NAME})(\\"[^\S\n]*:[^\S\n]*\\")(?!\[REDACTED)((?:[^\\\n]|\\+(?![\\"])|(?:\\\\\\\\)*\\\\\\"|(?:\\\\\\\\)+(?=\\")){1,1024})\\"`,
      "gi",
    ),
    (_m, name = "", separator = "") => `${name}${separator}${tag("secret-value")}\\"`,
  ],
  // JSON escaped twice or more (a log line holding an escaped log line): the quotes carry a
  // run of N backslashes, and the value ends at the next run of exactly N before a quote.
  [
    new RegExp(
      String.raw`(?<![A-Za-z0-9])([\w-]{0,40}?${SECRET_NAME})((\\{2,})"[^\S\n]*:[^\S\n]*\3")(?!\[REDACTED)((?:(?!(?<!\\)\3")[^\n]){1,1024})(?<!\\)\3"`,
      "gi",
    ),
    (_m, name = "", separator = "", slashes = "") =>
      `${name}${separator}${tag("secret-value")}${slashes}"`,
  ],
  // A quoted value never runs across a following secret flag: an unclosed quote before
  // "--primary-key='-V" would otherwise swallow that flag and leave V unredacted.
  // Command-line flags, compound ones included (--client-secret, --admin-password,
  // --account-key, --shared-key). Every --…-key flag is a secret except the ones known to
  // carry evidence (--sort-key, --partition-key, --ssh-key, --public-key, --run-key): an
  // allowlist of secret names missed --primary-key, --sas-key and dozens more. The value
  // follows a space or '=' (--primary-key=…), and names run to six segments
  // (--destination-storage-account-access-key). A value never starts with '-' here: after
  // a space that is the next flag (--api-key --verbose), and an empty '=' value must not
  // swallow the next flag's name. '='-values that do start with '-' have their own last rule.
  [
    new RegExp(
      String.raw`(?<![\w-])(--?(${FLAG_NAME})([^\S\n]+|[^\S\n]*=[^\S\n]*))("(?:(?!${FLAG_BOUNDARY})[^"\n]){1,1024}"|'(?:(?!${FLAG_BOUNDARY})[^'\n]){1,1024}'|["']?(?!\[REDACTED|-)(?:(?!${FLAG_BOUNDARY})[^\s"']){4,})`,
      "gi",
    ),
    (m, flag = "", name = "", separator = "", value = "") =>
      isFlagSecret(name, separator, value) ? `${flag}${tag("secret-value")}` : m,
  ],
  // No word boundary before the name: DB_PASSWORD and AWS_SECRET_ACCESS_KEY have none.
  // The prefix is bounded: unbounded, a run of "a-" rescans to the end from every position.
  [
    new RegExp(
      // '&', ',' and ';' end the value only before a space or the next pair, in any of its
      // forms (name=, name:, name =, "name":): "Pa;ssw0rd" and "Summer,2024!" are one
      // value, "?token=V&user=bob" and "password=abc&token: V" are two. No length cap: the
      // two alternatives never match the same character, so nothing backtracks, and a cap
      // left the tail of a long token in clear. The separator is any of = : => := (Ruby, PHP,
      // Go, Makefile). After an opening quote the value stops at a quote; unquoted, a quote
      // is part of the value (DB_PASSWORD=Ab1'S3cret is one value).
      `(?<![A-Za-z0-9])([\\w-]{0,40}?${SECRET_NAME})(["']?[^\\S\\n]*(?:=>|:=|[=:])[^\\S\\n]*["']?)(?!\\[REDACTED|${NEXT_FLAG})((?:(?<=["'])(?:[^\\s"'&,;]|[&,;](?![^\\S\\n]|["']?[\\w-]{1,40}["']?[^\\S\\n]*[=:]))+|(?<!["'])(?!["'])(?:[^\\s&,;]|[&,;](?![^\\S\\n]|["']?[\\w-]{1,40}["']?[^\\S\\n]*[=:]))+))`,
      "gi",
    ),
    // '=' is config syntax and redacts a value of any length; after ':' a value needs four
    // characters, as "pwd: n/a" and "token: 'it's gone'" are prose. Quoted values have their
    // own rule above.
    (m, name = "", separator = "", value = "") =>
      isSecretValue(name, separator, value) && (value.length >= 4 || separator.includes("="))
        ? `${name}${separator}${tag("secret-value")}`
        : m,
  ],
  // An '='-value that starts with '-' (--sas-key=-Zm9v…, 1 in 64 base64url values). Last, so
  // every other rule has already redacted a following flag: in "--sas-key= --account-key V"
  // the flag rule takes V first. Neither this rule nor the name=value rule above takes the
  // next secret flag as a value (NEXT_FLAG), so --sas-token's own '-'-led value is still caught.
  [
    new RegExp(
      String.raw`(?<![\w-])(--?(?:${FLAG_NAME})(?:[^\S\n]*=[^\S\n]*["']?|[^\S\n]+["']))(?!\[REDACTED|${NEXT_FLAG})(-[^\s"';&|]{3,})`,
      "gi",
    ),
    (_m, flag = "") => `${flag}${tag("secret-value")}`,
  ],
];

/**
 * Rules run to a fixed point: one rule's tag can remove the character that stopped an
 * earlier rule (https://u:password=a/bc;@host loses its '/' to the name=value rule, and
 * only then reads as URL credentials), and a second pass must not change a first pass's
 * output. Real text settles in one or two passes; input nested to need more is crafted,
 * and is replaced whole rather than logged half-redacted. An uncapped loop is quadratic.
 */
const MAX_PASSES = 8;

export function redactText(text: string): string {
  let out = text;
  for (let pass = 0; pass < MAX_PASSES; pass++) {
    let next = out;
    for (const [pattern, replace] of RULES) next = next.replace(pattern, replace);
    if (next === out) return out;
    out = next;
  }
  return tag("unstable-input");
}

/** A key that names a secret: {password: "…"} never passes through a name=value rule. */
const SECRET_KEY = new RegExp(
  `^(?:[\\w-]{0,40}?${SECRET_NAME}|(?:set-)?cookies?|(?:proxy-)?authorization)$`,
  "i",
);

/**
 * Every string at any depth, keys included: a refused call is logged with the
 * arguments that failed validation, so a key is not known to be a schema field.
 * The value under a secret-named key is replaced whole, whatever its shape
 * ({password: ["…"]} as much as {password: "…"}); the key is evidence.
 */
export function redactArgs<T>(value: T): T {
  if (typeof value === "string") return redactText(value) as T;
  if (Array.isArray(value)) return value.map(redactArgs) as T;
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([k, v]) => [
      redactText(k),
      SECRET_KEY.test(k) && v !== null && v !== undefined && typeof v !== "boolean"
        ? tag("secret-value")
        : redactArgs(v),
    ]),
  ) as T;
}

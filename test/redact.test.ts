import { expect, test } from "bun:test";
import { redactArgs, redactText } from "../src/redact.ts";

const SECRETS: [string, string][] = [
  ["jwt", "eyJhbGciOiJSUzI1NiJ9.eyJ1cG4iOiJ1QGV4LmNvbSJ9.c2lnbmF0dXJlX2J5dGVz"], // gitleaks:allow — fake fixture token
  ["github", `ghp_${"A1b2".repeat(9)}`],
  ["github fine-grained", `github_pat_${"x9".repeat(15)}`],
  ["npm", `npm_${"Z".repeat(36)}`],
  ["slack", "xoxb-1234567890-abcdefghij"],
  ["anthropic", `sk-ant-api03-${"k".repeat(40)}`],
  ["openai project", `sk-proj-${"p".repeat(40)}`],
  ["stripe", `sk_live_${"s".repeat(24)}`],
  ["google", `AIza${"G".repeat(35)}`],
  ["pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"], // gitleaks:allow — fake fixture key
];

// Built at runtime so no credential-shaped literal sits in the source.
const OPAQUE = "a1B2c3D4".repeat(4);
const VALUE = "x1Y2".repeat(4);
const BASIC = btoa("svc-backup:Winter2026");

test("each credential shape is replaced", () => {
  for (const [label, secret] of SECRETS) {
    const out = redactText(`found ${secret} in the paste`);
    expect(out, label).not.toContain(secret);
    expect(out, label).toMatch(/\[REDACTED:[a-z-]+\]/);
  }
});

test("auth headers are redacted when the token is credential-shaped", () => {
  expect(redactText(`Authorization: Bearer ${OPAQUE}`)).toBe(
    "Authorization: Bearer [REDACTED:auth-header]",
  );
  expect(redactText(`Authorization: Basic ${BASIC}`)).toBe(
    "Authorization: Basic [REDACTED:auth-header]",
  );
});

test("prose after Basic or Bearer is evidence, not a token", () => {
  for (const prose of [
    "legacy Basic authentication/IMAP sign-ins from 203.0.113.7",
    "basic infrastructure-as-code drift on the deploy role",
    "the Bearer authentication-scheme header was replayed",
  ]) {
    expect(redactText(prose)).toBe(prose);
  }
});

test("cookie values are redacted; names and the text after them are kept", () => {
  expect(redactText(`Cookie: ESTSAUTH=${VALUE}; x=1 replayed from 203.0.113.7 on WS-FIN-04`)).toBe(
    "Cookie: ESTSAUTH=[REDACTED:cookie]; x=[REDACTED:cookie] replayed from 203.0.113.7 on WS-FIN-04",
  );
  const prose = "the Cookie: header was replayed from 10.1.2.3";
  expect(redactText(prose)).toBe(prose);
});

test("secret assignments are redacted, env-style and prefixed names included", () => {
  expect(redactText(`client_secret="${VALUE}"`)).toBe('client_secret="[REDACTED:secret-value]"');
  for (const name of [
    "DB_PASSWORD",
    "AWS_SECRET_ACCESS_KEY",
    "aws_secret_access_key",
    "my_password",
    "AccountKey",
    "X-API-Key",
    "access_token",
    "sig",
  ]) {
    for (const sep of ["=", ": ", " = "]) {
      const out = redactText(`${name}${sep}${VALUE}`);
      expect(out, `${name}${sep}`).toBe(`${name}${sep}[REDACTED:secret-value]`);
    }
  }
  expect(redactText("https://svc:hunter22@10.0.0.5/api")).toBe(
    "https://[REDACTED:url-credentials]@10.0.0.5/api",
  );
});

test("a plain word after 'password:' or 'secret:' is prose and stays", () => {
  for (const prose of [
    "password: reset by helpdesk at 09:14",
    "secret: exfiltrated via rclone",
    "token: stolen from the browser profile",
    "password: reset.",
    "token: revoked, then reissued",
    "Key Vault secret: prod-sql-conn accessed by the app",
    "password: <redacted> in the ticket",
    "password: (blank) on the service account",
  ]) {
    expect(redactText(prose)).toBe(prose);
  }
});

test("quoted and JSON values are config syntax and always redacted", () => {
  // Built at runtime: a weak, all-lowercase password is the common real case.
  const weak = ["change", "me"].join("");
  for (const [input, out] of [
    [
      `{"user":"alice","password":"${weak}"}`,
      `{"user":"alice","password":"[REDACTED:secret-value]"}`,
    ],
    [`password: '${weak}'`, "password: '[REDACTED:secret-value]'"],
    [`"secret": "${weak}"`, '"secret": "[REDACTED:secret-value]"'],
    [`DB_PASSWORD: ${weak}`, "DB_PASSWORD: [REDACTED:secret-value]"],
    [`api_key: ${"abcdefghijklmnop"}`, "api_key: [REDACTED:secret-value]"],
  ]) {
    expect(redactText(input as string)).toBe(out as string);
  }
});

test("a Basic credential at the end of a sentence, or unpadded, is still caught", () => {
  const unpadded = BASIC.replace(/=+$/, "");
  expect(redactText(`Authorization: Basic ${BASIC}.`)).toBe(
    "Authorization: Basic [REDACTED:auth-header].",
  );
  expect(redactText(`Basic ${btoa("admin:hunter22").replace(/=+$/, "")}`)).toBe(
    "Basic [REDACTED:auth-header]",
  );
  expect(redactText(`Basic ${unpadded}`)).toBe("Basic [REDACTED:auth-header]");
});

test("Set-Cookie attributes are evidence; only the cookie value goes", () => {
  expect(redactText(`Set-Cookie: sid=${VALUE}; Domain=.contoso.com; Path=/; HttpOnly`)).toBe(
    "Set-Cookie: sid=[REDACTED:cookie]; Domain=.contoso.com; Path=/; HttpOnly",
  );
});

test("a long mixed-case Bearer token with no digit is still a token", () => {
  expect(redactText(`Bearer ${"abcdEFGH".repeat(4)}`)).toBe("Bearer [REDACTED:auth-header]");
});

test("the evidence around a secret is kept", () => {
  const evidence =
    "victim@contoso.com signed in from 203.0.113.7 on WS-FIN-04; key AKIAIOSFODNN7EXAMPLE used; bearer token was stolen";
  expect(redactText(evidence)).toBe(evidence);
});

test("redaction is idempotent", () => {
  for (const [, secret] of SECRETS) {
    const once = redactText(`a ${secret} b`);
    expect(redactText(once)).toBe(once);
  }
  for (const s of [
    `Authorization: Bearer ${OPAQUE}`,
    `Authorization: Basic ${BASIC}`,
    `Cookie: a=${VALUE}; b=${VALUE}`,
    "https://u:p4ssw0rd@h/x",
    `DB_PASSWORD = ${VALUE}`,
    `X-API-Key: ${VALUE}`,
  ]) {
    const once = redactText(s);
    expect(once).toContain("[REDACTED:");
    expect(redactText(once)).toBe(once);
  }
});

test("args are redacted at every depth, keys included", () => {
  const jwt = SECRETS[0]?.[1] as string;
  const token = SECRETS[1]?.[1] as string;
  expect(
    redactArgs({ decision: jwt, nested: { list: [jwt, 3, null] }, [token]: "x", n: 1 }),
  ).toEqual({
    decision: "[REDACTED:jwt]",
    nested: { list: ["[REDACTED:jwt]", 3, null] },
    "[REDACTED:github-token]": "x",
    n: 1,
  });
});

test("the worst-case inputs for the scanning rules stay linear", () => {
  for (const hostile of ["-eyJ".repeat(8192), "a.".repeat(16384), "a-".repeat(16384)]) {
    const started = performance.now();
    redactText(hostile);
    expect(performance.now() - started).toBeLessThan(50);
  }
});

test("a quoted value is redacted whole, spaces and separators included", () => {
  const phrase = ["correct", "horse", "battery", "staple"].join(" ");
  const amp = ["p", "ssw0rd9"].join("&");
  for (const [input, out] of [
    [`"password": "${phrase}"`, '"password": "[REDACTED:secret-value]"'],
    [`{"password":"${amp}"}`, '{"password":"[REDACTED:secret-value]"}'],
    [`"api_key":"abc,defg1234"`, '"api_key":"[REDACTED:secret-value]"'],
    [`Password='Pa ss w0rd'`, "Password='[REDACTED:secret-value]'"],
  ]) {
    const once = redactText(input as string);
    expect(once).toBe(out as string);
    expect(redactText(once)).toBe(once);
  }
});

test("hostnames and package names that start with sk- are kept", () => {
  for (const prose of [
    "host sk-prod-web-server-01-euwest01 down",
    "sk-learn-preprocessing-pipeline-v2 installed",
  ]) {
    expect(redactText(prose)).toBe(prose);
  }
  expect(redactText(`sk-${"A1b2C3d4".repeat(6)}`)).toBe("[REDACTED:api-key]");
});

test("sk- keys with a short hyphenated prefix, or a trailing hyphen, are still keys", () => {
  // Built at runtime so no credential-shaped literal sits in the source.
  const body = "a1B2c3D4e5".repeat(5);
  for (const key of [`sk-or-v1-${body}`, `sk-admin-${body}`, `sk-None-${body}`, `sk-${body}-x`]) {
    expect(redactText(`key ${key} leaked`), key).toBe("key [REDACTED:api-key] leaked");
  }
  const hostile = "sk-".repeat(12000);
  const started = performance.now();
  redactText(hostile);
  expect(performance.now() - started).toBeLessThan(50);
});

test("escaped JSON, CLI flags and a UPN username still lose their secret", () => {
  const phrase = ["correct", "horse"].join(" ");
  const pw = ["hunter", "22"].join("");
  for (const [input, out] of [
    [`{\\"password\\":\\"${phrase}\\"}`, '{\\"password\\":\\"[REDACTED:secret-value]\\"}'],
    [`mysql --password ${pw} -h db`, "mysql --password [REDACTED:secret-value] -h db"],
    [`tool --token "${phrase}" run`, "tool --token [REDACTED:secret-value] run"],
    [`ftp://alice@corp.com:${pw}@ftp.corp.com/`, "ftp://[REDACTED:url-credentials]@ftp.corp.com/"],
  ]) {
    const once = redactText(input as string);
    expect(once).toBe(out as string);
    expect(redactText(once)).toBe(once);
  }
  for (const kept of ["ssh://bob@host:22", "run with --token-file ./t and --password-stdin"]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("URL passwords keep '#', '?' and brackets; compound and unclosed flags are caught", () => {
  const pw = ["hunter", "22"].join("");
  const phrase = ["correct", "horse"].join(" ");
  for (const [input, out] of [
    [`mongodb://admin:Pa#${pw}@db.internal`, "mongodb://[REDACTED:url-credentials]@db.internal"],
    [`https://svc:Pa?${pw}@db.internal`, "https://[REDACTED:url-credentials]@db.internal"],
    [`amqp://guest:gu[est]${pw}@mq:5672/`, "amqp://[REDACTED:url-credentials]@mq:5672/"],
    [`az login --client-secret ${pw}`, "az login --client-secret [REDACTED:secret-value]"],
    [
      `az vm create --admin-password ${pw}`,
      "az vm create --admin-password [REDACTED:secret-value]",
    ],
    [`tool --password "${pw} x`, "tool --password [REDACTED:secret-value] x"],
    [`password="${phrase}"x`, 'password="[REDACTED:secret-value]"x'],
    [
      `{\\"password\\":\\"a\\\\\\"b ${phrase}\\"}`,
      '{\\"password\\":\\"[REDACTED:secret-value]\\"}',
    ],
  ]) {
    const once = redactText(input as string);
    expect(once, input).toBe(out as string);
    expect(redactText(once)).toBe(once);
  }
  for (const kept of [
    "a --password reset link was sent",
    "the attacker used the --password flag",
    "see the --token option in the docs",
  ]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("prose in parentheses and apostrophes after a secret name are kept", () => {
  for (const prose of [
    "(token: expired?)",
    "(the password: reset!)",
    "the token: 'it's gone' per the user",
  ]) {
    expect(redactText(prose)).toBe(prose);
  }
});

test("URL credentials are redacted inside JSON, and a port or a later '@' is not credentials", () => {
  expect(redactText('"url":"https://svc:hunter22@db.internal"')).toBe(
    '"url":"https://[REDACTED:url-credentials]@db.internal"',
  );
  const pad = "x".repeat(210);
  expect(
    redactText(
      `{"dsn":"postgres://u:hunter22@db.internal","note":"${pad}","owner":"bob@corp.com"}`,
    ),
  ).toBe(
    `{"dsn":"postgres://[REDACTED:url-credentials]@db.internal","note":"${pad}","owner":"bob@corp.com"}`,
  );
  for (const url of [
    "https://login.microsoftonline.com:443/common/oauth2/authorize?login_hint=alice@corp.com",
    "hxxps://evil.com:443/owa/auth.owa?u=alice@corp.com",
    "https://registry.npmjs.org:443/@babel/core",
    "http://10.1.1.1:8080/x@y",
    "https://host:8443/@x",
    '{"url":"https://app.contoso.com:8443/x","upn":"alice@contoso.com"}',
    '{"url":"https://app.contoso.com:8443","upn":"alice@contoso.com"}',
  ]) {
    expect(redactText(url)).toBe(url);
  }
});

test("placeholders are judged after punctuation, and only letters count", () => {
  expect(redactText("password: (blank).")).toBe("password: (blank).");
  expect(redactText(`password: <${"Spr1ng"}!>`)).toBe("password: [REDACTED:secret-value]");
});

test("*_KEY names and PGP private key blocks are caught", () => {
  for (const name of ["SECRET_KEY", "Ocp-Apim-Subscription-Key"]) {
    expect(redactText(`${name}=${VALUE}`), name).toBe(`${name}=[REDACTED:secret-value]`);
  }
  expect(
    redactText(
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----",
    ),
  ).toBe("[REDACTED:private-key]");
});

test("sk- keys with '-' or '_' anywhere in a random body are keys; lowercase names are not", () => {
  // Built at runtime so no credential-shaped literal sits in the source.
  const body = ["Rb_PE", "1oi4G", "qulHFbM2N2Wu8yJ"].join("-").repeat(3);
  const hex = "0123456789abcdef".repeat(4);
  for (const key of [`sk-${body}`, `sk-admin-${body}`, `sk-or-v1-${hex}`, `sk-a-b-c-d-${body}`]) {
    expect(redactText(`key ${key} leaked`), key).toBe("key [REDACTED:api-key] leaked");
  }
});

test("flags: key-named flags are caught; masks and bare --key are kept", () => {
  const pw = ["Wint3r", "x9"].join("");
  for (const flag of ["--account-key", "--secret-key", "--secret-access-key", "--api_key"]) {
    expect(redactText(`az ${flag} ${pw} x`), flag).toBe(`az ${flag} [REDACTED:secret-value] x`);
  }
  expect(redactText("--api-key abcdefghijklmnopqrst")).toBe("--api-key [REDACTED:secret-value]");
  for (const kept of [
    "set --password ******** for svc",
    "openssl --key ./client.pem",
    "aws dynamodb query --partition-key Tenant2024 --sort-key CreatedAt2024",
    "ssh-keygen --ssh-key id_ed25519",
  ]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("placeholders with '/' or '.' are kept; a digit makes a bracketed word a password", () => {
  for (const prose of ["password: (n/a)", "token: <user.name>"]) {
    expect(redactText(prose)).toBe(prose);
  }
  for (const pw of ["(Summer2024)", "<Welcome1>", "[Winter2025]"]) {
    expect(redactText(`password: ${pw}`), pw).toBe("password: [REDACTED:secret-value]");
  }
});

test("URL credentials: empty usernames and '<>' are caught; IPv6 and '&' after a port are kept", () => {
  const pw = ["S3cret", "Pass99"].join("");
  for (const [input, out] of [
    [
      `redis://:${pw}@redis.corp.local:6379/0`,
      "redis://[REDACTED:url-credentials]@redis.corp.local:6379/0",
    ],
    [`http://u:p4ss>${pw}@host`, "http://[REDACTED:url-credentials]@host"],
  ]) {
    expect(redactText(input as string)).toBe(out as string);
  }
  for (const kept of ["http://[fe80::1]:8080?upn=alice@corp.com"]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("an escaped-JSON value ending in a backslash keeps the next field intact", () => {
  expect(redactText('{\\"password\\":\\"abc\\\\\\\\\\",\\"upn\\":\\"alice@corp.com\\"}')).toBe(
    '{\\"password\\":\\"[REDACTED:secret-value]\\",\\"upn\\":\\"alice@corp.com\\"}',
  );
});

test("a value under a secret-named key is replaced whole; the key stays", () => {
  expect(
    redactArgs({
      decision: "x",
      password: "Spr1ng2024!",
      outcomes: { api_key: "Wint3r!x" },
      pin: 1234,
    }),
  ).toEqual({
    decision: "x",
    password: "[REDACTED:secret-value]",
    outcomes: { api_key: "[REDACTED:secret-value]" },
    pin: 1234,
  });
});

test("a truncated escaped-JSON value full of backslashes stays linear and later secrets go", () => {
  const pw = ["Zq9", "synthetic"].join("");
  for (const n of [56, 2000]) {
    const input = `{\\"password\\":\\"${"\\".repeat(n)}\n{\\"password\\":\\"${pw}\\"}`;
    const started = performance.now();
    const out = redactText(input);
    expect(performance.now() - started).toBeLessThan(50);
    expect(out).not.toContain(pw);
  }
});

test("flag values: base64 padding and look-alike references are secrets", () => {
  const b64 = `${"QWxhZGRpbjpvcGVu".repeat(2)}c2VzYW1l=`;
  for (const value of [b64, `/${b64}`, "Hunter2synth=", "$ecr3tSynth", ["$", "{P}x"].join("")]) {
    expect(redactText(`--client-secret ${value} run`), value).toBe(
      "--client-secret [REDACTED:secret-value] run",
    );
  }
});

test("ambiguous strings are redacted: lost evidence, never a kept secret", () => {
  // Each of these reads exactly like a credential shape that leaked when it was kept.
  for (const [input, out] of [
    [
      "http://evil.example:8080?login_hint=alice@corp.com",
      "http://[REDACTED:url-credentials]@corp.com",
    ],
    ["ssh://bob@host:22,carol@corp.com", "ssh://[REDACTED:url-credentials]@corp.com"],
    ["mysql --password $DB_PASS -h db", "mysql --password [REDACTED:secret-value] -h db"],
    [
      "kubectl --token /var/run/secrets/kubernetes.io/serviceaccount/token get pods",
      "kubectl --token [REDACTED:secret-value] get pods",
    ],
    ["sk-build-agent-ubuntu2204x64runner01.corp", "[REDACTED:api-key].corp"],
  ]) {
    expect(redactText(input as string), input).toBe(out as string);
  }
});

test("passwords that begin with digits, lowercase sk- keys and '/'-base64 flags are secrets", () => {
  const b64 = "9j4Kd8Qw2LmN7pXa".repeat(3);
  for (const [input, out] of [
    ["postgres://bob:2024&Secret@db.corp", "postgres://[REDACTED:url-credentials]@db.corp"],
    ["postgres://bob:2024#Spring@db.corp", "postgres://[REDACTED:url-credentials]@db.corp"],
    ["postgres://bob:1999*Rocks@db.corp", "postgres://[REDACTED:url-credentials]@db.corp"],
    [`key sk-${"a8f3kq2mzt9wrx7vlp4nb6yc1hd5gs0jeiuo"} x`, "key [REDACTED:api-key] x"],
    [`--token /${b64} run`, "--token [REDACTED:secret-value] run"],
    ["--password $HUNTER2 run", "--password [REDACTED:secret-value] run"],
  ]) {
    expect(redactText(input as string), input).toBe(out as string);
  }
  for (const kept of [
    "host sk-prod-web-server-01-euwest01 down",
    "sk-learn-preprocessing-pipeline-v2",
  ]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("redaction reaches a fixed point when one rule's tag unblocks another", () => {
  for (const input of ["https://u:password=a/bc;@host", "https://u:api_key=ab/cd&@host"]) {
    const once = redactText(input);
    expect(redactText(once), input).toBe(once);
    expect(once).not.toContain("bc;");
  }
});

test("every --…-key flag is a secret except the evidence ones", () => {
  const pw = ["Xy9Qw8", "Er7Ty6"].join("");
  for (const flag of [
    "--primary-key",
    "--shared-key",
    "--sas-key",
    "--license-key",
    "--host-key",
  ]) {
    expect(redactText(`cmd ${flag} ${pw} x`), flag).toBe(`cmd ${flag} [REDACTED:secret-value] x`);
  }
});

test("sk- tokens made of hex segments are keys", () => {
  const uuid = ["1f0e2d3c", "4b5a", "6978", "8a9b", "0c1d2e3f4a5b"].join("-");
  expect(redactText(`key sk-lf-${uuid} x`)).toBe("key [REDACTED:api-key] x");
});

test("input nested past the pass limit is replaced whole, and stays replaced", () => {
  const crafted = `password='Zq& 9x!${"pwd:pwd:'".repeat(8)}apikey='o'`;
  const once = redactText(crafted);
  expect(once).not.toContain("Zq&");
  expect(redactText(once)).toBe(once);
  const started = performance.now();
  redactText(`token='"${"token='a ".repeat(4000)}token='i'`);
  expect(performance.now() - started).toBeLessThan(500);
});

test("--…-key flags with '=' or long names, and _KEY names, lose their value", () => {
  const v = ["Zq8x7Rk2", "Lm9Pw4Tn6Yb3Vc5="].join("");
  for (const [input, out] of [
    [`--primary-key=${v} x`, "--primary-key=[REDACTED:secret-value] x"],
    [`--sas-key = ${v} x`, "--sas-key = [REDACTED:secret-value] x"],
    [
      `--destination-storage-account-access-key ${v} x`,
      "--destination-storage-account-access-key [REDACTED:secret-value] x",
    ],
    [`--password=reset x`, "--password=[REDACTED:secret-value] x"],
    [`--passphrase ${v} x`, "--passphrase [REDACTED:secret-value] x"],
    [`AZURE_STORAGE_KEY=${v}`, "AZURE_STORAGE_KEY=[REDACTED:secret-value]"],
    [`"primaryKey":"${v}"`, '"primaryKey":"[REDACTED:secret-value]"'],
  ]) {
    const once = redactText(input as string);
    expect(once, input).toBe(out as string);
    expect(redactText(once)).toBe(once);
  }
  for (const kept of [
    "reg add --run-key HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "aws s3api get-object --object-key logs/2024/a.gz",
    "--sort-key=CreatedAt2024",
  ]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("after '=' a value starting with '-' is a secret; after a space it is the next flag", () => {
  const v = ["-Zm9vYmFy", "_cXV4LWJh"].join("");
  for (const input of [`--sas-key=${v} x`, `--sas-key = ${v} x`]) {
    expect(redactText(input), input).not.toContain(v);
  }
  for (const kept of ["--api-key --verbose", "--hmac-key --dry-run", "--password --help"]) {
    expect(redactText(kept)).toBe(kept);
  }
  const started = performance.now();
  redactText(`--k-key${" ".repeat(64000)}-x`);
  expect(performance.now() - started).toBeLessThan(50);
});

test("an empty '=' value never swallows the next flag's secret", () => {
  const v = ["Zm9vYmFy", "QmF6UXV4MTIz"].join("");
  const pw = ["Hunter2", "Synthetic"].join("");
  for (const input of [
    `--sas-token= --account-key ${v}`,
    `--client-secret= --password ${pw}`,
    `--api-key = --account-key ${v}`,
    `--sas-key=\t--primary-key ${v}`,
    `--extra-key=--password ${pw}`,
    `--client-secret=  --sas-token = -${v}`,
    `--account-key = --primary-key='-${v}  --primary-key='-${pw}`,
    `--token="-${v};--password\t"${pw};--password = ${pw}`,
    `--api-key '-${v} --sas-key '${pw}`,
  ]) {
    const out = redactText(input);
    expect(out, input).not.toContain(v);
    expect(out, input).not.toContain(pw);
    expect(redactText(out)).toBe(out);
  }
});

test("credentials past the old rule edges are redacted, and their evidence kept", () => {
  const pw = "Zq8".repeat(4);
  const cases: [input: string, secret: string, keep?: string][] = [
    [`found DB_PASSWORD=Pa;${pw} in web.config`, pw, "web.config"],
    [`password=p&${pw}`, pw],
    [`password=Summer,${pw}`, pw],
    ["password=a1!", "a1!"],
    [`postgres://admin:Ab/${pw}@db.corp.local:5432/app`, pw, "db.corp.local"],
    [`mongodb://admin:P@${pw}@db.corp.local`, pw, "db.corp.local"],
    [`Authorization: Basic ${btoa("root:toor")}`, btoa("root:toor")],
    [`Basic Bearer ${OPAQUE}`, OPAQUE],
    [`{\\\\\\"password\\\\\\":\\\\\\"${pw} x\\\\\\"}`, pw],
    [`{"name": "Cookie", "value": "ESTSAUTH=0.${pw}"}`, pw, "ESTSAUTH"],
    [`"cookies": [{"name": "ESTSAUTHPERSISTENT", "value": "0.${pw}"}]`, pw, "ESTSAUTHPERSISTENT"],
    [`curl -b 'ESTSAUTH=0.${pw}' https://x`, pw, "ESTSAUTH"],
    [`curl --cookie 'session=${pw}' https://x`, pw, "session"],
    [`DB_PASS=${pw}`, pw],
    [`tool --pass ${pw}`, pw],
    [`mysql -u root -p${pw} -h db`, pw, "root"],
    [`Authorization: NTLM ${OPAQUE}`, OPAQUE, "NTLM"],
    [`Authorization: SSWS ${OPAQUE}`, OPAQUE, "SSWS"],
    [`<password>${pw}</password>`, pw],
    [`<Password>\n  <Value>${btoa(pw)}</Value>\n</Password>`, btoa(pw)],
    [`SAMLResponse=${btoa(pw)}`, btoa(pw)],
    [`glpat-${OPAQUE}`, OPAQUE],
    [`ya29.${OPAQUE}`, OPAQUE],
    [`pypi-AgE${OPAQUE}`, OPAQUE],
  ];
  for (const [input, secret, keep] of cases) {
    const out = redactText(input);
    expect(out, input).not.toContain(secret);
    if (keep) expect(out, input).toContain(keep);
    expect(redactText(out)).toBe(out);
  }
  for (const args of [
    { password: [pw] },
    { token: { v: pw } },
    { pass: pw },
    { cookie: `a=${pw}` },
  ]) {
    expect(JSON.stringify(redactArgs(args))).not.toContain(pw);
  }
});

test("ports, prose and file arguments around the new rules are kept", () => {
  for (const kept of [
    "https://login.microsoftonline.com:443/common/oauth2/authorize?login_hint=alice@corp.com",
    "https://user@host/path?email=a@b.com",
    "the bypass: enabled on the gateway",
    "tests pass: all green",
    "curl -b cookies.txt https://x",
    "grep -b file.txt",
    "the token: 'it's gone' per the user",
  ]) {
    expect(redactText(kept)).toBe(kept);
  }
});

test("long values, a following pair, and the round-2 forms are redacted whole", () => {
  const pw = "Zq8".repeat(4);
  const long = "Ab1x".repeat(375);
  const cases: [input: string, secret: string, keep?: string][] = [
    [`token=${long}`, long.slice(-40)],
    [`X-Amz-Security-Token=${long}&X-Amz-Signature=abc`, long.slice(-40)],
    [`secret: ${long}`, long.slice(-40)],
    [`postgres://u:${long}@h`, long.slice(-40), "@h"],
    [`SAMLResponse=${long}`, long.slice(-40)],
    [`<password>${long}</password>`, long.slice(-40)],
    [`password=abc&token: ${pw}`, pw],
    [`password=abc&token = ${pw}`, pw],
    [`DB_PASSWORD=abc,API_KEY: ${pw}`, pw],
    [`user=bob&password=abc&client_secret :${pw}`, pw],
    [`mongodb://admin:P@${pw}/1@x@db.corp/app`, pw, "db.corp"],
    [`{"cookie": "SESSID=${pw}"}`, pw, "SESSID"],
    [`"cookies": [{"name": "A", "value": "x]y ${pw}"}]`, pw],
    [`mysql -u root -p'two ${pw}' -h db`, pw],
    [`mariadb -u root -p${pw}`, pw],
    [`"Authorization": "SSWS ${OPAQUE}"`, OPAQUE, "SSWS"],
    [`{"name":"Authorization","value":"NTLM ${OPAQUE}"}`, OPAQUE, "NTLM"],
    [`<wsse:Password>${pw}</wsse:Password>`, pw],
    [`<password><![CDATA[${pw}]]></password>`, pw],
    [`Bearer Basic.${OPAQUE}`, OPAQUE],
  ];
  for (const [input, secret, keep] of cases) {
    const out = redactText(input);
    expect(out, input).not.toContain(secret);
    if (keep) expect(out, input).toContain(keep);
    expect(redactText(out)).toBe(out);
  }
  expect(JSON.stringify(redactArgs({ Authorization: `NTLM ${OPAQUE}` }))).not.toContain(OPAQUE);
});

test("an unclosed or repeated HAR cookies array stays linear", () => {
  const start = performance.now();
  redactText('"cookies":['.repeat(20_000));
  expect(performance.now() - start).toBeLessThan(500);
});

test("any horizontal whitespace separates, and => := quotes and CDATA are covered", () => {
  const pw = "Zq8".repeat(4);
  const cases: [input: string, secret: string, keep?: string][] = [];
  for (const ws of [" ", " ", "　", "\v", "\f", "\r"]) {
    cases.push(
      [`password=${ws}${pw}`, pw],
      [`password${ws}=${ws}${pw}`, pw],
      [`"password":${ws}"${pw}"`, pw],
      [`Authorization:${ws}NTLM ${OPAQUE}`, OPAQUE],
      [`Cookie:${ws}sid=${pw}`, pw, "sid"],
      [`mysql -u root${ws}-p${pw}`, pw],
      [`--password${ws}${pw}`, pw],
    );
  }
  cases.push(
    [`{"password"=>"${pw}"}`, pw],
    [`password => ${pw}`, pw],
    [`password := ${pw}`, pw],
    ["Authorization: Bearer 7f3a9c2e1b4d", "7f3a9c2e1b4d", "Bearer"],
    [`Authorization: lin_api_${OPAQUE}`, OPAQUE],
    [`{"Authorization": "${OPAQUE}"}`, OPAQUE],
    [`{'Authorization': 'Token ${OPAQUE}'}`, OPAQUE, "Token"],
    [`{\\"Authorization\\": \\"Token ${OPAQUE}\\"}`, OPAQUE, "Token"],
    [`{'Cookie': 'sid=${pw}'}`, pw, "sid"],
    [`{\\"cookie\\": \\"sid=${pw}\\"}`, pw, "sid"],
    [`<Password><![CDATA[a<${pw}]]></Password>`, pw],
    [`Cookie: domain=${pw}`, pw],
    [`curl -b 'Path=${pw}'`, pw],
    [`DB_PASSWORD=Ab1'${pw}`, pw],
    [`xoxe-1-${OPAQUE}`, OPAQUE],
  );
  for (const [input, secret, keep] of cases) {
    const out = redactText(input);
    expect(out, JSON.stringify(input)).not.toContain(secret);
    if (keep) expect(out, input).toContain(keep);
    expect(redactText(out)).toBe(out);
  }
  // Set-Cookie attributes stay evidence; only request cookies lose the exemption.
  expect(redactText(`Set-Cookie: sid=${pw}; Domain=corp.example; Path=/`)).toBe(
    "Set-Cookie: sid=[REDACTED:cookie]; Domain=corp.example; Path=/",
  );
});

test("an escaped quote inside a cookie string, and a quoted Authorization value, do not end redaction", () => {
  const pw = "Zq8".repeat(4);
  for (const [input, secret, keep] of [
    [`{"cookie": "a=\\"x\\"; sid=${pw}"}`, pw, "sid"],
    [`{"name":"Cookie","value":"lang=\\"en\\"; JSESSIONID=${pw}"}`, pw, "JSESSIONID"],
    [`{"Set-Cookie": "sid=\\"${pw}\\"; Path=/"}`, pw, "Path=/"],
    [`Authorization: "Token ${OPAQUE}"`, OPAQUE, "Token"],
    [`Authorization: '${OPAQUE}'`, OPAQUE],
  ] as [string, string, string?][]) {
    const out = redactText(input);
    expect(out, input).not.toContain(secret);
    if (keep) expect(out, input).toContain(keep);
    expect(redactText(out)).toBe(out);
  }
});

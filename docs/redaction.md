# Credential redaction

Before a tool call is appended to `provenance.jsonl`, credentials in its
arguments and errors are replaced with `[REDACTED:<kind>]`. The rules live in
`src/redact.ts`; the tests in `test/redact.test.ts`. What is redacted:

- `Authorization` headers of any scheme (Bearer, Basic, NTLM, Negotiate, SSWS,
  `token`), as a header line or as JSON / HAR;
- cookie values in `Cookie:` / `Set-Cookie:` headers, curl `-b` / `--cookie`,
  HAR cookie objects and arrays, and JSON `"cookie"` keys;
- JWTs, PEM and PGP private keys, and SAML responses;
- GitHub, GitLab, npm, PyPI, Slack, Stripe, Google (API keys and `ya29.`
  OAuth tokens) and `sk-` keys (OpenAI, Anthropic, OpenRouter, Langfuse and
  other random-bodied keys);
- `user:pass@` in URLs, including an empty or UPN username and passwords
  containing `/` or `@`;
- `password=` / `"secret": "…"` style values (also `pass`, `credentials`),
  quoted, unquoted, or escaped once or more inside a JSON log line;
- XML elements named for a secret, namespaced or in CDATA, including
  unattend.xml's `<Password><Value>`;
- command-line flags: `--password`, `--pass`, `--token`, `--secret`,
  `--passphrase` and every `--…-key` except evidence keys such as `--sort-key`,
  `--partition-key`, `--ssh-key` and `--run-key`, after a space or `=`; and
  the mysql / mariadb `-p<password>` form;
- the value of any argument whose key names a secret (`{password: "…"}`,
  `{cookie: …}`, `{Authorization: …}`), whatever its shape.

**Known limits.** Redaction recognises credentials by a name, header, prefix or
syntax in front of them. It does not catch:
- positional credentials with nothing naming them (`net user bob P@ss /add`,
  `ConvertTo-SecureString 'P@ss' -AsPlainText`, netrc's
  `machine h login bob password P@ss`, `bob:P@ss@host` with no scheme);
- client flags outside mysql / mariadb `-p`: `curl -u` / `--user`,
  `curl --oauth2-bearer`, `sshpass -p`, `redis-cli -a`, and a mysql `-p` value
  that itself starts with `-`;
- name / value pairs where the name is a separate field: XML attributes
  (`<add key="DbPassword" value="…"/>`), Kubernetes `- name: DB_PASSWORD` /
  `value: …`, HAR `params` and non-cookie headers, CloudFormation
  `ParameterKey` / `ParameterValue`;
- layouts the rules do not read: a YAML value on the line after its key, a tab
  as the only separator (`password<TAB>…`), a full-width colon, an ODBC
  brace-quoted value with spaces (`PWD={correct horse; battery}`);
- header names ending in `-key` that are not secret names
  (`x-functions-key: …`), a Digest `response=` hash, and `authorization=` as a
  query or config pair;
- token formats without a rule: Stripe `whsec_`, Slack `xapp-`, PuTTY private
  key files, and an unsigned JWT (empty signature);
- a URL password that starts with up to five digits and then `/`, which reads
  as a port and path (`host:443/…`) and is kept as evidence, or that contains
  a `"`;
- a bare prose name before a lowercase word (`password: correcthorse`), kept
  because it reads as prose.

Evidence text sent to the embedding host (`IRNAV_EMBED_URL`) is not redacted;
keep that host local.

Emails, UPNs, IPs, hostnames, ports, AKIA key ids and cookie names are
evidence and are kept, and so is prose ("password: reset by helpdesk").
Ambiguous strings are redacted rather than kept, because every exemption tried
leaked real secrets. So a reference to where a secret lives (`$DB_PASS`, a
file path or ARN after a flag), `host:8080?login_hint=…` with no path after
the port, and a bracketed word with a digit after a secret name
(`password: (Summer2024)`) are logged as
`[REDACTED:…]`. Input nested so deeply that eight passes do not settle is
replaced whole with `[REDACTED:unstable-input]`.

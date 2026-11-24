import { constants } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { redactArgs, redactText } from "./redact.ts";
import { closing, isAbsent, openRegular, readBounded, writeAll } from "./regular-file.ts";
import { ShownError, show } from "./shown.ts";

/**
 * 2: args are redacted before the write; failed calls are logged with `error`.
 * Rows without schema_version are version 1 (raw args, successful calls only).
 */
const PROVENANCE_SCHEMA_VERSION = 2;

export type ProvenanceEntry = {
  ts: string;
  tool: string;
  args: Record<string, unknown>;
  surfaced: Record<string, unknown>;
  /** Set when the call was refused: a client probing with unknown ids is a signal worth keeping. */
  error?: string;
};

const LOG = join(import.meta.dir, "..", "provenance.jsonl");

/**
 * The most of the log `review --stale` will read: 64 MiB, some tens of
 * thousands of rows. Past that the reader refuses rather than load a planted
 * file whole; the real log is rotated by hand.
 */
export const PROVENANCE_MAX_BYTES = 64 << 20;

const WHAT = "provenance log";

/**
 * Path is the caller's: tests must never append fake deliveries to the real
 * log. The log sits in the repo root, where any process with the checkout can
 * plant a file, so it is opened like an inbox file: a symlink at the path is
 * not followed (a row must not land in a file the link chose), a hard link is
 * refused, a FIFO cannot hang the server, and a directory or device is
 * refused. Everything after the open — the mode, the row — goes through the
 * checked handle, so nothing here follows a link swapped in later.
 */
export async function appendProvenance(path: string, entry: ProvenanceEntry): Promise<void> {
  // The tool name and errors echo caller text (an unknown tool, playbook or id), so they are redacted too.
  const row = {
    schema_version: PROVENANCE_SCHEMA_VERSION,
    ...entry,
    tool: redactText(entry.tool),
    args: redactArgs(entry.args),
    ...(entry.error === undefined ? {} : { error: redactText(entry.error) }),
  };
  const fh = await openRegular(
    path,
    WHAT,
    constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT,
    0o600,
  );
  await closing(fh, WHAT, async () => {
    // mode only applies on creation; a log created before this kept 0644. Decision text
    // names hosts and users from real incidents, so the mode is tightened before the row is
    // written, on the handle. A chmod refusal happens only on a log another owner created or
    // a filesystem without modes; the row is still written, because stopping every delivery
    // until someone fixes the mode would cost more than one more row in a file that is
    // already readable. The refusal is reported so that someone does.
    await fh.chmod(0o600).catch((e: NodeJS.ErrnoException) => {
      process.stderr.write(
        `[ir-navigator] cannot restrict ${show(path)} to 0600 (${e.code ?? e.message}) — chmod it by hand\n`,
      );
    });
    await writeAll(fh, Buffer.from(`${JSON.stringify(row)}\n`), WHAT);
  });
}

/**
 * The log as text for `review --stale`, through the same checked handle the
 * append uses, cut at the cap. A log that does not exist is null, so the
 * caller can say so rather than report every criterion as never surfaced.
 * One that is a symlink, a FIFO, a directory or over the cap is refused with
 * the reason.
 */
export async function readProvenance(
  path: string,
  cap: number = PROVENANCE_MAX_BYTES,
): Promise<string | null> {
  let fh: FileHandle;
  try {
    fh = await openRegular(path, WHAT, constants.O_RDONLY);
  } catch (e) {
    // ENOENT covers a missing parent directory too: no log either way.
    if (isAbsent(e)) return null;
    throw e;
  }
  return closing(fh, WHAT, async () => {
    const bytes = await readBounded(fh, cap);
    if (bytes === null) {
      throw new ShownError(
        `${WHAT} is over the ${Math.floor(cap / 2 ** 20)} MiB cap (${cap} bytes) and was not read — rotate it, then run --stale again: ${show(path)}`,
      );
    }
    return bytes.toString("utf8");
  });
}

export function provenancePath(): string {
  return LOG;
}

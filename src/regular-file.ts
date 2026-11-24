import { constants, type Stats } from "node:fs";
import { type FileHandle, open } from "node:fs/promises";
import { ShownError, show } from "./shown.ts";

/**
 * Open a path as a regular file, or throw. The one open pattern for every
 * file this server reads or appends that another process could have planted:
 * inbox drafts, the rejection record, the provenance log. O_NOFOLLOW: a
 * symlink in the final component fails the open (ELOOP) however recently it
 * was swapped in, so no earlier check can be raced. O_NONBLOCK: a FIFO cannot
 * hang the open. The handle is fstat'd before it is returned, so a directory
 * or device is refused too. `what` names the file in messages ("draft", the
 * record, the log). The error keeps the open's errno as its cause, so a caller
 * can tell an absent file from a refused one.
 */
export async function openRegular(
  path: string,
  what: string,
  flags: number,
  mode?: number,
): Promise<FileHandle> {
  // A platform without these flags (win32 defines neither) would OR in 0 and follow symlinks
  // silently. Refuse rather than open unguarded.
  if (typeof constants.O_NOFOLLOW !== "number" || typeof constants.O_NONBLOCK !== "number") {
    throw new ShownError(`this platform defines no O_NOFOLLOW / O_NONBLOCK; not opening ${what}`);
  }
  const fh = await open(path, flags | constants.O_NOFOLLOW | constants.O_NONBLOCK, mode).catch(
    (e: NodeJS.ErrnoException) => {
      // ELOOP (Linux, macOS) or EMLINK (FreeBSD) is what O_NOFOLLOW returns on a symlink; the
      // code is printed as is, since ELOOP can also mean a loop in an earlier component.
      if (e.code === "ELOOP" || e.code === "EMLINK") {
        throw new ShownError(`${what} is not a regular file (${e.code}): ${show(path)}`, {
          cause: e,
        });
      }
      throw new ShownError(`cannot open ${what} (${e.code ?? "unknown error"}): ${show(path)}`, {
        cause: e,
      });
    },
  );
  let st: Stats;
  try {
    st = await fh.stat();
  } catch (e) {
    // fstat on an open handle fails only for an I/O reason worth showing, not for the file's kind.
    await fh.close().catch(() => {});
    const code = (e as NodeJS.ErrnoException).code ?? "unknown error";
    throw new ShownError(`cannot stat ${what} (${code}): ${show(path)}`, { cause: e });
  }
  if (!st.isFile()) {
    await fh.close().catch(() => {});
    throw new ShownError(`${what} is not a regular file: ${show(path)}`);
  }
  // A file written through here must have one name: O_NOFOLLOW stops a symlink, not a hard
  // link, and link(2) needs no write permission on its target on macOS, so a planted hard link
  // would carry an appended row into a file the planter could not write. The count is read
  // after the open, so a link swapped in and out between the two gets past it: this refuses
  // a planted file, and the directory the file lives in is the trust boundary against a
  // process that can keep swapping.
  const writing = (flags & (constants.O_WRONLY | constants.O_RDWR)) !== 0;
  if (writing && st.nlink !== 1) {
    await fh.close().catch(() => {});
    throw new ShownError(`${what} has ${st.nlink} hard links and was not written: ${show(path)}`);
  }
  return fh;
}

/** True when the error is openRegular's for a path that does not exist. */
export function isAbsent(e: unknown): boolean {
  return (e as { cause?: NodeJS.ErrnoException })?.cause?.code === "ENOENT";
}

/**
 * Run `body` on an open handle, then close it. The body's error is the one
 * thrown: a close that fails after a failed body adds nothing. A close that
 * fails after a good body is reported on stderr, not thrown — what was read
 * is read, what was written is written, and failing the caller would invite
 * a retry into a duplicate row.
 */
export async function closing<T>(fh: FileHandle, what: string, body: () => Promise<T>): Promise<T> {
  let out: T;
  try {
    out = await body();
  } catch (e) {
    await fh.close().catch(() => {});
    throw e;
  }
  await fh.close().catch((e: NodeJS.ErrnoException) => {
    process.stderr.write(`[ir-navigator] ${what}: close failed (${e.code ?? e.message})\n`);
  });
  return out;
}

/** What the bounded read needs of a handle, so a test can pass one that lies about its size and reads short. */
export type Reader = {
  stat(): Promise<{ size: number }>;
  read(
    buffer: Buffer,
    offset: number,
    length: number,
    position: null,
  ): Promise<{ bytesRead: number }>;
};

/** What the whole write needs of a handle, so a test can pass one that writes short. */
export type Writer = {
  write(
    data: Buffer,
    offset: number,
    length: number,
    position: null,
  ): Promise<{ bytesWritten: number }>;
};

/**
 * Read a handle to its end, or to one byte past `cap`, whichever comes first.
 * A file fstat already reports as over the cap is refused unread. Otherwise
 * the buffer starts at the reported size and grows as the read goes on, so a
 * small file costs a small buffer and the cap is still on what is read: a
 * file that grows after the stat is cut here. Returns null when the file is
 * over the cap, so the caller names the file and the limit in its own words.
 */
export async function readBounded(fh: Reader, cap: number): Promise<Buffer | null> {
  const limit = cap + 1;
  const size = (await fh.stat()).size;
  if (size > cap) return null;
  // Unsafe-alloc is fine: only the bytes the read filled are ever looked at.
  let buf = Buffer.allocUnsafe(Math.max(size, 0) + 1);
  let n = 0;
  for (;;) {
    if (n === buf.length) {
      if (n >= limit) return null;
      const bigger = Buffer.allocUnsafe(Math.min(buf.length * 2, limit));
      buf.copy(bigger, 0, 0, n);
      buf = bigger;
    }
    const { bytesRead } = await fh.read(buf, n, buf.length - n, null);
    if (bytesRead === 0) break;
    n += bytesRead;
  }
  return n > cap ? null : buf.subarray(0, n);
}

/**
 * Write the whole buffer to a handle opened O_APPEND, continuing after a
 * short write. One call to write() may stop early (a full disk, a signal) and
 * an unfinished row would make the next row join it on one line.
 */
export async function writeAll(fh: Writer, data: Buffer, what: string): Promise<void> {
  let off = 0;
  while (off < data.length) {
    const { bytesWritten } = await fh.write(data, off, data.length - off, null);
    if (bytesWritten === 0) throw new ShownError(`${what}: write returned no bytes`);
    off += bytesWritten;
  }
}

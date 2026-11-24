import { expect, test } from "bun:test";
import { type Reader, readBounded, type Writer, writeAll } from "../src/regular-file.ts";

/** A handle whose fstat size is a lie and whose reads come in short pieces, so the loop is what is tested. */
function reader(bytes: Buffer, reported: number, piece: number): Reader {
  let pos = 0;
  return {
    stat: async () => ({ size: reported }),
    read: async (buf, offset, length) => {
      const n = Math.min(piece, length, bytes.length - pos);
      bytes.copy(buf, offset, pos, pos + n);
      pos += n;
      return { bytesRead: n };
    },
  };
}

test("readBounded cuts at the cap whatever fstat reported, and grows past a size that was a lie", async () => {
  const data = Buffer.from("abcdefghijklmnopq"); // 17 bytes
  // Reported over the cap: refused without a read.
  expect(await readBounded(reader(data, 17, 1), 16)).toBeNull();
  // Reported 0, grows to exactly the cap: accepted whole, through several doublings.
  const sixteen = data.subarray(0, 16);
  expect((await readBounded(reader(sixteen, 0, 1), 16))?.toString()).toBe("abcdefghijklmnop");
  expect((await readBounded(reader(sixteen, 4, 3), 16))?.toString()).toBe("abcdefghijklmnop");
  // Reported 0, grows to one past the cap: cut and refused.
  expect(await readBounded(reader(data, 0, 1), 16)).toBeNull();
  expect(await readBounded(reader(data, 16, 7), 16)).toBeNull();
  // Reported more than is there: only what was read comes back.
  expect((await readBounded(reader(sixteen, 16, 16), 16))?.toString()).toBe("abcdefghijklmnop");
  expect((await readBounded(reader(Buffer.alloc(0), 0, 1), 16))?.length).toBe(0);
});

test("writeAll continues after a short write and refuses a write that makes no progress", async () => {
  const out: Buffer[] = [];
  const short: Writer = {
    write: async (data, off, len) => {
      const n = Math.min(3, len);
      out.push(Buffer.from(data.subarray(off, off + n)));
      return { bytesWritten: n };
    },
  };
  await writeAll(short, Buffer.from("one row here\n"), "log");
  expect(Buffer.concat(out).toString()).toBe("one row here\n");
  expect(out.length).toBe(5);
  const stuck: Writer = { write: async () => ({ bytesWritten: 0 }) };
  await expect(writeAll(stuck, Buffer.from("x"), "log")).rejects.toThrow(
    /log: write returned no bytes/,
  );
  await writeAll(stuck, Buffer.alloc(0), "log");
});

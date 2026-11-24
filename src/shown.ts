/**
 * Text as the terminal may see it. Draft text is written by an AI client and
 * log rows echo caller text, so neither reaches the terminal raw: show()
 * escapes what could erase, redraw, reorder or hide, and ShownError marks a
 * message that already went through it.
 */

/** An error whose message already passed through show(): the CLI prints it as is, and a tool forwards it. */
export class ShownError extends Error {}

/** A field continues on a line indented this far, where it cannot pose as a new field. */
export const CONTINUATION = "      ";

// Format (bidi overrides, zero-width, BOM), private-use, unassigned and lone surrogates.
// Default_Ignorable adds the variation selectors and fillers, which render as nothing
// and can carry a hidden payload one byte per character.
const HIDDEN = /^[\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Default_Ignorable_Code_Point}]$/u;

/**
 * Draft text as the terminal shows it. A draft is written by an AI client, so
 * its text must not reach the terminal raw: escape sequences could erase or
 * redraw the listing the reviewer approves from. C0/C1 controls, DEL and the
 * Unicode line/paragraph separators are shown as \u{..}, as are format
 * characters (bidi overrides, zero-width) that reorder or hide text. A
 * backslash is doubled so literal "\u{1b}" text cannot pass for an escaped
 * control. A newline continues the field on an indented line so it cannot pose
 * as a new field. Spaces are kept as written — the reviewer must see the query
 * analysts will run — and wrap() keeps padding from posing as a field line.
 */
export function show(value: unknown, doubleBackslash = true, asciiOnly = false): string {
  let out = "";
  for (const ch of String(value)) {
    const n = ch.codePointAt(0) ?? 0;
    if (n === 0x0a) out += `\n${CONTINUATION}`;
    else if (n === 0x5c && doubleBackslash) out += "\\\\";
    else if (
      n < 0x20 ||
      (asciiOnly && n > 0x7e) ||
      (n >= 0x7f && n <= 0x9f) ||
      n === 0x2028 ||
      n === 0x2029 ||
      HIDDEN.test(ch)
    ) {
      out += `\\u{${n.toString(16)}}`;
    } else out += ch;
  }
  return out;
}

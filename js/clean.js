"use strict";
// Cleans text entering Logs and imports: pictographs and outer whitespace only.
// Characters inside commands, paths, URLs, hashes and timestamps are left as they are.
globalThis.SOCClean = (() => {
  // ©, ® and ™ are plain text in product names, not pictographs to drop.
  const BASE = "(?:[\\u{1F1E6}-\\u{1F1FF}]|(?![\\u00A9\\u00AE\\u2122])\\p{Extended_Pictographic})";
  const MODIFIER = "[\\uFE0F\\u20E3\\u{1F3FB}-\\u{1F3FF}\\u{E0020}-\\u{E007F}]";
  const SEQUENCE = BASE + MODIFIER + "*(?:\\u200D" + BASE + MODIFIER + "*)*";
  const present = new RegExp(SEQUENCE + "|[\\uFE0F\\u20E3]", "u");
  const padded = new RegExp("(^|[ \\t])(?:" + SEQUENCE + ")+[ \\t]*", "gu");
  const remaining = new RegExp(SEQUENCE + "|[\\uFE0F\\u20E3]", "gu");
  // A removed pictograph takes its own padding with it; indentation and inner spacing stay.
  const line = text => present.test(text) ? text.replace(padded, "$1").replace(remaining, "").replace(/[ \t]+$/, "") : text;
  // Original line endings are kept. Outer blank lines and outer spaces are dropped.
  function text(value) {
    if (typeof value !== "string") return value;
    return value.split(/(\r\n|\n|\r)/).map((part, index) => index % 2 ? part : line(part)).join("").trim();
  }
  // One wording for the EDR status, in Summary and in the report.
  const status = value => typeof value === "string" && /^\s*not[ _-]mitigated\s*$/i.test(value) ? "Unmitigated" : value;
  const value = input => status(text(input));
  return Object.freeze({ line, text, status, value });
})();
if (typeof window !== "undefined" && window.SOCNote) window.SOCNote.clean = globalThis.SOCClean;
if (typeof module !== "undefined") module.exports = globalThis.SOCClean;

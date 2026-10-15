"use strict";
window.SOCNote.defang = Object.freeze({
  // Presentation only: keep original source values intact.
  isUrl(value) {
    if (typeof value !== "string") return false;
    const text = value.trim();
    if (/\s/.test(text) || !/^(?:https?|hxxps?|ftps?):\/\//i.test(text)) return false;
    try {
      const url = new URL(text.replace(/^hxxp(?=s?:\/\/)/i, "http").replace(/\[\.\]/g, "."));
      return ["http:", "https:", "ftp:", "ftps:"].includes(url.protocol) && Boolean(url.hostname);
    } catch { return false; }
  },
  value(value) {
    return String(value)
      .replace(/\bhttps:\/\//gi, "hxxps://")
      .replace(/\bhttp:\/\//gi, "hxxp://")
      .replace(/\[\.\]|\./g, "[.]");
  }
});

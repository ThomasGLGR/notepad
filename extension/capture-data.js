"use strict";
globalThis.SOCCaptureData = (() => {
  const types = Object.freeze(["URL", "IP", "Domain", "Email", "Hash", "Hostname", "User", "Process", "File", "Command line", "Date", "UUID", "SID", "EDR Action", "Country", "Unknown"]);
  const MAX_VALUE = 500000;
  const MAX_SOURCES = 5000;
  const bounded = (value, size) => typeof value === "string" && value.length <= size;
  function validate(value) {
    if (!value || !bounded(value.id, 128) || !value.id || !bounded(value.value, MAX_VALUE) || !value.value.trim()) return null;
    if (!Number.isSafeInteger(value.timestamp) || value.timestamp < 0 || !Number.isInteger(value.tabId) || value.tabId < 0 || !Number.isInteger(value.windowId) || value.windowId < 0) return null;
    if (!bounded(value.title, 200) || !bounded(value.url, 2048) || !bounded(value.context, 160)) return null;
    if (value.method !== undefined && !["selection", "page-url", "clipboard", "json"].includes(value.method)) return null;
    if (value.method === "json" && !globalThis.SOCJSON?.prepare(value.value).ok) return null;
    if (value.digest !== undefined && (value.method !== "json" || typeof value.digest !== "string" || !/^[a-f0-9]{64}$/.test(value.digest))) return null;
    const clean = { id: value.id, value: value.value, timestamp: value.timestamp, tabId: value.tabId, windowId: value.windowId, title: value.title, url: value.url, context: value.context };
    if (value.method !== undefined) clean.method = value.method;
    if (value.digest !== undefined) clean.digest = value.digest;
    return clean;
  }
  function validateMany(values) {
    if (!Array.isArray(values) || values.length > MAX_SOURCES) return null;
    const ids = new Set(), clean = [];
    for (const value of values) {
      const item = validate(value);
      if (!item || ids.has(item.id)) return null;
      ids.add(item.id);
      clean.push(item);
    }
    return clean;
  }
  return Object.freeze({ types, MAX_VALUE, MAX_SOURCES, validate, validateMany });
})();
if (typeof module !== "undefined") module.exports = globalThis.SOCCaptureData;

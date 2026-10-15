"use strict";
window.SOCNote.remediationStorage = (() => {
  const KEY = "soc-note-builder.remediation-catalog.v1";
  const MAX_SIZE = 2000000;
  const string = value => typeof value === "string";
  function validate(value) {
    if (!value || value.version !== 1 || !Array.isArray(value.tactics) || value.tactics.length > 100) return null;
    const tacticIds = new Set(), itemIds = new Set();
    const tactics = [];
    for (const tactic of value.tactics) {
      if (!tactic || !["id", "name", "mitreId"].every(key => string(tactic[key])) || !tactic.id || !tactic.name.trim() || tacticIds.has(tactic.id) || !["default", "custom"].includes(tactic.origin)) return null;
      if (!Array.isArray(tactic.remediations) || tactic.remediations.length > 2000) return null;
      tacticIds.add(tactic.id);
      const remediations = [];
      for (const item of tactic.remediations) {
        if (!item || !["id", "template", "generic"].every(key => string(item[key])) || !item.id || !item.template.trim() || itemIds.has(item.id) || !["default", "custom"].includes(item.origin) || typeof item.enabled !== "boolean" || typeof item.favorite !== "boolean") return null;
        itemIds.add(item.id);
        // Only catalogue configuration is retained. No investigation fields.
        remediations.push({ id: item.id, template: item.template, generic: item.generic, origin: item.origin, enabled: item.enabled, favorite: item.favorite });
      }
      tactics.push({ id: tactic.id, name: tactic.name, mitreId: tactic.mitreId, origin: tactic.origin, remediations });
    }
    return tactics;
  }
  function load() {
    try {
      const raw = window.localStorage.getItem(KEY);
      if (raw === null) return { enabled: false, catalog: window.SOCNote.remediationData.defaults(), error: null };
      if (raw.length > MAX_SIZE) throw Error("Too large");
      const catalog = validate(JSON.parse(raw));
      if (!catalog) throw Error("Invalid catalogue");
      return { enabled: true, catalog: window.SOCNote.remediationData.upgradeCatalog(catalog), error: null };
    } catch {
      return { enabled: false, catalog: window.SOCNote.remediationData.defaults(), error: "Local catalogue is unavailable or invalid. Configuration remains in memory." };
    }
  }
  function save(catalog) {
    try {
      const tactics = validate({ version: 1, tactics: catalog });
      if (!tactics) throw Error("Invalid catalogue");
      const encoded = JSON.stringify({ version: 1, tactics });
      if (encoded.length > MAX_SIZE) throw Error("Too large");
      window.localStorage.setItem(KEY, encoded);
      return { ok: true };
    } catch {
      return { ok: false, error: "Catalogue saving is unavailable. Configuration remains in memory." };
    }
  }
  function setEnabled(enabled, catalog) {
    if (enabled) return save(catalog);
    try { window.localStorage.removeItem(KEY); return { ok: true }; }
    catch { return { ok: false, error: "The browser denied access to the local catalogue." }; }
  }
  return Object.freeze({ load, save, setEnabled, validate });
})();

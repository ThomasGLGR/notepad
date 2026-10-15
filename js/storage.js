"use strict";
window.SOCNote.storage = (() => {
  const CURRENT_KEY = "soc-note-builder.current-analysis.v1";
  const LEGACY_DOCUMENT_KEY = "soc-note-builder.document.v1";
  const LEGACY_PREFERENCE_KEY = "soc-note-builder.persist.v1";
  const MAX_SAVED_CHARACTERS = 4000000;
  const string = value => typeof value === "string";
  function validate(value) {
    const { templates, pairs } = window.SOCNote;
    if (!value || typeof value !== "object" || !string(value.raw)) return null;
    if (value.schemaVersion === 1) return migrateLegacy(value);
    if (![2, 3, 4].includes(value.schemaVersion) || !Array.isArray(value.variables) || value.variables.length > 2000) return null;
    if (!Array.isArray(value.ignoredKeys) || value.ignoredKeys.length > 2000 || !value.ignoredKeys.every(string)) return null;
    if (value.schemaVersion >= 3 && (!Array.isArray(value.ignoredValues) || value.ignoredValues.length > 2000 || !value.ignoredValues.every(string))) return null;
    if (!string(value.createdAt) || !string(value.updatedAt) || typeof value.isDemo !== "boolean") return null;
    const ids = new Set();
    for (const item of value.variables) {
      if (!item || !string(item.id) || !string(item.key) || !string(item.value) || !["raw", "manual", "captured", "mitre"].includes(item.origin) || ids.has(item.id)) return null;
      if (item.origin === "mitre" && (!string(item.tacticId) || !item.tacticId)) return null;
      if (item.defangUrl !== undefined && typeof item.defangUrl !== "boolean") return null;
      if (item.hideVirusTotal !== undefined && typeof item.hideVirusTotal !== "boolean") return null;
      if (item.hideFlag !== undefined && typeof item.hideFlag !== "boolean") return null;
      if (item.timeZone !== undefined && !pairs.TIME_ZONES.includes(item.timeZone)) return null;
      if (item.hideTimeZone !== undefined && typeof item.hideTimeZone !== "boolean") return null;
      if (item.parentId !== undefined && (!string(item.parentId) || !item.parentId || item.parentId === item.id)) return null;
      if (item.captureType !== undefined && !globalThis.SOCCaptureData?.types.includes(item.captureType)) return null;
      for (const name of window.SOCNote.entities?.META || []) if (item[name] !== undefined && !window.SOCNote.entities.validMeta(name, item[name])) return null;
      if (item.jsonFields !== undefined && (!Array.isArray(item.jsonFields) || !item.jsonFields.length || item.jsonFields.length > 2000 || !item.jsonFields.every(key => string(key) && key.trim() && key.length <= 256 && !/[\r\n]/.test(key)))) return null;
      if (value.schemaVersion >= 3 && (!Array.isArray(item.keys) || !item.keys.length || !item.keys.every(string) || !item.value.trim() || (!item.jsonFields?.length && /[\r\n]/.test(item.value)))) return null;
      ids.add(item.id);
    }
    const byId = new Map(value.variables.map(item => [item.id, item]));
    for (const item of value.variables) if (item.parentId && (!byId.has(item.parentId) || byId.get(item.parentId).parentId)) return null;
    const clean = templates.emptyDocument();
    for (const key of ["raw", "createdAt", "updatedAt", "isDemo"]) clean[key] = value[key];
    for (const key of ["rule", "sourceFileName", "capturedRaw", "analysis"]) {
      if (value[key] !== undefined && !string(value[key])) return null;
      clean[key] = value[key] || "";
    }
    clean.variables = pairs.normalize(value.variables, { splitLegacy: value.schemaVersion === 2 });
    if (value.schemaVersion >= 3 && clean.variables.length !== value.variables.length) return null;
    if (value.mitreTechniques !== undefined && window.SOCNote.mitre) {
      const techniques = window.SOCNote.mitre.validate(value.mitreTechniques);
      if (!techniques) return null;
      clean.mitreTechniques = techniques;
    }
    clean.ignoredKeys = [...value.ignoredKeys];
    clean.ignoredValues = [...(value.ignoredValues || [])];
    if (value.extensionCaptures !== undefined) {
      const captures = globalThis.SOCCaptureData?.validateMany(value.extensionCaptures);
      if (!captures) return null;
      clean.extensionCaptures = captures;
    }
    // Retain older analyst-written prose while rebuilding only the current schema.
    if (value.schemaVersion <= 3 && string(value.draft) && value.draft.trim()) clean.analysis += (clean.analysis ? "\n\n" : "") + value.draft;
    if (window.SOCNote.remediationEngine) {
      const remediation = window.SOCNote.remediationEngine.validateSession(value.remediation);
      if (!remediation) return null;
      clean.remediation = remediation;
    }
    if (value.remediationCatalog != null) {
      const catalogue = window.SOCNote.remediationStorage?.validate({ version: 1, tactics: value.remediationCatalog });
      if (!catalogue) return null;
      clean.remediationCatalog = catalogue;
    }
    return clean;
  }
  function migrateLegacy(value) {
    const { templates, pairs } = window.SOCNote;
    const fields = { title: "Alert", id: "Alert ID", source: "Source", severity: "Severity", detectedAt: "Date" };
    const groups = ["users", "hosts", "processes", "network", "iocs", "timeline"];
    if (!value.alert || !Object.keys(fields).every(key => string(value.alert[key]))) return null;
    if (!string(value.observations) || !string(value.analystNotes) || typeof value.isDemo !== "boolean") return null;
    if (!string(value.createdAt) || !string(value.updatedAt)) return null;
    if (!groups.every(key => Array.isArray(value[key]) && value[key].length <= 2000 && value[key].every(item => item && string(item.value) && string(item.context)))) return null;
    const clean = templates.emptyDocument();
    for (const key of ["raw", "isDemo", "createdAt", "updatedAt"]) clean[key] = value[key];
    clean.rule = value.alert.title;
    const add = (key, value) => { if (value) clean.variables.push({ id: templates.createId(), key, value, origin: "manual" }); };
    for (const [key, label] of Object.entries(fields)) add(label, value.alert[key]);
    for (const key of groups) for (const item of value[key]) add(key, item.value + (item.context ? " — " + item.context : ""));
    clean.analysis = [value.observations, value.analystNotes].filter(Boolean).join("\n\n");
    clean.variables = pairs.normalize(clean.variables);
    return clean;
  }
  function isEmpty(document) {
    return !document.rule && !document.raw && !document.capturedRaw && !document.analysis && !document.sourceFileName && !document.variables.length && !document.remediation.selected.length && !document.remediation.activeTactics.length && !document.extensionCaptures?.length && !document.mitreTechniques?.length;
  }
  function load() {
    try {
      let raw = window.localStorage.getItem(CURRENT_KEY);
      if (raw === null && window.localStorage.getItem(LEGACY_PREFERENCE_KEY) === "yes") raw = window.localStorage.getItem(LEGACY_DOCUMENT_KEY);
      if (!raw) return { document: null, writable: true, error: null };
      if (raw.length > MAX_SAVED_CHARACTERS) throw Error("Draft too large");
      const document = validate(JSON.parse(raw));
      if (!document) throw Error("Invalid draft");
      return { document, writable: true, error: null };
    } catch {
      return { document: null, writable: false, error: "Current Analysis could not be restored. Start a New Investigation to replace this draft." };
    }
  }
  function clear() {
    try {
      window.localStorage.removeItem(CURRENT_KEY);
      window.localStorage.removeItem(LEGACY_DOCUMENT_KEY);
      window.localStorage.removeItem(LEGACY_PREFERENCE_KEY);
      return { ok: true };
    } catch { return { ok: false, error: "Current Analysis could not be cleared." }; }
  }
  function save(document) {
    try {
      const clean = validate(document);
      if (!clean) return { ok: false, error: "Current Analysis could not be saved: invalid data." };
      if (isEmpty(clean)) return clear();
      const encoded = JSON.stringify(clean);
      if (encoded.length > MAX_SAVED_CHARACTERS) return { ok: false, error: "Current Analysis is too large to recover automatically." };
      window.localStorage.setItem(CURRENT_KEY, encoded);
      window.localStorage.removeItem(LEGACY_DOCUMENT_KEY);
      window.localStorage.removeItem(LEGACY_PREFERENCE_KEY);
      return { ok: true };
    } catch { return { ok: false, error: "Current Analysis could not be saved. Browser storage is unavailable." }; }
  }
  return Object.freeze({ load, save, clear, validate, isEmpty });
})();

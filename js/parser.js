"use strict";
window.SOCNote.parser = (() => {
  const MAX_CHARACTERS = 500000;
  const MAX_VARIABLES = 200;
  function parse(raw, { capture = false, context = "" } = {}) {
    const result = { variables: [], limited: false };
    if (raw.length > MAX_CHARACTERS) { result.limited = true; return result; }
    const { pairs } = window.SOCNote;
    const found = new Map();
    const clean = globalThis.SOCClean;
    for (const original of raw.split(/\r\n|\n|\r/)) {
      // Pictographs never reach Summary, whatever sent the text. A captured flag
      // on its own is read as its country code first.
      const flag = capture && /^\s*[\u{1F1E6}-\u{1F1FF}]{2}\s*$/u.test(original) ? globalThis.SOCCountry?.code(original) : null;
      const line = flag || (clean ? clean.line(original) : original);
      const field = capture ? window.SOCNote.extractors.captureField(line, context) : window.SOCNote.extractors.explicitField(line);
      if (!field || !field.value.trim()) continue;
      if (clean) field.value = clean.status(field.value);
      const previous = found.get(field.value);
      if (previous) previous.keys = pairs.combineKeys(previous.keys, [field.key]);
      else if (found.size < MAX_VARIABLES) {
        const record = { key: field.key, keys: [field.key], value: field.value };
        if (capture) record.captureType = field.captureType;
        found.set(field.value, record);
      }
      else result.limited = true;
    }
    result.variables = [...found.values()];
    return result;
  }
  function merge(document, parsed) {
    if (document.raw.length > MAX_CHARACTERS) return;
    const { templates, pairs } = window.SOCNote;
    const retained = document.variables.filter(record => record.origin !== "raw");
    const byValue = new Map(retained.map(record => [record.value, record]));
    const previous = new Map(document.variables.map(record => [record.value, record]));
    const ignoredKeys = new Set(document.ignoredKeys);
    const ignoredValues = new Set(document.ignoredValues || []);
    for (const field of parsed.variables) {
      if (ignoredValues.has(field.value)) continue;
      const names = pairs.keys(field).filter(key => !ignoredKeys.has(templates.normalizeKey(key)));
      if (!names.length) continue;
      const existing = byValue.get(field.value);
      if (existing) {
        existing.keys = pairs.combineKeys(pairs.keys(existing), names);
        existing.key = existing.keys[0];
      } else {
        const record = { id: previous.get(field.value)?.id || templates.createId(), key: names[0], keys: names, value: field.value, origin: "raw" };
        if (previous.get(field.value)?.defangUrl === true) record.defangUrl = true;
        if (previous.get(field.value)?.parentId) record.parentId = previous.get(field.value).parentId;
        if (previous.has(field.value)) pairs.inheritMeta(record, previous.get(field.value));
        retained.push(record);
        byValue.set(record.value, record);
      }
    }
    document.variables = pairs.repairHierarchy(retained);
  }
  function capture(document) {
    // Submitted Logs are archived cleaned: no pictographs, outer spaces or outer blank lines.
    if (globalThis.SOCClean && document.raw.length <= MAX_CHARACTERS) document.raw = globalThis.SOCClean.text(document.raw);
    if (!document.raw.trim()) return { ok: false, empty: true, limited: false };
    const parsed = parse(document.raw);
    if (document.raw.length > MAX_CHARACTERS) return { ok: false, empty: false, limited: true };
    merge(document, parsed);
    for (const record of document.variables) if (record.origin === "raw") record.origin = "captured";
    document.capturedRaw = (document.capturedRaw || "") + (document.capturedRaw ? "\n\n" : "") + document.raw;
    document.raw = "";
    return { ok: true, count: parsed.variables.length, limited: parsed.limited };
  }
  const originalRaw = document => (document.capturedRaw || "") + (document.capturedRaw && document.raw ? "\n\n" : "") + document.raw;
  function importCaptures(document, captures) {
    const clean = globalThis.SOCCaptureData?.validateMany(captures);
    if (!clean) return { ok: false, error: "Invalid capture data." };
    const sources = document.extensionCaptures || [];
    const known = new Set(sources.map(source => source.id));
    for (const source of clean) {
      const previous = sources.find(item => item.id === source.id);
      if (previous?.method === "json" && (source.method !== "json" || globalThis.SOCJSON.prepare(previous.value).signature !== globalThis.SOCJSON.prepare(source.value).signature)) return { ok: false, error: "This JSON send ID was already used with different data." };
    }
    const fresh = clean.filter(source => !known.has(source.id));
    if (sources.length + fresh.length > globalThis.SOCCaptureData.MAX_SOURCES) return { ok: false, error: "Capture provenance limit reached. Start a new investigation." };
    const parsed = fresh.map(source => source.method === "json" || globalThis.SOCJSON?.looksLikeJSON(source.value)
      ? { json: globalThis.SOCJSON.prepare(source.value) }
      : parse(source.value, { capture: true, context: source.context }));
    const invalidJSON = parsed.find(result => result.json && !result.json.ok);
    if (invalidJSON) return invalidJSON.json;
    if (parsed.some(result => result.limited)) return { ok: false, error: "Capture exceeds the parser limit. Select a smaller block." };
    const { pairs, templates } = window.SOCNote;
    const working = JSON.parse(JSON.stringify(document));
    const ignoredKeys = new Set(document.ignoredKeys), ignoredValues = new Set(document.ignoredValues || []);
    let jsonCount = 0, jsonSends = 0;
    for (const result of parsed) {
      if (result.json) {
        const imported = globalThis.SOCJSON.importJSON(working, result.json.encoded);
        if (!imported.ok) return imported;
        jsonCount += imported.count;
        jsonSends++;
        continue;
      }
      const used = new Set(working.variables.flatMap(record => pairs.keys(record).map(templates.normalizeKey)));
      const values = new Map(working.variables.map(record => [record.value, record]));
      for (const field of result.variables) {
        const allowedNames = pairs.keys(field).filter(name => !ignoredKeys.has(templates.normalizeKey(name)));
        if (!allowedNames.length || ignoredValues.has(field.value)) continue;
        if (values.has(field.value)) {
          const existing = values.get(field.value);
          if (existing.origin === "raw") existing.origin = "captured";
          existing.keys = pairs.combineKeys(pairs.keys(existing), allowedNames);
          existing.key = existing.keys[0];
          continue;
        }
        const names = allowedNames.map(name => {
          let key = name, suffix = 2;
          while (used.has(templates.normalizeKey(key))) key = name + " " + suffix++;
          used.add(templates.normalizeKey(key));
          return key;
        });
        const record = { id: templates.createId(), key: names[0], keys: names, value: field.value, origin: "captured", captureType: field.captureType };
        values.set(field.value, record);
        working.variables.push(record);
      }
    }
    document.variables = working.variables;
    if (fresh.length) document.extensionCaptures = [...sources, ...fresh];
    return { ok: true, count: fresh.length, ids: clean.map(source => source.id), jsonCount, jsonSends };
  }
  return Object.freeze({ parse, merge, capture, originalRaw, importCaptures, MAX_CHARACTERS, MAX_VARIABLES });
})();

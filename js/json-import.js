"use strict";
globalThis.SOCJSON = (() => {
  const MAX_CHARACTERS = 500000, MAX_FIELDS = 200, MAX_KEY = 256;
  const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value) && Object.prototype.toString.call(value) === "[object Object]";
  function prepare(data) {
    try {
      if (typeof data === "string") {
        if (data.length > MAX_CHARACTERS) throw Error("JSON exceeds 500,000 characters.");
        data = JSON.parse(data);
      }
      const objects = Array.isArray(data) ? data : [data];
      if (objects.length > 2000 || !objects.every(isObject)) throw Error("Expected a JSON object or an array of objects.");
      let nodes = 0;
      const copy = (value, depth = 0, sorted = false) => {
        if (++nodes > 20000 || depth > 32) throw Error("JSON is too complex.");
        if (value === null || typeof value === "string" || typeof value === "boolean") return value;
        if (typeof value === "number" && Number.isFinite(value)) return value;
        if (Array.isArray(value)) return value.map(item => copy(item, depth + 1, sorted));
        if (!isObject(value)) throw Error("Unsupported JSON value.");
        const names = Object.keys(value);
        if (sorted) names.sort();
        return Object.fromEntries(names.map(key => {
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          if (!descriptor || !Object.hasOwn(descriptor, "value")) throw Error("Unsupported JSON property.");
          return [key, copy(descriptor.value, depth + 1, sorted)];
        }));
      };
      const clean = copy(data);
      const encoded = JSON.stringify(clean);
      if (encoded.length > MAX_CHARACTERS) throw Error("JSON exceeds 500,000 characters.");
      const fields = [], seen = new Map();
      // Context links (country, file path, file hash) found inside a single object.
      const links = [], occurrences = new Map();
      const identity = field => field.key + "\u0000" + field.value;
      let ignored = 0;
      const addField = (key, item) => {
        if (item === null || (typeof item === "string" && !item.trim()) || (Array.isArray(item) && !item.length) || (isObject(item) && !Object.keys(item).length)) { ignored++; return; }
        const value = typeof item === "string" ? item : JSON.stringify(item);
        const values = seen.get(key) || new Set();
        if (values.has(value)) return;
        values.add(value); seen.set(key, values);
        fields.push({ key, value });
        if (fields.length > MAX_FIELDS) throw Error("JSON exceeds 200 distinct field/value pairs.");
      };
      // Text values lose pictographs and outer whitespace; inner spacing and line breaks stay.
      const tidy = item => typeof item === "string" && globalThis.SOCClean ? globalThis.SOCClean.value(item) : item;
      const collect = object => {
        const entries = [];
        const note = (key, item, field) => {
          if (typeof item === "string") entries.push({ key, value: item, field });
          // Nested objects stay JSON text in Summary; their leaves only give context.
          else if (isObject(item)) for (const [name, child] of Object.entries(item)) note(key + "." + name, child, false);
        };
        for (const [key, original] of Object.entries(object)) {
          if (!key.trim() || key.length > MAX_KEY || /[\r\n]/.test(key)) throw Error("JSON field names must contain 1–256 characters on one line.");
          if (!Array.isArray(original)) { addField(key, tidy(original)); note(key, tidy(original), true); continue; }
          for (const item of original) {
            // Arrays of objects expose their own field names, without a
            // container/index prefix. Literal dotted keys remain untouched.
            if (isObject(item)) collect(item);
            else { addField(key, tidy(item)); note(key, tidy(item), true); }
          }
        }
        const count = (entry, name) => {
          const tally = occurrences.get(identity(entry)) || { total: 0, linked: 0 };
          tally[name]++;
          occurrences.set(identity(entry), tally);
        };
        for (const entry of entries) if (entry.field) count(entry, "total");
        const found = globalThis.SOCEntities?.associate(entries) || [];
        for (const key of new Set(found.flatMap(link => link.sources.map(identity)))) occurrences.get(key).linked++;
        links.push(...found);
      };
      for (const object of Array.isArray(clean) ? clean : [clean]) collect(object);
      nodes = 0;
      const signature = JSON.stringify(copy(clean, 0, true));
      // A field is absorbed by its entity only if every occurrence was linked.
      const linked = new Set([...occurrences].filter(([, tally]) => tally.linked && tally.linked === tally.total).map(([key]) => key));
      return { ok: true, fields, encoded, signature, ignored, links, linked };
    } catch (error) {
      return { ok: false, error: error instanceof SyntaxError ? "Invalid JSON. Check its syntax." : error.message || "Invalid JSON." };
    }
  }
  function importJSON(document, data) {
    const prepared = prepare(data);
    if (!prepared.ok) return prepared;
    const { pairs, templates } = window.SOCNote;
    const records = JSON.parse(JSON.stringify(document.variables));
    const byValue = new Map(records.map(record => [record.value, record]));
    const used = new Set(records.flatMap(record => pairs.keys(record).map(templates.normalizeKey)));
    const reserved = new Set(prepared.fields.map(field => templates.normalizeKey(field.key)));
    const ignoredKeys = new Set(document.ignoredKeys), ignoredValues = new Set(document.ignoredValues || []);
    let count = 0, ignored = prepared.ignored;
    const identity = field => field.key + "\u0000" + field.value;
    const excluded = field => ignoredKeys.has(templates.normalizeKey(field.key)) || ignoredValues.has(field.value);
    const add = field => {
      if (excluded(field)) { ignored++; return; }
      let record = byValue.get(field.value);
      if (record?.jsonFields?.includes(field.key)) return;
      if (record && pairs.keys(record).includes(field.key)) {
        record.jsonFields = [...new Set([...(record.jsonFields || []), field.key])];
        if (["raw", "mitre"].includes(record.origin)) { record.origin = "captured"; delete record.tacticId; }
        return;
      }
      let name = field.key, suffix = 2;
      while (used.has(templates.normalizeKey(name))) {
        name = field.key + suffix++;
        while (reserved.has(templates.normalizeKey(name))) name = field.key + suffix++;
      }
      used.add(templates.normalizeKey(name));
      if (record) {
        record.keys = [...pairs.keys(record), name];
        record.key = record.keys[0];
        record.jsonFields = [...new Set([...(record.jsonFields || []), field.key])];
        if (["raw", "mitre"].includes(record.origin)) { record.origin = "captured"; delete record.tacticId; }
      } else {
        record = { id: templates.createId(), key: name, keys: [name], value: field.value, origin: "captured", jsonFields: [field.key] };
        records.push(record); byValue.set(field.value, record);
      }
      count++;
    };
    const linked = prepared.linked || new Set();
    for (const field of prepared.fields) if (!linked.has(identity(field))) add(field);
    // Countries and file details join their own IP, URL or file. A missing or
    // already different target keeps the field as an ordinary pair instead.
    const unplaced = new Set();
    for (const link of prepared.links || []) {
      const sources = link.sources.filter(source => !excluded(source));
      if (link.sources.length && !sources.length) continue;
      const record = byValue.get(link.target);
      if (record && record.origin !== "mitre" && !record[link.meta]) { record[link.meta] = link.value; count++; }
      else if (record?.[link.meta] !== link.value) for (const source of sources) unplaced.add(identity(source));
    }
    for (const field of prepared.fields) if (linked.has(identity(field)) && unplaced.has(identity(field))) add(field);
    if (records.length > 2000) return { ok: false, error: "Investigation exceeds 2,000 values. Start a new investigation." };
    document.variables = records;
    return { ok: true, count, ignored };
  }
  const looksLikeJSON = text => /^\s*(?:\{\s*(?:"|\})|\[\s*(?:\{|\]))/.test(text);
  return Object.freeze({ prepare, importJSON, looksLikeJSON, MAX_CHARACTERS, MAX_FIELDS, MAX_KEY });
})();
if (typeof window !== "undefined" && window.SOCNote) window.SOCNote.jsonImport = globalThis.SOCJSON;
if (typeof module !== "undefined") module.exports = globalThis.SOCJSON;

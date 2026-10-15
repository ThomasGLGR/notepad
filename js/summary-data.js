"use strict";
window.SOCNote.pairs = (() => {
  const { templates } = window.SOCNote;
  const offsets = Array.from({ length: 27 }, (_, index) => (index - 12) * 60).filter(minutes => minutes !== 0);
  offsets.push(-570, 210, 270, 330, 345, 390, 525, 570, 630, 765, 825);
  const TIME_ZONES = Object.freeze(["", "UTC", ...offsets.sort((a, b) => a - b).map(minutes => {
    const hours = Math.floor(Math.abs(minutes) / 60), remainder = Math.abs(minutes) % 60;
    return "UTC" + (minutes < 0 ? "-" : "+") + hours + (remainder ? ":" + String(remainder).padStart(2, "0") : "");
  })]);
  function keys(record) {
    const source = Array.isArray(record.keys) ? record.keys : [record.key];
    const seen = new Set();
    return source.filter(key => typeof key === "string").map(key => record.jsonFields?.length ? key : key.trim()).filter(key => {
      const normalized = templates.normalizeKey(key);
      if (!key || seen.has(normalized)) return false;
      seen.add(normalized);
      return true;
    });
  }
  function combineKeys(first, second) { return keys({ keys: [...first, ...second] }); }
  // Details and report presentation choices follow their value through merges and re-parsing.
  const inheritMeta = (target, source) => {
    window.SOCNote.entities?.inherit(target, source);
    if (source.hideVirusTotal === true) target.hideVirusTotal = true;
    if (source.hideFlag === true) target.hideFlag = true;
    if (source.timeZone !== undefined && target.timeZone === undefined) target.timeZone = source.timeZone;
    if (source.hideTimeZone === true) target.hideTimeZone = true;
    return target;
  };
  // Keep a flat storage format, with each parent's children immediately after it.
  function ordered(records) {
    const children = new Map();
    for (const record of records) if (record.parentId) {
      if (!children.has(record.parentId)) children.set(record.parentId, []);
      children.get(record.parentId).push(record);
    }
    return records.filter(record => !record.parentId).flatMap(record => [record, ...(children.get(record.id) || [])]);
  }
  function repairHierarchy(records) {
    const byId = new Map(records.map(record => [record.id, record]));
    const invalid = records.filter(record => record.parentId && (!byId.has(record.parentId) || record.parentId === record.id || byId.get(record.parentId).parentId));
    for (const record of invalid) delete record.parentId;
    return ordered(records);
  }
  function normalize(records, { splitLegacy = false } = {}) {
    const byValue = new Map();
    const usedIds = new Set();
    const mergedIds = new Map();
    for (const record of records) {
      const names = keys(record);
      if (!names.length || typeof record.value !== "string") continue;
      const values = splitLegacy ? record.value.split(/\r\n|\n|\r/) : [record.value];
      for (const original of values) {
        const value = record.jsonFields?.length ? original : original.trim();
        if (!value.trim()) continue;
        const existing = byValue.get(value);
        if (existing) {
          if (record.id && record.id !== existing.id) mergedIds.set(record.id, existing.id);
          existing.keys = combineKeys(existing.keys, names);
          existing.key = existing.keys[0];
          if (record.origin === "manual") existing.origin = "manual";
          if (record.defangUrl === true) existing.defangUrl = true;
          if (record.jsonFields) existing.jsonFields = [...new Set([...(existing.jsonFields || []), ...record.jsonFields])];
          inheritMeta(existing, record);
          continue;
        }
        const id = record.id && !usedIds.has(record.id) ? record.id : templates.createId();
        usedIds.add(id);
        const clean = { id, key: names[0], keys: [...names], value, origin: record.origin || "raw" };
        if (record.parentId) clean.parentId = record.parentId;
        if (record.captureType !== undefined) clean.captureType = record.captureType;
        if (record.origin === "mitre") clean.tacticId = record.tacticId;
        if (record.defangUrl === true) clean.defangUrl = true;
        if (record.jsonFields) clean.jsonFields = [...record.jsonFields];
        byValue.set(value, inheritMeta(clean, record));
      }
    }
    const result = [...byValue.values()];
    for (const record of result) if (mergedIds.has(record.parentId)) record.parentId = mergedIds.get(record.parentId);
    return repairHierarchy(result);
  }
  // "Not mitigated" reads "Unmitigated" everywhere, including in drafts saved before the change.
  const status = value => globalThis.SOCClean ? globalThis.SOCClean.status(value) : value;
  const displayValue = record => record.defangUrl === true && window.SOCNote.defang.isUrl(record.value) ? window.SOCNote.defang.value(record.value) : status(record.value);
  function isDate(record) {
    const value = record.value.trim();
    if (window.SOCNote.extractors?.isDate(value)) return true;
    // Numeric epoch values need an explicit date/time key to avoid treating IDs as dates.
    return /^(?:\d{10}|\d{13})$/.test(value) && keys(record).some(key => /(?:^|[_. -])(?:timestamp|date|datetime|time)(?:$|[_. -])|(?:created|updated|detected|occurred)[_ -]?at$/i.test(key));
  }
  // Only an exact upper-case ISO code gets a flag: names and lower-case words are left alone.
  const countryCode = record => record.origin !== "mitre" && globalThis.SOCCountry?.isCode(record.value.trim()) ? record.value.trim() : "";
  const countryFlag = record => countryCode(record) ? globalThis.SOCCountry.flag(countryCode(record)) : "";
  const reportFlag = record => record.hideFlag === true ? "" : countryFlag(record);
  const reportTimeZone = record => isDate(record) && record.hideTimeZone !== true ? (record.timeZone ?? "UTC") : "";
  const format = document => ordered(document.variables).map(record => (record.parentId ? "  " : "") + keys(record).join(" / ") + " : " + displayValue(record)).join("\n");
  const values = document => ordered(document.variables).map(displayValue).join("\n");
  function syncMitre(document, tactics) {
    const facts = document.variables.filter(record => record.origin !== "mitre");
    const factByValue = new Map(facts.map(record => [record.value, record]));
    const values = new Set(facts.map(record => record.value));
    const wanted = new Map();
    for (const tactic of tactics) {
      const value = tactic.name + (tactic.mitreId ? " (" + tactic.mitreId + ")" : "");
      if (values.has(value)) {
        const fact = factByValue.get(value);
        if (fact) { fact.keys = combineKeys(keys(fact), ["MITRE"]); fact.key = fact.keys[0]; }
        continue;
      }
      values.add(value);
      wanted.set(tactic.id, { id: "mitre:" + tactic.id, key: "MITRE", keys: ["MITRE"], value, origin: "mitre", tacticId: tactic.id });
    }
    const records = [];
    for (const record of document.variables) {
      if (record.origin !== "mitre") records.push(record);
      else if (wanted.has(record.tacticId)) {
        records.push({ ...wanted.get(record.tacticId), id: record.id, ...(record.parentId ? { parentId: record.parentId } : {}) });
        wanted.delete(record.tacticId);
      }
    }
    records.push(...wanted.values());
    document.variables = repairHierarchy(records);
  }
  function edit(document, id, { names, value }) {
    const record = document.variables.find(record => record.id === id);
    if (!record || record.origin === "mitre") return { ok: false };
    const nextKeys = names === undefined ? keys(record) : keys({ keys: names });
    const nextValue = value === undefined ? record.value : status(record.jsonFields?.length ? value : value.trim());
    if (!nextKeys.length || !nextValue || (!record.jsonFields?.length && /[\r\n]/.test(nextValue)) || nextKeys.some(key => /[{}\r\n]/.test(key))) return { ok: false };
    if (record.origin !== "manual" && (record.value !== nextValue || JSON.stringify(keys(record)) !== JSON.stringify(nextKeys))) {
      if (!document.ignoredValues.includes(record.value)) document.ignoredValues.push(record.value);
    }
    const duplicate = document.variables.find(other => other.id !== id && other.value === nextValue);
    if (duplicate) {
      duplicate.keys = combineKeys(keys(duplicate), nextKeys);
      duplicate.key = duplicate.keys[0];
      duplicate.origin = "manual";
      if (record.defangUrl === true) duplicate.defangUrl = true;
      if (record.jsonFields) duplicate.jsonFields = [...new Set([...(duplicate.jsonFields || []), ...record.jsonFields])];
      inheritMeta(duplicate, record);
      // Merging a parent into its child promotes that child before adopting siblings.
      if (duplicate.parentId === id) delete duplicate.parentId;
      const children = document.variables.filter(other => other.parentId === id && other.id !== duplicate.id);
      if (children.length) delete duplicate.parentId;
      for (const child of children) child.parentId = duplicate.id;
      document.variables = document.variables.filter(other => other.id !== id);
      document.variables = repairHierarchy(document.variables);
      return { ok: true, merged: true, id: duplicate.id };
    }
    Object.assign(record, { key: nextKeys[0], keys: nextKeys, value: nextValue, origin: "manual" });
    return { ok: true, id };
  }
  function add(document, names, value, parentId) {
    const parent = parentId && document.variables.find(record => record.id === parentId);
    if (parentId && (!parent || parent.parentId)) return { ok: false };
    const nextKeys = keys({ keys: names });
    const nextValue = status(value.trim());
    if (!nextKeys.length || !nextValue || /[\r\n]/.test(nextValue) || nextKeys.some(key => /[{}\r\n]/.test(key))) return { ok: false };
    const existing = document.variables.find(record => record.value === nextValue);
    if (existing) {
      if (parentId && existing.parentId !== parentId) return { ok: false, duplicate: true };
      existing.keys = combineKeys(keys(existing), nextKeys);
      existing.key = existing.keys[0];
      return { ok: true, merged: true, id: existing.id };
    }
    const record = { id: templates.createId(), key: nextKeys[0], keys: nextKeys, value: nextValue, origin: "manual" };
    if (parentId) record.parentId = parentId;
    document.variables.push(record);
    document.variables = ordered(document.variables);
    return { ok: true, id: record.id };
  }
  function canMove(document, id, targetId, { nest = false } = {}) {
    const source = document.variables.find(record => record.id === id);
    const target = document.variables.find(record => record.id === targetId);
    if (!source || id === targetId || (targetId && !target) || target?.parentId === id) return false;
    // A right-side drop on a child uses its existing parent, never a third level.
    const parentId = nest ? (target?.parentId || target?.id) : target?.parentId;
    if (nest && !target) return false;
    // Creating a child is reserved for the right-side nesting target.
    if (!nest && !source.parentId && target?.parentId) return false;
    return !parentId || !document.variables.some(record => record.parentId === id);
  }
  function resolveDrop(document, id, targetId, { nest = false, after = false } = {}) {
    if (canMove(document, id, targetId, { nest })) return { id: targetId, nest, after };
    const source = document.variables.find(record => record.id === id);
    const target = document.variables.find(record => record.id === targetId);
    if (!source || !target) return null;
    const roots = document.variables.filter(record => !record.parentId);
    const index = roots.findIndex(record => record.id === (target.parentId || target.id));
    if (index < 0) return null;
    // The first legal top-level gap below a row is after its entire parent block.
    // For a drop on the source's own block, anchor before the next root instead.
    const anchor = roots[index];
    const fallback = anchor.id === id
      ? { id: roots[index + 1]?.id, nest: false, after: false, fallback: true }
      : { id: anchor.id, nest: false, after: true, fallback: true };
    return canMove(document, id, fallback.id, fallback) ? fallback : null;
  }
  function move(document, id, targetId, { nest = false, after = false } = {}) {
    if (!canMove(document, id, targetId, { nest })) return { ok: false };
    const source = document.variables.find(record => record.id === id);
    const target = document.variables.find(record => record.id === targetId);
    const block = document.variables.filter(record => record.id === id || record.parentId === id);
    const records = ordered(document.variables).filter(record => !block.includes(record));
    const parentId = nest ? (target.parentId || target.id) : target?.parentId;
    if (parentId) source.parentId = parentId;
    else delete source.parentId;
    let index = records.findIndex(record => record.id === targetId);
    if (index < 0) index = records.length;
    else if (nest || after) {
      index += 1;
      // Nesting inserts directly below the hovered row. Root reordering moves
      // past the target's complete block of children.
      if (!nest && !target.parentId) while (records[index]?.parentId === targetId) index += 1;
    }
    records.splice(index, 0, ...block);
    document.variables = ordered(records);
    return { ok: true, id };
  }
  function remove(document, id) {
    const record = document.variables.find(record => record.id === id);
    if (!record) return { ok: false };
    // Deleting a category keeps its manually created children as top-level categories.
    for (const child of document.variables) if (child.parentId === id) delete child.parentId;
    document.variables = ordered(document.variables.filter(record => record.id !== id));
    // A deleted value can be imported again; only current records count as duplicates.
    document.ignoredValues = document.ignoredValues.filter(value => value !== record.value);
    return { ok: true };
  }
  // An empty value removes the detail. The pair keeps its origin, key and value.
  function setMeta(document, id, name, value) {
    const record = document.variables.find(record => record.id === id), entities = window.SOCNote.entities;
    if (!record || record.origin === "mitre" || !entities?.META.includes(name) || typeof value !== "string") return { ok: false };
    const next = entities.cleanMeta(name, value);
    if (next) record[name] = next;
    else delete record[name];
    return { ok: true, id, value: next };
  }
  return Object.freeze({ TIME_ZONES, keys, combineKeys, inheritMeta, ordered, repairHierarchy, normalize, displayValue, isDate, countryCode, countryFlag, reportFlag, reportTimeZone, format, values, syncMitre, edit, add, canMove, resolveDrop, move, remove, setMeta });
})();

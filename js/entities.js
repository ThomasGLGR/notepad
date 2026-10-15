"use strict";
// Local enrichment of Summary values: entity kinds, VirusTotal links and JSON context.
// Links are built as text only. Nothing here requests, resolves or submits an indicator.
globalThis.SOCEntities = (() => {
  const labels = Object.freeze({ country: "Country", domain: "Domain", path: "Path", hash: "Hash", virusTotal: "VirusTotal" });
  const META = Object.freeze(["country", "filePath", "fileHash"]);
  const LIMITS = Object.freeze({ country: 64, filePath: 4096, fileHash: 256 });
  const VT = "https://www.virustotal.com/gui/";
  const single = value => typeof value === "string" && Boolean(value.trim()) && !/[\r\n]/.test(value);
  const normalizeKey = key => key.normalize("NFD").replace(/[̀-ͯ]/g, "").trim().toLowerCase().replace(/[ .-]+/g, "_");
  function ip(value) {
    if (!single(value)) return null;
    const text = value.trim().replace(/\[\.\]/g, ".");
    if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(text)) return text.split(".").every(part => Number(part) <= 255) ? text : null;
    if (!/^[\da-f:]+$/i.test(text) || !text.includes(":")) return null;
    try { return new URL("http://[" + text + "]/").hostname.replace(/^\[|\]$/g, "") || null; } catch { return null; }
  }
  // Private, loopback and link-local addresses have no public reputation to look up.
  function routable(address) {
    if (address.includes(":")) return !/^(?:::1?$|fe[89ab][\da-f]:|f[cd][\da-f]{2}:)/i.test(address);
    const [a, b] = address.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168));
  }
  // Same acceptance as the Defanged URL option, including hxxp(s):// and [.] forms.
  function url(value) {
    if (!single(value)) return null;
    const text = value.trim();
    if (/\s/.test(text) || !/^(?:https?|hxxps?|ftps?):\/\//i.test(text)) return null;
    const exact = text.replace(/^hxxp(s?):\/\//i, (match, secure) => "http" + secure.toLowerCase() + "://").replace(/\[\.\]/g, ".");
    try {
      const parsed = new URL(exact);
      if (!["http:", "https:", "ftp:", "ftps:"].includes(parsed.protocol) || !parsed.hostname) return null;
      return { exact, domain: parsed.hostname };
    } catch { return null; }
  }
  function hashType(value) {
    if (typeof value !== "string" || !/^[a-f\d]+$/i.test(value.trim())) return null;
    return { 32: "MD5", 40: "SHA1", 64: "SHA256" }[value.trim().length] || null;
  }
  // VirusTotal URL identifier: unpadded URL-safe base64 of the exact URL.
  function base64url(text) {
    let encoded;
    try { encoded = encodeURIComponent(text); } catch { return null; }
    const bytes = [];
    for (let index = 0; index < encoded.length; index++) {
      if (encoded[index] === "%") { bytes.push(parseInt(encoded.slice(index + 1, index + 3), 16)); index += 2; }
      else bytes.push(encoded.charCodeAt(index));
    }
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let output = "";
    for (let index = 0; index < bytes.length; index += 3) {
      const chunk = (bytes[index] << 16) | ((bytes[index + 1] || 0) << 8) | (bytes[index + 2] || 0);
      output += alphabet[chunk >> 18] + alphabet[(chunk >> 12) & 63];
      if (index + 1 < bytes.length) output += alphabet[(chunk >> 6) & 63];
      if (index + 2 < bytes.length) output += alphabet[chunk & 63];
    }
    return output;
  }
  const virusTotal = Object.freeze({
    ip(value) { const address = ip(value); return address ? VT + "ip-address/" + address : null; },
    file(value) { return hashType(value) ? VT + "file/" + value.trim().toLowerCase() : null; },
    urlId(value) { const parsed = url(value); return parsed ? base64url(parsed.exact) : null; },
    url(value) { const id = virusTotal.urlId(value); return id ? VT + "url/" + id : null; }
  });
  const FILE_KEY = /(?:^|_)(?:(?:file|fichier)(?:_?(?:name|path|full_path))?|filename|filepath|targetfilename|originalfilename|attachment|piece_jointe)$/;
  const COMMAND_KEY = /command|cmd_?line/;
  const keyNames = record => [...(Array.isArray(record.keys) ? record.keys : [record.key]), ...(record.jsonFields || [])]
    .filter(key => typeof key === "string").map(key => normalizeKey(key).replace(/_?\d+$/, ""));
  function isFile(record) {
    const names = keyNames(record);
    if (names.some(name => COMMAND_KEY.test(name))) return false;
    return record.captureType === "File" || names.some(name => FILE_KEY.test(name));
  }
  // Links to the event in its own console (ECS event.url and similar) are references
  // to open, not indicators to analyze.
  const REFERENCE_KEY = /^(?:.*_)?event_(?:url|reference)$|^(?:.*_)?alert_url$|^rule_reference$/;
  const isReference = record => keyNames(record).some(name => REFERENCE_KEY.test(name));
  // The value decides for addresses, URLs and hashes; files need an explicit key or capture type.
  function kind(record) {
    if (!record || record.origin === "mitre" || !single(record.value)) return null;
    if (url(record.value)) return isReference(record) ? "reference" : "url";
    if (ip(record.value)) return "ip";
    if (hashType(record.value)) return "hash";
    return isFile(record) ? "file" : null;
  }
  const pathLike = value => /[\\/]/.test(value);
  function link(record) {
    const type = kind(record);
    if (type === "ip") { const address = ip(record.value); return routable(address) ? virusTotal.ip(address) : null; }
    if (type === "url") return virusTotal.url(record.value);
    if (type === "hash") return virusTotal.file(record.value);
    return type === "file" ? virusTotal.file(record.fileHash) : null;
  }
  // `shown` is the value as presented: a defanged URL gets a defanged domain.
  function describe(record, shown = record.value) {
    const type = kind(record), domain = type === "url" ? url(record.value).domain : "";
    return {
      kind: type,
      link: link(record),
      domain: /^hxxp|\[\.\]/i.test(shown) ? domain.replace(/\./g, "[.]") : domain,
      country: type === "ip" || type === "url",
      path: type === "file" && !pathLike(record.value),
      hash: type === "file",
      hashType: type === "hash" ? hashType(record.value) : type === "file" ? hashType(record.fileHash) : null
    };
  }
  // A reference is clickable only as a plain http(s) address: a defanged one stays text.
  function reference(record, shown = record.value) {
    return kind(record) === "reference" && /^https?:\/\//i.test(shown.trim()) && url(shown) ? shown.trim() : null;
  }
  // Report lines under a Summary value.
  function details(record, shown = record.value) {
    const about = describe(record, shown), lines = [];
    const add = (label, value) => { if (value) lines.push({ label, value }); };
    add(labels.domain, about.domain);
    if (about.country) add(labels.country, globalThis.SOCCountry ? globalThis.SOCCountry.display(record.country) : record.country);
    if (about.path) add(labels.path, record.filePath);
    if (about.hash) add(labels.hash + (about.hashType ? " " + about.hashType : ""), record.fileHash);
    if (about.link) lines.push({ label: labels.virusTotal, value: about.link, href: about.link });
    return lines;
  }
  function cleanMeta(name, value) {
    if (!META.includes(name) || typeof value !== "string") return "";
    let text = value.replace(/[\r\n]+/g, " ").trim();
    if (name === "fileHash") text = text.replace(/^(?:sha-?256|sha-?1|md5)\s*[:=]\s*/i, "");
    text = text.slice(0, LIMITS[name]).trim();
    if (name === "country") return globalThis.SOCCountry ? globalThis.SOCCountry.normalize(text) : text;
    return name === "fileHash" && hashType(text) ? text.toLowerCase() : text;
  }
  const validMeta = (name, value) => META.includes(name) && typeof value === "string" && Boolean(value.trim()) && value.length <= LIMITS[name] && !/[\r\n]/.test(value);
  // Missing details only: an existing choice on the target is never replaced.
  function inherit(target, source) {
    for (const name of META) if (validMeta(name, source[name]) && !target[name]) target[name] = source[name];
    return target;
  }
  // Context links inside one JSON object. A link exists only when its target is
  // unambiguous; otherwise the fields stay ordinary Summary pairs.
  function associate(entries) {
    const usable = entries.filter(entry => single(entry.value));
    const groups = new Map();
    for (const entry of usable) {
      const name = normalizeKey(entry.key);
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(entry);
    }
    const distinct = list => [...new Set(list.map(entry => entry.value))];
    const unique = list => list && distinct(list).length === 1 ? list[0] : null;
    const pick = (names, test) => {
      for (const name of names) { const entry = unique(groups.get(name)); if (entry && test(entry.value)) return entry; }
      return null;
    };
    const links = [];
    const add = (target, meta, value, sources) => links.push({ target: target.value, meta, value,
      sources: sources.filter(source => source.field).map(source => ({ key: source.key, value: source.value })) });

    const resolver = globalThis.SOCCountry;
    const countries = new Map();
    for (const [name, list] of groups) {
      const match = /^(.*?)(country_iso_code|country_code2?|country_name|country)$/.exec(name);
      if (!match) continue;
      const prefix = match[1].replace(/_$/, "").replace(/(?:^|_)geo(?:ip)?$/, "");
      if (!countries.has(prefix)) countries.set(prefix, { codes: [], names: [], broken: false });
      const group = countries.get(prefix), entry = unique(list);
      if (!entry) group.broken = true;
      else (/^country_(?:iso_code|code2?)$/.test(match[2]) ? group.codes : group.names).push(...list);
    }
    const lone = () => {
      const addresses = distinct(usable.filter(entry => ip(entry.value)));
      const values = addresses.length ? addresses : distinct(usable.filter(entry => url(entry.value)));
      return values.length === 1 ? usable.find(entry => entry.value === values[0]) : null;
    };
    for (const [prefix, group] of resolver ? countries : []) {
      const candidates = [...group.codes, ...group.names];
      if (group.broken || !candidates.length) continue;
      const best = candidates.find(entry => resolver.code(entry.value)) || candidates[0];
      const code = resolver.code(best.value), value = resolver.normalize(best.value);
      if (!value || candidates.some(entry => (resolver.code(entry.value) || code) !== code)) continue;
      const target = !prefix ? lone()
        : pick([prefix + "_ip", prefix + "ip", prefix + "_address", prefix + "_ip_address", prefix + "_ipaddress", prefix + "_addr", prefix], ip)
          || pick([prefix + "_url", prefix + "url", prefix + "_url_full", prefix + "_url_original", prefix + "_full", prefix + "_original", prefix], url);
      if (target) add(target, "country", value, candidates.filter(entry => code ? resolver.code(entry.value) === code : entry.value === best.value));
    }

    const files = new Map();
    for (const [name, list] of groups) {
      let match, role;
      if ((match = /^(.*_)?(?:file_?name|file|fichier|targetfilename|originalfilename)$/.exec(name))) role = "name";
      else if ((match = /^(.*_)?file_?(?:full_)?path$/.exec(name))) role = "path";
      else if ((match = /^(.*_)?file_?(?:hash_?)?(?:sha256|sha1|md5)$/.exec(name) || /^(.*_)?file_?hash$/.exec(name) || /^()(?:hash_?)?(?:sha256|sha1|md5)$/.exec(name) || /^()hash$/.exec(name))) role = "hash";
      else continue;
      const prefix = match[1] || "";
      if (!files.has(prefix)) files.set(prefix, { name: [], path: [], hash: [] });
      files.get(prefix)[role].push(...list);
    }
    const rank = { SHA256: 0, SHA1: 1, MD5: 2 };
    for (const group of files.values()) {
      if (distinct(group.name).length > 1 || distinct(group.path).length > 1) continue;
      const name = group.name[0], path = group.path[0], primary = name || path;
      if (!primary) continue;
      if (name && path && path.value !== name.value) add(name, "filePath", cleanMeta("filePath", path.value), group.path);
      const hashes = group.hash.filter(entry => hashType(entry.value)).sort((first, second) => rank[hashType(first.value)] - rank[hashType(second.value)]);
      const strongest = hashes.filter(entry => hashType(entry.value) === hashType(hashes[0].value));
      if (distinct(strongest).length === 1) add(primary, "fileHash", cleanMeta("fileHash", strongest[0].value), strongest);
    }
    return links.filter(item => validMeta(item.meta, item.value));
  }
  return Object.freeze({ labels, META, LIMITS, ip, routable, url, hashType, virusTotal, kind, link, reference, describe, details, cleanMeta, validMeta, inherit, associate, normalizeKey });
})();
if (typeof window !== "undefined" && window.SOCNote) window.SOCNote.entities = globalThis.SOCEntities;
if (typeof module !== "undefined") module.exports = globalThis.SOCEntities;

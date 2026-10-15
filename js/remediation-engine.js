"use strict";
window.SOCNote.remediationEngine = (() => {
  const aliases = {
    USER: ["user", "utilisateur", "username", "account", "compte", "users"],
    HOST: ["host", "hote", "hostname", "machine", "computer", "hosts"],
    IP: ["ip", "ip_address", "adresse_ip"],
    SRC_IP: ["src_ip", "source_ip", "ip_source"],
    DST_IP: ["dst_ip", "destination_ip", "ip_destination", "destination"],
    DOMAIN: ["domain", "domaine"], URL: ["url", "uri"], HASH: ["hash", "sha256", "sha1", "md5"],
    FILE: ["file", "fichier", "filename", "file_name", "filepath", "file_path"],
    PROCESS: ["process", "processus", "process_name", "processes"]
  };
  const genericValues = {
    USER: "under investigation", HOST: "under investigation", IP: "identified as malicious", SRC_IP: "identified as malicious",
    DST_IP: "identified as malicious", DOMAIN: "identified as malicious", URL: "identified as malicious",
    HASH: "identified in the investigation", FILE: "identified as malicious", PROCESS: "identified as malicious"
  };
  const jsonAliases = {
    USER: ["user_name", "user_id", "user_email"], HOST: ["host_hostname", "host_name", "host_id"],
    IP: ["host_ip", "source_ip", "destination_ip", "client_ip", "server_ip"], SRC_IP: ["source_ip", "client_ip"], DST_IP: ["destination_ip", "server_ip"],
    DOMAIN: ["dns_question_name", "url_domain"], URL: ["url_full", "url_original"], HASH: ["file_hash_sha256", "file_hash_sha1", "file_hash_md5", "process_hash_sha256"],
    FILE: ["file_name", "file_path"], PROCESS: ["process_name", "process_executable"]
  };
  const normalize = value => value.normalize("NFD").replace(/[\u0300-\u036f]/g, "").trim().toLowerCase().replace(/[ .-]+/g, "_");
  const usable = value => typeof value === "string" && value.trim() && !/^(undefined|null)$/i.test(value.trim());
  const plain = value => value.trim().replace(/\s*\r?\n\s*/g, " / ");
  function values(document) {
    const result = Object.create(null);
    for (const [token, keys] of Object.entries(aliases)) {
      const values = [];
      for (const variable of document.variables || []) {
        const names = window.SOCNote.pairs.keys(variable).map(key => {
          const name = normalize(key);
          // Numbered extension fields retain the existing remediation aliases.
          return variable.captureType ? name.replace(/_\d+$/, "") : name;
        });
        const jsonNames = (variable.jsonFields || []).map(normalize);
        if ((names.some(key => keys.includes(key)) || jsonNames.some(key => keys.includes(key) || jsonAliases[token].includes(key))) && usable(variable.value)) {
          const value = plain(variable.value);
          if (!values.includes(value)) values.push(value);
          // A file's own path completes {FILE}, as its separate pair did.
          if (token === "FILE" && usable(variable.filePath) && !values.includes(variable.filePath)) values.push(variable.filePath);
        }
        if (token === "HASH" && usable(variable.fileHash) && !values.includes(variable.fileHash)) values.push(variable.fileHash);
      }
      if (values.length) result[token] = values.map(value => ["IP", "SRC_IP", "DST_IP", "DOMAIN", "URL"].includes(token) ? window.SOCNote.defang.value(value) : value).join(" / ");
    }
    return result;
  }
  function resolve(template, document, generic = "") {
    const map = values(document);
    const missing = [];
    const text = String(template).replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, key) => {
      const token = key.toUpperCase();
      if (Object.hasOwn(map, token)) return map[token];
      missing.push(token);
      return genericValues[token] || "[to complete]";
    });
    // A custom generic phrase is used only if every referenced value is absent.
    if (generic && missing.length && !/\{[^{}]+\}/.test(generic) && !Object.keys(map).some(key => new RegExp("\\{" + key + "\\}", "i").test(template))) {
      return { text: generic, missing };
    }
    return { text, missing };
  }
  const emptySession = () => ({ activeTactics: [], selected: [], includeTactics: false });
  function validateSession(value) {
    if (value === undefined) return emptySession();
    if (!value || typeof value !== "object" || typeof value.includeTactics !== "boolean") return null;
    if (!Array.isArray(value.activeTactics) || value.activeTactics.length > 100 || !value.activeTactics.every(id => typeof id === "string")) return null;
    if (!Array.isArray(value.selected) || value.selected.length > 2000) return null;
    const ids = new Set();
    const selected = [];
    for (const item of value.selected) {
      if (!item || !["id", "tacticId", "tacticName", "template", "generic"].every(key => typeof item[key] === "string") || (item.text !== null && typeof item.text !== "string") || ids.has(item.id)) return null;
      ids.add(item.id);
      selected.push(window.SOCNote.remediationData.upgradeTemplate({ id: item.id, tacticId: item.tacticId, tacticName: item.tacticName, template: item.template, generic: item.generic, text: item.text }));
    }
    return { activeTactics: [...new Set(value.activeTactics)], selected, includeTactics: value.includeTactics };
  }
  const selectedText = (item, document) => resolve(item.text === null ? item.template : item.text, document, item.text === null ? item.generic : "").text.trim();
  function format(document, { heading = false } = {}) {
    const session = document.remediation || emptySession();
    const lines = [];
    let lastTactic = null;
    for (const item of session.selected) {
      const text = selectedText(item, document);
      if (!text) continue;
      if (session.includeTactics && lastTactic !== item.tacticId) {
        if (lines.length) lines.push("");
        lines.push(item.tacticName);
        lastTactic = item.tacticId;
      }
      lines.push("- " + text.replace(/\r?\n/g, "\n  "));
    }
    return lines.length ? (heading ? "REMEDIATION\n\n" : "") + lines.join("\n") : "";
  }
  return Object.freeze({ values, resolve, emptySession, validateSession, selectedText, format, normalize });
})();

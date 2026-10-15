"use strict";
window.SOCNote.extractors = (() => {
  // Explicit lines only. No discovery or execution.
  function explicitField(line) {
    const match = /^\s*([A-Za-zÀ-ÿ_][A-Za-zÀ-ÿ0-9_. -]{0,63}?)\s*[:=]\s*(.*)$/.exec(line);
    if (!match) return null;
    const key = match[1].trim();
    if ((/^https?$/i.test(key) && match[2].startsWith("//"))) return null;
    return { key, value: match[2].trim() };
  }
  function isDate(text) {
    const iso = /^(\d{4})-(\d{2})-(\d{2})(.*)$/.exec(text);
    const local = iso ? null : /^(\d{2})([\/.-])(\d{2})\2(\d{4})(.*)$/.exec(text);
    if (!iso && !local) return false;
    const year = Number(iso ? iso[1] : local[4]);
    const month = Number(iso ? iso[2] : local[3]);
    const day = Number(iso ? iso[3] : local[1]);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year < 1 || month < 1 || month > 12 || day < 1 || day > days[month - 1]) return false;
    const suffix = iso ? iso[4] : local[5];
    if (!suffix) return true;
    const time = /^[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,]\d{1,9})?)?(?: ?(Z|UTC|GMT|[+-]\d{2}:?\d{2}))?$/i.exec(suffix);
    if (!time || Number(time[1]) > 23 || Number(time[2]) > 59 || Number(time[3] || 0) > 59) return false;
    const zone = time[4]?.replace(":", "");
    return !zone || !/^[+-]/.test(zone) || (Number(zone.slice(1, 3)) <= 23 && Number(zone.slice(3)) <= 59);
  }
  function isSID(text) {
    const sid = /^S-1-(0|[1-9]\d{0,9}|0x[a-f\d]{12})((?:-(?:0|[1-9]\d{0,9})){1,15})$/i.exec(text);
    if (!sid) return false;
    const authority = Number(sid[1]);
    if (/^0x/i.test(sid[1]) ? authority < 4294967296 : authority > 4294967295) return false;
    return sid[2].slice(1).split("-").every(part => Number(part) <= 4294967295);
  }
  // Used only for extension captures. Ordinary Logs keep explicit-field parsing.
  function classify(value, context = "") {
    const text = value.trim();
    const label = context.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[_:=.-]+/g, " ").trim();
    if (/^(?:https?|hxxps?|ftps?):\/\/\S+$/i.test(text)) {
      try {
        const url = new URL(text.replace(/^hxxp/i, "http").replace(/\[\.\]/g, "."));
        if (url.hostname) return "URL";
      } catch { /* Keep malformed URLs unclassified. */ }
    }
    if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(text) && text.split(".").every(part => Number(part) <= 255)) return "IP";
    if (/^[\da-f:]+$/i.test(text) && text.includes(":")) {
      try { if (new URL("http://[" + text + "]/").hostname) return "IP"; } catch { /* Invalid IPv6. */ }
    }
    if (/^[^\s@<>]+@[a-z\d](?:[a-z\d.-]*[a-z\d])?\.[a-z]{2,}$/i.test(text)) return "Email";
    if (isDate(text)) return "Date";
    const uuidText = text.replace(/^urn:uuid:/i, "");
    const uuid = uuidText.startsWith("{") && uuidText.endsWith("}") ? uuidText.slice(1, -1) : uuidText;
    if (/^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i.test(uuid)) return "UUID";
    if (isSID(text)) return "SID";
    const status = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/[_-]+/g, " ").replace(/\s+/g, " ");
    if (/^(?:(?:not |non )?mitigated|unmitigated|(?:non )?(?:mitige|attenue))$/.test(status)) return "EDR Action";
    if (/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64}|[a-f\d]{128})$/i.test(text)) return "Hash";
    if (/^(?:[a-z]:[\\/]|\\\\[^\\\s]+\\|\/(?:[^/\s]+\/|[^/\s]+$))/i.test(text)) return "File";
    if (/^(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|bash|sh|zsh|python\d*(?:\.exe)?|curl(?:\.exe)?|wget(?:\.exe)?|rundll32(?:\.exe)?|certutil(?:\.exe)?)\s+\S/i.test(text)) return "Command line";
    if (/^[\w.-]+\.exe$/i.test(text)) return "Process";
    if (/^[\w.-]+\.(?:dll|ps1|bat|cmd|sh|log|json|csv|txt)$/i.test(text)) return "File";
    if (/^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i.test(text.replace(/\[\.\]/g, "."))) return "Domain";
    // An upper-case ISO country code sent on its own is a country; "in" or "France" are not.
    if (globalThis.SOCCountry?.isCode(text)) return "Country";
    if (/^(?:user(?:name)?|utilisateur|account|compte|login|user principal name)(?: name)?$/.test(label) && /^\S+$/.test(text)) return "User";
    if (/^(?:host(?:name)?|hote|computer|machine|device)(?: name)?$/.test(label) && /^[\w.-]+$/.test(text)) return "Hostname";
    if (/^(?:process(?: name)?|processus|image name)$/.test(label) && /^\S+$/.test(text)) return "Process";
    if (/^(?:command(?: line)?|commandline|ligne de commande)$/.test(label)) return "Command line";
    if (/^(?:file(?: name| path)?|fichier|filepath)$/.test(label)) return "File";
    if (/^(?:edr action|edr status|mitigation(?: status)?|mitigated)$/.test(label) && text) return "EDR Action";
    return "Unknown";
  }
  function captureField(line, context = "") {
    const value = line.trim();
    if (!value) return null;
    const type = classify(value);
    if (type !== "Unknown") return { key: type, value, captureType: type };
    const explicit = explicitField(line);
    if (explicit) return { ...explicit, captureType: classify(explicit.value, explicit.key) };
    const contextual = classify(value, context);
    return { key: contextual, value, captureType: contextual };
  }
  return Object.freeze({ explicitField, isDate, classify, captureField });
})();

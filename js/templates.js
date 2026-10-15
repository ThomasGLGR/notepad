"use strict";
window.SOCNote = window.SOCNote || {};
// Remediation and Recommendations are withdrawn for now. Their catalogue, engine,
// editor and saved selections remain; set this to true to bring both sections back.
window.SOCNote.features = { remediation: false };
window.SOCNote.templates = (() => {
  const normalizeKey = key => key.trim().toLowerCase();
  function createId() {
    return window.crypto && typeof window.crypto.randomUUID === "function"
      ? window.crypto.randomUUID() : "pair-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  }
  function emptyDocument() {
    const now = new Date().toISOString();
    return { schemaVersion: 4, createdAt: now, updatedAt: now, rule: "", sourceFileName: "", raw: "", capturedRaw: "", analysis: "", mitreTechniques: [], variables: [], ignoredKeys: [], ignoredValues: [], isDemo: false,
      remediation: { activeTactics: [], selected: [], includeTactics: false }, remediationCatalog: null };
  }
  function demoDocument() {
    const document = emptyDocument();
    document.isDemo = true;
    document.rule = "Suspicious PowerShell Execution";
    document.raw = "# Fictional example\nuser: a.martin\nhost: WS-DEMO-07\ndestination_ip: 192.0.2.17\ndestination_ip: 192.0.2.18\ndestination_ip: 192.0.2.17\nprocess: powershell.exe\ncommand_line: powershell.exe -NoProfile -File C:\\Demo\\inventory.ps1";
    document.variables = [
      ["user", "a.martin"], ["host", "WS-DEMO-07"], ["destination_ip", "192.0.2.17"], ["destination_ip", "192.0.2.18"],
      ["process", "powershell.exe"], ["command_line", "powershell.exe -NoProfile -File C:\\Demo\\inventory.ps1"]
    ].map(([key, value]) => ({ id: createId(), key, keys: [key], value, origin: "raw" }));
    document.analysis = "Review sign-ins and process activity. This example is fictional.";
    return document;
  }
  return Object.freeze({ normalizeKey, createId, emptyDocument, demoDocument });
})();

"use strict";
(() => {
  const { templates, parser, formatter, storage } = window.SOCNote;
  const $ = id => document.getElementById(id);
  const loaded = storage.load();
  let state = loaded.document || templates.emptyDocument();
  const extensionMode = location.protocol === "chrome-extension:" && !!globalThis.chrome?.runtime?.id;
  let lastSavedState = null;
  let draftWritable = loaded.writable;
  let storageError = loaded.error;
  let pastedRaw = null;
  let manualCopyText = null;
  let pendingEdit = null;
  let editTimer, saveTimer, toastTimer;
  let sourceTimer = null;
  let fileReadGeneration = 0;
  let lastJSONInput = null;
  const history = [];
  let remediationUI, summaryUI, reportUI, mitreUI;

  function element(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function toast(message) {
    clearTimeout(toastTimer);
    $("toast").textContent = message;
    $("toast").hidden = false;
    toastTimer = setTimeout(() => { $("toast").hidden = true; }, 2500);
  }
  function pushHistory(before, label) {
    history.push({ before, label });
    let size = history.reduce((sum, entry) => sum + entry.before.length, 0);
    while (history.length > 20 || (history.length > 1 && size > 8000000)) size -= history.shift().before.length;
  }
  function refreshUndo() {
    const entry = pendingEdit || history[history.length - 1];
    $("undo-button").disabled = !entry;
    $("undo-button").title = entry ? "Undo: " + entry.label : "No changes to undo";
  }
  function flushEdit() {
    clearTimeout(editTimer);
    if (pendingEdit) { pushHistory(pendingEdit.before, pendingEdit.label); pendingEdit = null; }
    refreshUndo();
  }
  function refreshStorage() {
    $("draft-error").hidden = !storageError;
    $("draft-error").textContent = storageError || "";
  }
  function saveNow() {
    if (sourceTimer !== null) syncSource();
    clearTimeout(saveTimer);
    if (!draftWritable) return;
    // Inactive extension tabs must not overwrite a newer shared draft with an
    // unchanged snapshot. Real edits still use the existing autosave lifecycle.
    if (extensionMode && lastSavedState === JSON.stringify(state)) return;
    const result = storage.save(state);
    if (result.ok) lastSavedState = JSON.stringify(state);
    storageError = result.ok ? null : result.error;
    refreshStorage();
  }
  function change(label, mutate, { key = null } = {}) {
    if (!key || (pendingEdit && pendingEdit.key !== key)) flushEdit();
    const before = JSON.stringify(state);
    mutate(state);
    synchronizeMitre();
    if (JSON.stringify(state) === before) return;
    state.updatedAt = new Date().toISOString();
    if (key) {
      if (!pendingEdit) pendingEdit = { before, label, key };
      clearTimeout(editTimer);
      editTimer = setTimeout(flushEdit, 700);
    } else pushHistory(before, label);
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, 200);
    refresh();
  }
  function replaceDocument(next, label) {
    lastJSONInput = null;
    fileReadGeneration += 1;
    $("log-file-input").value = "";
    clearTimeout(sourceTimer);
    sourceTimer = null;
    flushEdit();
    pushHistory(JSON.stringify(state), label);
    state = next;
    draftWritable = true;
    summaryUI?.reset();
    render();
    saveNow();
    $("raw-input").focus();
    $("raw-input").setSelectionRange(0, 0);
    $("raw-input").scrollTop = 0;
  }
  function undo() {
    clearTimeout(sourceTimer);
    sourceTimer = null;
    flushEdit();
    const entry = history.pop();
    if (!entry) return;
    state = JSON.parse(entry.before);
    render();
    saveNow();
    toast("Undone: " + entry.label);
  }
  function refresh() {
    synchronizeMitre();
    const text = formatter.format(state);
    reportUI?.refresh();
    if ($("analysis-input").value !== state.analysis) $("analysis-input").value = state.analysis;
    if ($("rule-input").value !== state.rule) $("rule-input").value = state.rule;
    $("source-filename").textContent = state.sourceFileName;
    $("source-filename").hidden = !state.sourceFileName;
    $("copy-report-button").disabled = !text;
    $("source-status").textContent = state.raw.length > parser.MAX_CHARACTERS ? "Extraction limited to 500,000 characters." : "";
    $("source-status").hidden = !$("source-status").textContent;
    summaryUI?.refresh();
    mitreUI?.refresh();
    refreshUndo();
    refreshStorage();
    remediationUI?.refresh();
  }
  function render() {
    $("raw-input").value = state.raw;
    refresh();
  }
  function importExtensionCaptures(captures, { sync = true, background: backgroundClaim = false } = {}) {
    if (!draftWritable) return { ok: false, error: "Start a New Investigation before importing captures into an unavailable draft." };
    if (sync && sourceTimer !== null) syncSource();
    let candidate = JSON.parse(JSON.stringify(state));
    // Saved receipts prevent replay across views. Focused views reuse captured
    // inputs; background delivery updates an unchanged view from the shared draft.
    const latestLoad = storage.load();
    const latest = latestLoad.document;
    // An inactive view must preserve the latest shared notes during automatic
    // JSON delivery, rather than save an old snapshot over another view's edits.
    const background = extensionMode && (backgroundClaim || !document.hasFocus()) && lastSavedState === JSON.stringify(state);
    if (background) {
      if (!latestLoad.writable) return { ok: false, error: latestLoad.error };
      candidate = latest ? JSON.parse(JSON.stringify(latest)) : templates.emptyDocument();
    }
    if (latest && (latest.createdAt === candidate.createdAt || storage.isEmpty(candidate)) && latest.extensionCaptures?.length) {
      candidate.createdAt = latest.createdAt;
      const restored = parser.importCaptures(candidate, latest.extensionCaptures);
      if (!restored.ok) return restored;
    }
    const backgroundBaseline = background ? JSON.parse(JSON.stringify(candidate)) : null;
    const result = parser.importCaptures(candidate, captures);
    if (!result.ok) return result;
    candidate.updatedAt = new Date().toISOString();
    const saved = storage.save(candidate);
    if (!saved.ok) {
      storageError = saved.error;
      refreshStorage();
      return { ok: false, error: saved.error };
    }
    if (background) state = backgroundBaseline;
    change("extension captures", document => {
      if (background) Object.assign(document, candidate);
      document.createdAt = candidate.createdAt;
      document.variables = candidate.variables;
      document.extensionCaptures = candidate.extensionCaptures;
    });
    // The transaction was already saved before acknowledgement. A redundant
    // delayed save from this tab could overwrite the next tab's imported inputs.
    clearTimeout(saveTimer);
    state.updatedAt = candidate.updatedAt;
    if (background) $("raw-input").value = state.raw;
    lastSavedState = JSON.stringify(state);
    storageError = null;
    refreshStorage();
    if (result.jsonSends) toast("JSON imported: " + result.jsonCount);
    return result;
  }
  function importJSON(data, { requestId, title = "JSON import", sync = true, quietRepeat = false } = {}) {
    const prepared = window.SOCNote.jsonImport.prepare(data);
    if (!prepared.ok) { toast(prepared.error); return prepared; }
    if (requestId !== undefined && (typeof requestId !== "string" || !/^[A-Za-z0-9._:-]{1,100}$/.test(requestId))) {
      const result = { ok: false, error: "Invalid JSON send ID." }; toast(result.error); return result;
    }
    const id = "json:" + (requestId || templates.createId());
    const result = importExtensionCaptures([{ id, method: "json", value: prepared.encoded, timestamp: Date.now(), tabId: 0, windowId: 0,
      title: String(title).slice(0, 200), url: location.href.slice(0, 2048), context: "" }], { sync });
    if (!result.ok) toast(result.error);
    else if (!result.count && !quietRepeat) toast("JSON already imported");
    return result;
  }
  window.SOCNote.importJSON = importJSON;
  window.importJSON = importJSON;
  function synchronizeMitre() {
    if (!remediationUI) return;
    // Tactic context comes from Remediation choices and leaves Summary with that section.
    window.SOCNote.pairs.syncMitre(state, window.SOCNote.features.remediation ? remediationUI.getTactics() : []);
    state.remediationCatalog = remediationUI.getCatalog();
    // Tactic context belongs in Summary rather than an optional output setting.
    state.remediation.includeTactics = false;
  }
  function focusSection(id) {
    const target = $(id);
    target.closest("section").scrollIntoView({ block: "nearest", behavior: "smooth" });
    target.focus({ preventScroll: true });
  }
  function syncSource() {
    clearTimeout(sourceTimer);
    sourceTimer = null;
    if (window.SOCNote.jsonImport.looksLikeJSON(state.raw)) {
      if (lastJSONInput?.raw !== state.raw) lastJSONInput = { raw: state.raw, id: templates.createId() };
      importJSON(state.raw, { requestId: lastJSONInput.id, sync: false });
      return;
    }
    const parsed = parser.parse(state.raw);
    change("fields from logs", document => parser.merge(document, parsed), { key: "raw" });
    if (parsed.limited && state.raw.length <= parser.MAX_CHARACTERS) { $("source-status").textContent = "Extraction limited to 200 unique values."; $("source-status").hidden = false; }
  }
  function captureSource() {
    clearTimeout(sourceTimer);
    sourceTimer = null;
    if (window.SOCNote.jsonImport.looksLikeJSON(state.raw)) {
      if (lastJSONInput?.raw !== state.raw) lastJSONInput = { raw: state.raw, id: templates.createId() };
      // Pending JSON was already imported when it was pasted; submitting only archives it.
      const result = importJSON(state.raw, { requestId: lastJSONInput.id, sync: false, quietRepeat: true });
      if (!result.ok) return;
      change("JSON submission", document => {
        document.capturedRaw += (document.capturedRaw ? "\n\n" : "") + document.raw;
        document.raw = "";
      });
      $("raw-input").value = "";
      $("raw-input").focus();
      return;
    }
    let result;
    change("log submission", document => { result = parser.capture(document); });
    if (!result.ok) {
      toast(result.empty ? "Add logs first" : "Input too large. Logs retained.");
      return;
    }
    $("raw-input").value = state.raw;
    toast(result.limited ? "Added: " + result.count + " · 200-value limit" : result.count ? "Added: " + result.count : "No values found");
    $("raw-input").focus();
  }
  async function copyText(text, { manual = true, html = null } = {}) {
    if (!text) { toast("Nothing to copy"); return; }
    html ??= window.SOCNote.clipboard.textHTML(text);
    if (navigator.clipboard?.write && typeof ClipboardItem === "function") {
      try {
        await navigator.clipboard.write([new ClipboardItem({
          "text/plain": new Blob([text], { type: "text/plain" }),
          "text/html": new Blob([html], { type: "text/html" })
        })]);
        toast("Copied");
        return;
      } catch { /* Use the local copy event to preserve both formats. */ }
    }
    const active = document.activeElement;
    const range = typeof active.selectionStart === "number" ? [active.selectionStart, active.selectionEnd] : null;
    const currentSelection = window.getSelection();
    const editorRange = active.isContentEditable && currentSelection.rangeCount ? currentSelection.getRangeAt(0).cloneRange() : null;
    const buffer = element("textarea");
    buffer.className = "clipboard-buffer";
    buffer.value = text;
    buffer.readOnly = true;
    buffer.tabIndex = -1;
    document.body.append(buffer);
    buffer.select();
    let copied = false;
    const onCopy = event => {
      if (!event.clipboardData) return;
      event.preventDefault();
      // Do not let the textarea normalize original CRLF/CR source text.
      event.clipboardData.setData("text/plain", text);
      event.clipboardData.setData("text/html", html);
    };
    buffer.addEventListener("copy", onCopy);
    try { copied = document.execCommand("copy"); } catch { /* Manual fallback below. */ }
    finally { buffer.removeEventListener("copy", onCopy); }
    buffer.remove();
    if (active.isConnected) {
      active.focus({ preventScroll: true });
      if (range) active.setSelectionRange(...range);
      if (editorRange?.commonAncestorContainer.isConnected) {
        currentSelection.removeAllRanges();
        currentSelection.addRange(editorRange);
      }
    }
    if (copied) { toast("Copied"); return; }
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(text);
      toast("Copied");
      return;
    } catch { /* Manual fallback below. */ }
    if (!manual) { reportUI.select(); toast("Press Ctrl / ⌘ + C"); return; }
    manualCopyText = text;
    $("manual-copy-input").value = text;
    if (!$("copy-dialog").open) $("copy-dialog").showModal();
    $("manual-copy-input").focus();
    $("manual-copy-input").select();
  }
  async function copyReport() {
    if (sourceTimer !== null) syncSource();
    const text = formatter.format(state);
    if (!text) { toast("Nothing to copy"); return; }
    await copyText(text, { manual: false, html: reportUI.getHTML() });
  }
  // Map displayed LF offsets back to untouched CRLF/CR source segments.
  function originalOffset(text, displayedOffset) {
    let original = 0;
    for (let displayed = 0; displayed < displayedOffset && original < text.length; displayed += 1) original += text[original] === "\r" && text[original + 1] === "\n" ? 2 : 1;
    return original;
  }
  function preserveRawEdit(original, displayed) {
    const previous = original.replace(/\r\n?/g, "\n");
    let start = 0;
    while (start < previous.length && start < displayed.length && previous[start] === displayed[start]) start += 1;
    let oldEnd = previous.length, newEnd = displayed.length;
    while (oldEnd > start && newEnd > start && previous[oldEnd - 1] === displayed[newEnd - 1]) { oldEnd -= 1; newEnd -= 1; }
    return original.slice(0, originalOffset(original, start)) + displayed.slice(start, newEnd) + original.slice(originalOffset(original, oldEnd));
  }

  remediationUI = window.SOCNote.remediationUI.create({
    getState: () => state, change, copyText, toast,
    focus: () => focusSection("remediation-search"),
    syncSource: () => { if (sourceTimer !== null) syncSource(); },
    onCatalogChange: catalogue => change("remediation templates", document => { document.remediationCatalog = catalogue; })
  });
  summaryUI = window.SOCNote.summaryEditor.create({ getState: () => state, change, copyText, toast });
  reportUI = window.SOCNote.reportUI.create({ getState: () => state });
  mitreUI = window.SOCNote.mitre.create({ getState: () => state, change, toast });
  $("remediation-panel").hidden = !window.SOCNote.features.remediation;
  render();
  if (loaded.error) toast(loaded.error);
  else saveNow();
  $("raw-input").addEventListener("paste", event => {
    if (!event.clipboardData) return;
    const input = event.target, original = event.clipboardData.getData("text/plain");
    // Pasted blocks arrive without pictographs, outer spaces or outer blank lines.
    const pasted = window.SOCNote.clean.text(original);
    pastedRaw = state.raw.slice(0, originalOffset(state.raw, input.selectionStart)) + pasted + state.raw.slice(originalOffset(state.raw, input.selectionEnd));
    setTimeout(() => { pastedRaw = null; }, 0);
    if (pasted === original) return;
    // The browser would insert the clipboard text as it is.
    event.preventDefault();
    input.setRangeText(pasted.replace(/\r\n?/g, "\n"), input.selectionStart, input.selectionEnd, "end");
    input.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste" }));
  });
  $("raw-input").addEventListener("copy", event => {
    const input = event.target;
    if (!event.clipboardData || input.selectionStart === input.selectionEnd) return;
    const text = state.raw.slice(originalOffset(state.raw, input.selectionStart), originalOffset(state.raw, input.selectionEnd));
    event.preventDefault();
    event.clipboardData.setData("text/plain", text);
    event.clipboardData.setData("text/html", window.SOCNote.clipboard.textHTML(text));
  });
  $("raw-input").addEventListener("input", event => {
    fileReadGeneration += 1;
    const fromPaste = event.inputType === "insertFromPaste" || pastedRaw !== null;
    const next = pastedRaw !== null && pastedRaw.replace(/\r\n?/g, "\n") === event.target.value ? pastedRaw : preserveRawEdit(state.raw, event.target.value);
    pastedRaw = null;
    const freshInput = !state.raw;
    // A new paste or new Logs entry is a fresh import, even with identical JSON.
    if (fromPaste || freshInput) lastJSONInput = null;
    change("logs", document => { document.raw = next; if (fromPaste || freshInput) document.sourceFileName = ""; }, { key: "raw" });
    clearTimeout(sourceTimer);
    if (fromPaste) syncSource();
    else sourceTimer = setTimeout(syncSource, 250);
  });
  document.addEventListener("focusout", event => {
    if (event.target.id === "raw-input" && sourceTimer !== null) syncSource();
    if (event.target.matches("input, textarea, [contenteditable]")) flushEdit();
  });
  $("rule-input").addEventListener("input", event => change("rule", document => { document.rule = event.target.value; }, { key: "rule" }));
  $("open-log-button").addEventListener("click", () => $("log-file-input").click());
  $("log-file-input").addEventListener("change", async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    const generation = ++fileReadGeneration;
    try {
      const raw = window.SOCNote.clean.text(await file.text());
      if (generation !== fileReadGeneration) return;
      if (/\.json$/i.test(file.name) || window.SOCNote.jsonImport.looksLikeJSON(raw)) {
        importJSON(raw, { title: file.name });
        return;
      }
      clearTimeout(sourceTimer);
      sourceTimer = null;
      change("log file", document => {
        document.raw = raw;
        document.sourceFileName = file.name;
        parser.merge(document, parser.parse(raw));
      });
      $("raw-input").value = state.raw;
    } catch { if (generation === fileReadGeneration) toast("Could not read the log file."); }
    finally { event.target.value = ""; }
  });
  $("process-source-button").addEventListener("click", captureSource);
  $("raw-input").addEventListener("keydown", event => {
    if (event.key !== "Enter" || !event.ctrlKey || event.altKey || event.shiftKey || event.metaKey || event.isComposing) return;
    event.preventDefault();
    if (!event.repeat) $("process-source-button").click();
  });
  // Dropped data joins Summary through the existing JSON and capture paths. A real
  // file becomes a File pair that can be hashed locally. Fields keep native text drops.
  function dropKind(event) {
    const types = Array.from(event.dataTransfer?.types || []);
    if (types.includes("application/x-soc-pair")) return null;
    if (types.includes("Files")) return "files";
    const editable = event.target instanceof Element && event.target.closest("input, textarea, [contenteditable]");
    return types.includes("text/plain") && !editable ? "text" : null;
  }
  function importDroppedText(text) {
    if (!text.trim()) return;
    if (window.SOCNote.jsonImport.looksLikeJSON(text)) { importJSON(text, { title: "Dropped JSON" }); return; }
    const result = importExtensionCaptures([{ id: "drop:" + templates.createId(), value: text, timestamp: Date.now(), tabId: 0, windowId: 0,
      title: "Drag and drop", url: location.href.slice(0, 2048), context: "" }]);
    if (!result.ok) toast(result.error);
  }
  async function importDroppedFiles(files) {
    for (const file of files) {
      if (/\.json$/i.test(file.name) && file.size <= 4 * window.SOCNote.jsonImport.MAX_CHARACTERS) {
        try {
          const raw = await file.text();
          if (window.SOCNote.jsonImport.prepare(raw).ok) { importJSON(raw, { title: file.name }); continue; }
        } catch { /* An unreadable JSON file is still listed as a file. */ }
      }
      summaryUI.addFile(file);
    }
  }
  document.addEventListener("dragover", event => {
    if (!dropKind(event)) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "copy";
  });
  document.addEventListener("drop", event => {
    const kind = dropKind(event);
    if (!kind) return;
    event.preventDefault();
    if (kind === "files") importDroppedFiles(Array.from(event.dataTransfer.files).slice(0, 20));
    else importDroppedText(event.dataTransfer.getData("text/plain"));
  });
  $("analysis-input").addEventListener("input", event => change("analysis", document => { document.analysis = event.target.value; }, { key: "analysis" }));
  $("copy-summary-button").addEventListener("click", () => copyText(formatter.summaryValues(state)));
  $("copy-analysis-button").addEventListener("click", () => copyText(state.analysis));
  $("copy-report-button").addEventListener("click", copyReport);
  $("new-button").addEventListener("click", () => replaceDocument(templates.emptyDocument(), "new investigation"));
  $("undo-button").addEventListener("click", undo);
  $("close-copy-button").addEventListener("click", () => $("copy-dialog").close());
  $("manual-copy-input").addEventListener("copy", event => {
    if (manualCopyText === null || !event.clipboardData) return;
    const input = event.target;
    const text = manualCopyText.slice(originalOffset(manualCopyText, input.selectionStart), originalOffset(manualCopyText, input.selectionEnd));
    event.preventDefault();
    event.clipboardData.setData("text/plain", text);
    event.clipboardData.setData("text/html", window.SOCNote.clipboard.textHTML(text));
  });
  $("copy-dialog").addEventListener("close", () => { $("manual-copy-input").value = ""; manualCopyText = null; });
  document.addEventListener("keydown", event => {
    if ($("copy-dialog").open) return;
    const key = event.key.toLowerCase();
    if (extensionMode && event.ctrlKey && event.altKey && !event.shiftKey && !event.metaKey && key === "x" && !event.getModifierState("AltGraph")) {
      event.preventDefault();
      if (!event.isTrusted || event.repeat) return;
      window.SOCNote.extensionBridge.captureClipboard().then(result => {
        if (!result?.ok) toast(result?.error || "Clipboard capture unavailable");
      }).catch(() => toast("Clipboard capture unavailable"));
      return;
    }
  });
  window.addEventListener("pagehide", saveNow);
  if (extensionMode) window.addEventListener("blur", saveNow);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") saveNow(); });
  window.SOCNote.extensionBridge.start({
    onImport: importExtensionCaptures,
    onError: toast
  });
})();

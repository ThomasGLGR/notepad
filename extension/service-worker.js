"use strict";
importScripts("../js/clean.js", "../js/json-import.js", "capture-data.js", "capture-queue.js", "selection.js", "clipboard-client.js", "clipboard-shortcut.js", "json-receiver.js");
const BUILDER_URL = chrome.runtime.getURL("index.html");
async function isFocused(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    const focused = await chrome.windows.getLastFocused();
    return tab.active && focused.focused && focused.id === tab.windowId;
  } catch { return false; }
}
const queue = SOCCaptureQueue.create({ storage: chrome.storage.session, isFocused });
async function badge(message = "") {
  const pending = (await queue.snapshot()).captures.length;
  await chrome.action.setBadgeText({ text: pending ? String(pending) : "" });
  await chrome.action.setBadgeBackgroundColor({ color: message ? "#a76717" : "#31577d" });
  await chrome.action.setTitle({ title: (message || "Open SOC Note Builder") + " · " + pending + " pending capture(s)" });
}
async function initialize() {
  await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  await badge();
}
chrome.runtime.onInstalled.addListener(() => { initialize().catch(() => {}); });
chrome.runtime.onStartup.addListener(() => { badge().catch(() => {}); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes[SOCCaptureQueue.KEY]) badge().catch(() => {});
});
async function captureSelection(tab, { timestamp = Date.now() } = {}) {
  if (!Number.isInteger(tab?.id) || !Number.isInteger(tab.windowId)) return badge("Source tab unavailable");
  if (tab.url && !/^(https?|file):/i.test(tab.url)) return badge("Capture unavailable on this browser page");
  const id = crypto.randomUUID();
  let selected;
  try {
    const results = await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: readSOCSelection });
    const page = results.find(result => result.frameId === 0)?.result;
    selected = results.find(result => result.result?.focused && result.result.value?.trim())?.result;
    // Browser UI focus must not capture an old selection or infer a page URL.
    // Keep the event's source tab authoritative during rapid window switching.
    if (!selected && page?.focused === false && await isFocused(tab.id)) return badge("No text selected in the page");
    if (!selected) selected = results.find(result => result.result?.value?.trim())?.result;
  } catch {
    return badge("Capture unavailable on this page");
  }
  if (!selected?.value?.trim()) return badge("No text selected");
  if (SOCJSON.looksLikeJSON(selected.value)) {
    const prepared = SOCJSON.prepare(selected.value);
    if (!prepared.ok) return badge(prepared.error);
  }
  const capture = { id, value: selected.value, timestamp, method: "selection", tabId: tab.id, windowId: tab.windowId,
    title: String(tab.title || selected.title || "").slice(0, 200), url: String(tab.url || selected.url || "").slice(0, 2048), context: String(selected.context || "").slice(0, 160) };
  try { await queue.enqueue(capture); await badge("Captured"); return { value: selected.value }; }
  catch { await badge("Capture not saved: selection or queue is too large"); }
}
let captureTail = Promise.resolve();
function serializeCapture(operation) {
  const pending = captureTail.then(operation);
  captureTail = pending.catch(() => {});
  return pending;
}
async function installClipboardShortcut(tab) {
  if (!Number.isInteger(tab?.id) || (tab.url && !/^(https?|file):/i.test(tab.url))) return;
  try { await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: installSOCClipboardShortcut }); }
  catch { /* Restricted pages cannot receive the focused-page shortcut. */ }
  if (/^https?:/i.test(tab.url || "")) {
    try { await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, func: installSOCJSONReceiver }); }
    catch { /* A source page must be activated before it can send JSON. */ }
  }
}
function captureCommand(tab) {
  const timestamp = Date.now();
  return serializeCapture(async () => {
    await installClipboardShortcut(tab);
    const selection = await captureSelection(tab, { timestamp });
    if (!selection) return { ok: false, error: "No selection captured" };
    try {
      await SOCCaptureClipboard.writeText(selection.value);
      return { ok: true, count: 1 };
    } catch {
      const warning = "Selection saved; clipboard copy unavailable";
      await badge(warning);
      return { ok: true, count: 1, warning };
    }
  });
}
function captureClipboard(tab) {
  const timestamp = Date.now();
  return serializeCapture(() => captureClipboardOnce(tab, timestamp));
}
async function captureClipboardOnce(tab, timestamp) {
  const feedback = async (message, result) => { await badge(message); return result; };
  if (!Number.isInteger(tab?.id) || !Number.isInteger(tab.windowId)) return feedback("Source tab unavailable", { ok: false, error: "Source tab unavailable" });
  // Read once, only for Ctrl+Alt+X. Never overwrite the existing clipboard.
  let text;
  try { text = await SOCCaptureClipboard.readText(); }
  catch { return feedback("Clipboard unavailable", { ok: false, error: "Clipboard unavailable" }); }
  if (!text.trim()) return feedback("Clipboard is empty", { ok: false, error: "Clipboard is empty" });
  if (SOCJSON.looksLikeJSON(text)) {
    const prepared = SOCJSON.prepare(text);
    if (!prepared.ok) return feedback(prepared.error, prepared);
  }
  try {
    await queue.enqueue({
      id: crypto.randomUUID(), value: text, timestamp, method: "clipboard",
      tabId: tab.id, windowId: tab.windowId, title: String(tab.title || "").slice(0, 200),
      url: String(tab.url || "").slice(0, 2048), context: ""
    });
    return feedback("Captured", { ok: true, count: 1 });
  } catch {
    const error = "Clipboard not saved: text or queue is too large";
    return feedback(error, { ok: false, error });
  }
}
chrome.commands.onCommand.addListener((command, tab) => {
  // The event's tab is authoritative, even if focus changes during injection.
  if (command === "capture-selection") captureCommand(tab).catch(() => {});
});
chrome.action.onClicked.addListener(tab => {
  (async () => {
    await installClipboardShortcut(tab);
    const existing = (await chrome.runtime.getContexts({ contextTypes: ["TAB"], documentUrls: [BUILDER_URL] })).find(context => context.tabId >= 0);
    if (existing) {
      await chrome.windows.update(existing.windowId, { focused: true });
      await chrome.tabs.update(existing.tabId, { active: true });
    } else await chrome.tabs.create({ url: BUILDER_URL });
  })().catch(() => {});
});
async function jsonConsumer() {
  const contexts = await chrome.runtime.getContexts({ contextTypes: ["TAB"], documentUrls: [BUILDER_URL] });
  const tabs = [];
  for (const context of contexts) {
    try { tabs.push(await chrome.tabs.get(context.tabId)); } catch { /* Closed tab. */ }
  }
  for (const tab of tabs) if (await isFocused(tab.id)) return tab.id;
  return (tabs.find(tab => tab.active) || tabs[0])?.id;
}
async function receiveJSON(message, sender) {
  const origin = new URL(sender.url).origin;
  const id = "json:" + message.requestId;
  const receipt = (await queue.snapshot()).jsonReceipts?.find(item => item.id === id);
  if (message.type === "soc-json/status") {
    if (!receipt || receipt.origin !== origin) return { ok: false, error: "JSON send not found." };
    return { ok: true, status: receipt.status, ...(receipt.error ? { error: receipt.error } : {}) };
  }
  const prepared = SOCJSON.prepare(message.data);
  if (!prepared.ok) return prepared;
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(prepared.signature));
  const digest = Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
  await queue.enqueue({ id, method: "json", value: prepared.encoded, digest, timestamp: Date.now(), tabId: sender.tab.id, windowId: sender.tab.windowId,
    title: String(sender.tab.title || "").slice(0, 200), url: String(sender.url).slice(0, 2048), context: "" });
  await badge(receipt ? "JSON already received" : "JSON received");
  return { ok: true, status: receipt?.status || "queued", duplicate: !!receipt, fields: prepared.fields.length };
}
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (["soc-json/import", "soc-json/status"].includes(message?.type)) {
    if (sender.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id) || !Number.isInteger(sender.tab?.windowId) || !/^https?:\/\//i.test(sender.url || "") || sender.frameId !== 0) return false;
    if (typeof message.requestId !== "string" || !/^[A-Za-z0-9._:-]{1,100}$/.test(message.requestId) || (message.type === "soc-json/import" && (typeof message.data !== "string" || message.data.length > SOCJSON.MAX_CHARACTERS))) return false;
    serializeCapture(() => receiveJSON(message, sender)).then(respond, error => respond({ ok: false, error: error.message === "JSON send ID reused with different data" ? error.message : "JSON not saved. Check the queue or browser storage." }));
    return true;
  }
  if (message?.type === "soc-clipboard/hotkey") {
    if (sender.id !== chrome.runtime.id || !sender.tab || !/^(https?|file):/i.test(sender.url || "")) return false;
    (async () => {
      if (!await isFocused(sender.tab.id)) return { ok: false };
      return captureClipboard(sender.tab);
    })().then(respond, () => respond({ ok: false }));
    return true;
  }
  if (!message || !String(message.type).startsWith("soc-capture/") || sender.id !== chrome.runtime.id || sender.url !== BUILDER_URL || (sender.frameId !== undefined && sender.frameId !== 0)) return false;
  (async () => {
    if (!Number.isInteger(message.tabId) || typeof message.clientId !== "string" || !message.clientId || message.clientId.length > 128) throw Error("Invalid consumer");
    const tab = await chrome.tabs.get(message.tabId);
    const contexts = await chrome.runtime.getContexts({ contextTypes: ["TAB"], documentUrls: [BUILDER_URL] });
    if (!contexts.some(context => context.tabId === tab.id && (!sender.documentId || context.documentId === sender.documentId)) || (sender.tab && sender.tab.id !== tab.id)) throw Error("Invalid consumer tab");
    const owner = { clientId: message.clientId, tabId: tab.id, windowId: tab.windowId };
    if (message.type === "soc-capture/claim-json") {
      if (await jsonConsumer() !== tab.id) return { ok: true, claim: null };
      return { ok: true, claim: await queue.claim(owner, { jsonOnly: true }) };
    }
    if (message.type === "soc-capture/clipboard") {
      if (!await isFocused(tab.id)) return { ok: false, error: "Focus Note Builder to capture the clipboard." };
      return captureClipboard(tab);
    }
    if (message.type === "soc-capture/claim") return { ok: true, claim: await queue.claim(owner) };
    if (message.type === "soc-capture/json-error") return { ok: await queue.reportJSONError(owner, message.token, message.error) };
    if (message.type === "soc-capture/ack") return { ok: await queue.acknowledge(owner, message.token, message.ids) };
    if (message.type === "soc-capture/release") return { ok: await queue.release(owner, message.token) };
    return { ok: false };
  })().then(respond, () => respond({ ok: false, error: "Capture transport unavailable. Pending captures are retained." }));
  return true;
});

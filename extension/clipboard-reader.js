"use strict";
function readClipboardText() {
  const input = document.getElementById("clipboard-input");
  let pasted = null;
  const onPaste = event => {
    if (!event.clipboardData) return;
    pasted = event.clipboardData.getData("text/plain");
    event.preventDefault();
  };
  input.value = "";
  input.focus();
  input.select();
  input.addEventListener("paste", onPaste);
  try {
    // Offscreen documents cannot receive browser focus. With clipboardRead,
    // the extension's local paste command provides plain text without a prompt.
    const pastedNormally = document.execCommand("paste");
    if (!pastedNormally && pasted === null) throw Error("Clipboard read unavailable");
    const text = pasted === null ? input.value : pasted;
    if (text.length > SOCCaptureData.MAX_VALUE) throw Error("Clipboard text too large");
    return text;
  } finally {
    input.removeEventListener("paste", onPaste);
    input.value = "";
  }
}
function writeClipboardText(text) {
  if (typeof text !== "string" || text.length > SOCCaptureData.MAX_VALUE) throw Error("Clipboard text too large");
  const input = document.getElementById("clipboard-input");
  let copied = false;
  const onCopy = event => {
    if (!event.clipboardData) return;
    event.clipboardData.setData("text/plain", text);
    event.preventDefault();
    copied = true;
  };
  input.value = text;
  input.focus();
  input.select();
  input.addEventListener("copy", onCopy);
  try {
    // clipboardWrite permits this one-shot copy in an offscreen document.
    const copiedNormally = document.execCommand("copy");
    if (!copiedNormally && !copied) throw Error("Clipboard copy unavailable");
  } finally {
    input.removeEventListener("copy", onCopy);
    input.value = "";
  }
}
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (message?.target !== "soc-clipboard-reader" || !["read", "write"].includes(message.type)) return false;
  const workerUrl = chrome.runtime.getURL("extension/service-worker.js");
  if (sender.id !== chrome.runtime.id || sender.tab || sender.documentId || (sender.url && sender.url !== workerUrl)) return false;
  if (typeof message.requestId !== "string" || !message.requestId || message.requestId.length > 128) return false;
  try {
    if (message.type === "read") respond({ ok: true, requestId: message.requestId, text: readClipboardText() });
    else {
      writeClipboardText(message.text);
      respond({ ok: true, requestId: message.requestId });
    }
  } catch (error) {
    respond({ ok: false, requestId: message.requestId, error: error.message === "Clipboard text too large" ? error.message : message.type === "read" ? "Clipboard read unavailable" : "Clipboard copy unavailable" });
  }
  return false;
});

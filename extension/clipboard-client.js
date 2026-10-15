"use strict";
globalThis.SOCCaptureClipboard = (() => {
  const PATH = "extension/clipboard-reader.html";
  let tail = Promise.resolve();
  async function requestOnce(type, text) {
    const reading = type === "read";
    if (!reading && (typeof text !== "string" || text.length > SOCCaptureData.MAX_VALUE)) throw Error("Clipboard text too large");
    if (!await chrome.permissions.contains({ permissions: [reading ? "clipboardRead" : "clipboardWrite"] })) throw Error("Clipboard permission unavailable");
    const documentUrl = chrome.runtime.getURL(PATH);
    const contexts = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"], documentUrls: [documentUrl] });
    if (!contexts.length) await chrome.offscreen.createDocument({
      url: PATH, reasons: ["CLIPBOARD"], justification: "Read or copy plain text only when the analyst invokes a capture shortcut."
    });
    let timeout;
    try {
      const requestId = crypto.randomUUID();
      const response = await Promise.race([
        chrome.runtime.sendMessage({ target: "soc-clipboard-reader", type, requestId, ...(reading ? {} : { text }) }),
        new Promise((_, reject) => { timeout = setTimeout(() => reject(Error("Clipboard request timed out")), 5000); })
      ]);
      if (!response?.ok || response.requestId !== requestId) throw Error(response?.error || (reading ? "Clipboard read unavailable" : "Clipboard copy unavailable"));
      if (reading) {
        if (typeof response.text !== "string") throw Error("Clipboard read unavailable");
        if (response.text.length > SOCCaptureData.MAX_VALUE) throw Error("Clipboard text too large");
        return response.text;
      }
    } finally {
      clearTimeout(timeout);
      // Do not retain clipboard text or a polling document after this request.
      await chrome.offscreen.closeDocument().catch(() => {});
    }
  }
  function request(type, text) {
    const operation = tail.then(() => requestOnce(type, text));
    tail = operation.catch(() => {});
    return operation;
  }
  return Object.freeze({ readText: () => request("read"), writeText: text => request("write", text) });
})();

"use strict";
window.SOCNote.extensionBridge = (() => {
  function start({ onImport, onStatus, onError }) {
    if (location.protocol !== "chrome-extension:" || !globalThis.chrome?.runtime?.id) return;
    const clientId = crypto.randomUUID();
    let tabId = null, busy = false;
    const active = () => document.visibilityState === "visible" && document.hasFocus();
    const send = (type, details = {}) => chrome.runtime.sendMessage({ type: "soc-capture/" + type, clientId, tabId, ...details });
    async function drain() {
      if (busy || tabId === null) return;
      busy = true;
      try {
        while (true) {
          let jsonOnly = !active();
          let response = await send(jsonOnly ? "claim-json" : "claim");
          // Some browser windows retain document focus while another OS
          // window is active. The worker owns the final focus decision.
          if (response?.ok && !response.claim && !jsonOnly) {
            jsonOnly = true;
            response = await send("claim-json");
          }
          if (!response?.ok) { onError(response?.error || "Capture import unavailable. Pending captures are retained."); break; }
          const claim = response.claim;
          if (!claim) break;
          if (!jsonOnly && !active()) { await send("release", { token: claim.token }); break; }
          const result = onImport(claim.captures, { background: jsonOnly });
          if (!result.ok) {
            if (claim.captures.some(capture => capture.method === "json")) await send("json-error", { token: claim.token, error: result.error });
            await send("release", { token: claim.token });
            onError(result.error);
            break;
          }
          // onImport returns success only after the draft and receipt IDs are saved.
          const acknowledged = await send("ack", { token: claim.token, ids: result.ids });
          if (!acknowledged?.ok) break;
          onStatus?.();
        }
      } catch { onError("Capture import unavailable. Pending captures are retained."); }
      finally { busy = false; }
    }
    chrome.tabs.getCurrent().then(tab => {
      if (!Number.isInteger(tab?.id)) return;
      tabId = tab.id;
      onStatus?.();
      drain();
    }).catch(() => onError("Capture extension unavailable."));
    window.addEventListener("focus", drain);
    document.addEventListener("visibilitychange", drain);
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "session" && changes["soc-capture.queue.v1"]) drain();
    });
    // Handles expired claims, worker restarts and focus events missed by a browser.
    setInterval(drain, 1500);
  }
  async function captureClipboard() {
    if (location.protocol !== "chrome-extension:" || !globalThis.chrome?.runtime?.id) return { ok: false, error: "Clipboard capture requires the extension." };
    const tab = await chrome.tabs.getCurrent();
    return chrome.runtime.sendMessage({ type: "soc-capture/clipboard", clientId: crypto.randomUUID(), tabId: tab.id });
  }
  return Object.freeze({ start, captureClipboard });
})();

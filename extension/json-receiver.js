"use strict";
// A receiver exists only in a source page explicitly activated by the analyst.
globalThis.installSOCJSONReceiver = function installSOCJSONReceiver() {
  if (globalThis.socJSONReceiver) return;
  const channel = "soc-note-json/v1";
  const handler = async event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== channel || !["send", "status"].includes(event.data.type)) return;
    const { requestId } = event.data;
    if (typeof requestId !== "string" || !/^[A-Za-z0-9._:-]{1,100}$/.test(requestId)) return;
    const respond = result => window.postMessage({ channel, type: "result", requestId, ...result }, location.origin);
    try {
      let data;
      if (event.data.type === "send") {
        data = typeof event.data.data === "string" ? event.data.data : JSON.stringify(event.data.data);
        if (typeof data !== "string" || data.length > 500000) { respond({ ok: false, error: "JSON exceeds 500,000 characters or is missing." }); return; }
      }
      const result = await chrome.runtime.sendMessage({ type: "soc-json/" + (event.data.type === "send" ? "import" : "status"), requestId, ...(data === undefined ? {} : { data }) });
      respond(result || { ok: false, error: "JSON transport unavailable." });
    } catch { respond({ ok: false, error: "JSON transport unavailable. Activate the extension again." }); }
  };
  globalThis.socJSONReceiver = handler;
  window.addEventListener("message", handler);
};

"use strict";
// Installed only in a tab to which the analyst has granted activeTab access.
globalThis.installSOCClipboardShortcut = function installSOCClipboardShortcut() {
  if (globalThis.socClipboardKeyHandler) return;
  const handler = event => {
    if (!event.isTrusted || event.repeat || !event.ctrlKey || !event.altKey || event.shiftKey || event.metaKey || event.key.toLowerCase() !== "x" || event.getModifierState("AltGraph")) return;
    if (!document.hasFocus()) return;
    event.preventDefault();
    event.stopPropagation();
    // Return only a status to this script, never clipboard text to the page.
    chrome.runtime.sendMessage({ type: "soc-clipboard/hotkey" }).catch(() => {});
  };
  globalThis.socClipboardKeyHandler = handler;
  document.addEventListener("keydown", handler, true);
};

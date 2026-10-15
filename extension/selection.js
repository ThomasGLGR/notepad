"use strict";
// A self-contained function injected only after an explicit user gesture.
globalThis.readSOCSelection = function readSOCSelection() {
  // Keep the top document's focus signal even when it has no selected text.
  // Browser UI (including the address bar) is outside window.getSelection().
  const page = { value: "", context: "", title: document.title.slice(0, 200), url: location.href, focused: document.hasFocus() };
  const active = document.activeElement;
  if (active?.tagName === "INPUT" && active.type === "password") return page;
  // A focused frame owns the current selection; do not capture an old selection
  // left in its parent document. Accessible child frames are injected separately.
  if (active && /^(IFRAME|FRAME)$/.test(active.tagName)) return page;
  const selection = window.getSelection();
  let value = selection ? selection.toString() : "";
  let element = selection?.anchorNode?.nodeType === Node.ELEMENT_NODE ? selection.anchorNode : selection?.anchorNode?.parentElement;
  if (active && /^(INPUT|TEXTAREA)$/.test(active.tagName) && active.type !== "password" && typeof active.selectionStart === "number") {
    value = active.value.slice(active.selectionStart, active.selectionEnd);
    element = active;
  }
  if (!value.trim()) return page;
  const short = text => String(text || "").replace(/\s+/g, " ").trim().slice(0, 160);
  let context = short(element?.getAttribute("aria-label"));
  if (!context && element?.labels?.length) context = short(element.labels[0].textContent);
  const cell = element?.closest("td, th");
  if (!context && cell) {
    const table = cell.closest("table");
    const heading = table?.tHead?.rows[table.tHead.rows.length - 1]?.cells[cell.cellIndex] || table?.querySelector("tr")?.querySelectorAll("th")[cell.cellIndex];
    if (heading) context = short(heading.textContent);
  }
  const definition = element?.closest("dd");
  if (!context && definition?.previousElementSibling?.tagName === "DT") context = short(definition.previousElementSibling.textContent);
  if (!context) {
    const label = element?.closest("[aria-label]");
    if (label) context = short(label.getAttribute("aria-label"));
  }
  if (!context && element && !/^(BODY|HTML|MAIN|SECTION|ARTICLE)$/.test(element.tagName)) {
    // Inspect at most five direct text nodes, never the surrounding page tree.
    const nearby = Array.from(element.childNodes).slice(0, 5).filter(node => node.nodeType === Node.TEXT_NODE).map(node => node.textContent.slice(0, 240)).join(" ").slice(0, 240);
    const match = /^\s*([\w ._-]{1,64})\s*[:=]\s*/.exec(nearby);
    if (match) context = short(match[1]);
  }
  return { ...page, value, context };
};

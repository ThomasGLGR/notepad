"use strict";
window.SOCNote.clipboard = (() => {
  function html(source, { report = false } = {}) {
    const output = document.createElement("div");
    // This fixed font style is allowed by its hash in index.html and manifest.json.
    if (report) {
      output.style.fontFamily = "monospace";
      output.style.fontSize = "14px";
      output.style.lineHeight = "1.55";
    }
    // Clipboard consumers do not have this page's CSS. Explicit breaks survive
    // editors that remove styles; inline headings avoid extra block margins.
    function append(parent, node) {
      if (node.nodeType === Node.TEXT_NODE) {
        node.textContent.replace(/\r\n?/g, "\n").split("\n").forEach((line, index, lines) => {
          if (index) parent.append(document.createElement("br"));
          // Preserve indentation without CSS. The plain payload stays untouched.
          // A space next to a link or highlight on the same line is ordinary inline spacing.
          const after = index === 0 && node.previousSibling?.nodeType === Node.ELEMENT_NODE;
          const before = index === lines.length - 1 && node.nextSibling?.nodeType === Node.ELEMENT_NODE;
          const spaced = line.replace(/^ +| +$| {2,}/g, (spaces, offset) => (after && offset === 0) || (before && offset + spaces.length === line.length) ? spaces : "\u00a0".repeat(spaces.length));
          parent.append(document.createTextNode(spaced));
        });
      } else {
        let target = parent;
        if (/^(STRONG|H3|H4)$/.test(node.nodeName)) target = document.createElement("strong");
        else if (node.nodeName === "A" && /^https?:$/.test(node.protocol)) {
          // Rich editors retain link targets, including short labels such as VirusTotal.
          target = document.createElement("a");
          target.setAttribute("href", node.href);
        } else if (node.classList?.contains("report-unknown")) {
          target = document.createElement("font");
          target.setAttribute("color", "#c0392b");
        }
        if (target !== parent) parent.append(target);
        for (const child of node.childNodes) append(target, child);
      }
    }
    for (const node of source.childNodes) append(output, node);
    return "<html><body>" + output.outerHTML + "</body></html>";
  }
  function textHTML(text) {
    const fragment = document.createDocumentFragment();
    fragment.append(document.createTextNode(text));
    return html(fragment);
  }
  return Object.freeze({ html, textHTML });
})();

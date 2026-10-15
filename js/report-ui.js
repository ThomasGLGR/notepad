"use strict";
window.SOCNote.reportUI = (() => {
  function create({ getState }) {
    const root = document.getElementById("final-report-input");
    let lastText = null;
    function element(tag, text, className) {
      const node = document.createElement(tag);
      if (text !== undefined) node.textContent = text;
      if (className) node.className = className;
      return node;
    }
    // References show their address. VirusTotal and MITRE use concise link labels.
    function link(text, href) {
      const node = element("a", text, "report-link");
      node.href = href;
      node.target = "_blank";
      node.rel = "noopener noreferrer";
      return node;
    }
    function refresh() {
      const state = getState();
      const text = window.SOCNote.formatter.format(state);
      if (text === lastText) return;
      lastText = text;
      const scroll = root.scrollTop;
      const fragment = document.createDocumentFragment();
      const title = state.rule.trim();
      const sections = window.SOCNote.formatter.sections(state);
      // Explicit newlines and separators keep preview text, selections and copies equal.
      const { formatter } = window.SOCNote;
      if (title) fragment.append(element("h3", title, "report-title"));
      sections.forEach((section, index) => {
        if (index || title) fragment.append("\n\n");
        const group = element("section", undefined, "report-section");
        group.dataset.reportSection = section.kind;
        const banner = element("span", undefined, "report-banner");
        const heading = element("h4");
        heading.append(element("span", formatter.headingIndent(section.title), "report-heading-indent"), section.title);
        banner.append(element("span", formatter.SEPARATOR, "report-separator"), element("span", "\n", "report-gap"), heading, element("span", "\n", "report-gap"), element("span", formatter.SEPARATOR, "report-separator"));
        group.append(banner, formatter.sectionGap(section));
        const body = element("div", undefined, section.fields ? "report-summary" : "report-text");
        const point = (row, child = false) => { if (body.childNodes.length) body.append(child ? "\n" : "\n\n"); body.append(row); };
        if (section.mitre?.length) {
          const row = element("span", undefined, "report-field report-mitre");
          row.append(element("strong", formatter.MITRE_TITLE), ": ");
          section.mitre.forEach((item, position) => row.append(position ? ", " : "", formatter.mitrePrefix(item), item.href ? link(item.id, item.href) : item.id, ")"));
          point(row);
        }
        for (const field of section.fields || []) {
          const row = element("span", undefined, "report-field");
          // Only the word "Unknown" turns red, until the key or the value is filled in.
          const key = element("strong");
          if (field.prefix) row.append(field.prefix);
          field.key.split(/\b(unknown)\b/i).forEach((part, position) => { if (part) key.append(position % 2 ? element("span", part, "report-unknown") : part); });
          if (field.href) row.append(key, ": ", link(field.value, field.href));
          else if (/^unknown$/i.test(field.value.trim())) row.append(key, ": ", element("span", field.value, "report-unknown"));
          else row.append(key, ": " + field.value);
          row.append(formatter.flagSuffix(field), formatter.timeZoneSuffix(field));
          if (field.virusTotal) row.append(" → ", link("VirusTotal", field.virusTotal));
          if (field.details.length) {
            const details = element("span", undefined, "report-detail");
            field.details.forEach((detail, position, all) => details.append((position ? "\n" : "") + formatter.fieldDetailPrefix(field, detail, position, all), detail.href ? link(detail.value, detail.href) : detail.value));
            row.append("\n", details);
          }
          point(row, field.child);
        }
        if (section.text) body.append(element("span", section.text, "report-section-text"));
        group.append(body);
        fragment.append(group);
      });
      root.replaceChildren(fragment);
      root.scrollTop = scroll;
    }
    const getHTML = (source = root) => window.SOCNote.clipboard.html(source, { report: true });
    const getText = () => window.SOCNote.formatter.format(getState());
    function select() {
      root.focus();
      const range = document.createRange();
      range.selectNodeContents(root);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
    root.addEventListener("copy", event => {
      const selection = window.getSelection();
      if (selection.rangeCount !== 1 || selection.isCollapsed || !event.clipboardData) return;
      const range = selection.getRangeAt(0);
      if (root.contains(range.startContainer) && root.contains(range.endContainer)) {
        event.preventDefault();
        event.clipboardData.setData("text/plain", range.toString());
        event.clipboardData.setData("text/html", getHTML(range.cloneContents()));
      }
    });
    const api = Object.freeze({ refresh, select, getHTML, getText });
    window.SOCNote.report = api;
    return api;
  }
  return Object.freeze({ create });
})();

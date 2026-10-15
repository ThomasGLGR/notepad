"use strict";
window.SOCNote.formatter = (() => {
  const body = document => window.SOCNote.pairs.format(document);
  const summaryValues = document => window.SOCNote.pairs.values(document);
  const MITRE_TITLE = "MITRE ATT&CK";
  const SEPARATOR = "=".repeat(50);
  const headingIndent = title => " ".repeat(Math.max(0, Math.floor((SEPARATOR.length - title.length) / 2)));
  const sectionHeading = title => SEPARATOR + "\n" + headingIndent(title) + title + "\n" + SEPARATOR;
  const sectionGap = () => "\n\n";
  function sections(document) {
    const result = [];
    // MITRE references open the Summary, ahead of the IOC and technical values.
    const mitre = window.SOCNote.mitre ? (document.mitreTechniques || []).map(item => ({ id: item.id, name: item.name, href: window.SOCNote.mitre.url(item.id) })) : [];
    const records = window.SOCNote.pairs.ordered(document.variables);
    if (mitre.length || records.length) result.push({ kind: "summary", title: "SUMMARY", mitre, fields: records.map((record, index) => {
      const value = window.SOCNote.pairs.displayValue(record);
      const prefix = record.parentId ? (records[index + 1]?.parentId === record.parentId ? "├── " : "└── ") : "";
      const entities = window.SOCNote.entities;
      const details = (entities?.details(record, value) || []).filter(detail => detail.label !== entities.labels.virusTotal && detail.label !== entities.labels.domain);
      return { key: window.SOCNote.pairs.keys(record).join(" / "), value, flag: window.SOCNote.pairs.reportFlag(record), timeZone: window.SOCNote.pairs.reportTimeZone(record), prefix, child: Boolean(record.parentId), href: entities?.reference(record, value) || null, virusTotal: record.hideVirusTotal === true ? null : entities?.link(record) || null, details };
    }) });
    const remediations = window.SOCNote.features?.remediation && window.SOCNote.remediationEngine?.format(document) || "";
    if (remediations) result.push({ kind: "remediation", title: "REMEDIATION", text: remediations });
    const analysis = (document.analysis || "").replace(/\r\n?/g, "\n").trim();
    if (analysis) result.push({ kind: "analysis", title: "ANALYSIS", text: analysis });
    return result;
  }
  // Details hang under their value: "├── Country     : NL 🇳🇱".
  const branch = (index, all) => index === all.length - 1 ? "└── " : "├── ";
  const detailPrefix = (detail, index, all) => branch(index, all) + detail.label.padEnd(12) + ": ";
  const fieldDetailPrefix = (field, detail, index, all) => (field.child ? (field.prefix.startsWith("├") ? "│   " : "    ") : "") + detailPrefix(detail, index, all);
  const detailLines = field => (field.details || []).map((detail, index, all) => fieldDetailPrefix(field, detail, index, all) + detail.value);
  const mitrePrefix = item => (item.name ? item.name + " " : "") + "(";
  const flagSuffix = field => field.flag ? " " + field.flag : "";
  const virusTotalSuffix = field => field.virusTotal ? " → VirusTotal" : "";
  const timeZoneSuffix = field => field.timeZone ? " (" + field.timeZone + ")" : "";
  const mitreValues = section => (section.mitre || []).map(item => mitrePrefix(item) + item.id + ")").join(", ");
  // One plain-text representation is used by the preview and clipboard. Sections and
  // Summary points are one blank line apart; a value keeps its own details right under it.
  function format(document) {
    const content = sections(document).map(section => {
      const points = [];
      for (const field of section.fields || []) {
        const text = [field.prefix + field.key + ": " + field.value + flagSuffix(field) + timeZoneSuffix(field) + virusTotalSuffix(field), ...detailLines(field)].join("\n");
        if (field.child && points.length) points[points.length - 1] += "\n" + text;
        else points.push(text);
      }
      if (section.text) points.push(section.text);
      if (section.mitre?.length) points.unshift(MITRE_TITLE + ": " + mitreValues(section));
      return sectionHeading(section.title) + sectionGap(section) + points.join("\n\n");
    }).join("\n\n");
    const title = (document.rule || "").trim();
    return title + (title && content ? "\n\n" : "") + content;
  }
  return Object.freeze({ MITRE_TITLE, SEPARATOR, headingIndent, sectionHeading, sectionGap, body, summaryValues, sections, branch, detailPrefix, fieldDetailPrefix, detailLines, mitrePrefix, flagSuffix, virusTotalSuffix, timeZoneSuffix, format });
})();

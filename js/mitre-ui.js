"use strict";
// MITRE ATT&CK tactic and technique selection beside the Rule: stored with the
// investigation and written at the start of the report's Summary.
window.SOCNote.mitre = (() => {
  const ID = /^T(?:A\d{4}|\d{4}(?:\.\d{3})?)$/;
  const isTactic = item => item.id.startsWith("TA");
  const MAX_SELECTED = 100, MAX_NAME = 200, MAX_SUGGESTIONS = 8;
  let names = null;
  function catalog() {
    names ??= new Map([...(window.SOCNote.mitreData?.tactics || []), ...(window.SOCNote.mitreData?.techniques || [])]);
    return names;
  }
  const label = item => item.id + (item.name ? " - " + item.name : "");
  function validate(value) {
    if (!Array.isArray(value) || value.length > MAX_SELECTED) return null;
    const ids = new Set(), clean = [];
    for (const item of value) {
      if (!item || typeof item.id !== "string" || !ID.test(item.id) || typeof item.name !== "string" || item.name.length > MAX_NAME || /[\r\n]/.test(item.name) || ids.has(item.id)) return null;
      ids.add(item.id);
      clean.push({ id: item.id, name: item.name });
    }
    return clean;
  }
  // "T1059", "t1059.001, TA0006" or "T1999 - Internal name" for an ID outside the catalogue.
  function parse(text) {
    const ids = [...new Set((String(text).match(/\bT(?:A\d{4}|\d{4}(?:\.\d{3})?)\b/gi) || []).map(id => id.toUpperCase()))];
    const custom = ids.length === 1 ? /^\s*T(?:A\d{4}|\d{4}(?:\.\d{3})?)\s*[-–:]\s*(\S.*)$/i.exec(text)?.[1].trim().slice(0, MAX_NAME) : "";
    return ids.map(id => ({ id, name: catalog().get(id) || custom || "" }));
  }
  function search(query, selected = []) {
    const words = query.toLowerCase().split(/[\s,;-]+/).filter(Boolean);
    if (!words.length) return [];
    const taken = new Set(selected.map(item => item.id));
    const found = [];
    for (const [id, name] of catalog()) {
      if (taken.has(id)) continue;
      const text = (id + " " + name).toLowerCase();
      if (words.every(word => text.includes(word))) found.push({ id, name, rank: text.startsWith(words[0]) || text.slice(1).startsWith(words[0]) ? 0 : 1 });
    }
    return found.sort((left, right) => left.rank - right.rank).slice(0, MAX_SUGGESTIONS).map(({ id, name }) => ({ id, name }));
  }
  function add(document, items) {
    const current = document.mitreTechniques || [], ids = new Set(current.map(item => item.id));
    const fresh = items.filter(item => ID.test(item.id) && !ids.has(item.id) && ids.add(item.id)).map(item => ({ id: item.id, name: item.name }));
    if (current.length + fresh.length > MAX_SELECTED) return { ok: false, error: "Technique limit reached." };
    // Tactics lead, as in the matrix; each group keeps the order of selection.
    const all = [...current, ...fresh];
    document.mitreTechniques = [...all.filter(isTactic), ...all.filter(item => !isTactic(item))];
    return { ok: true, count: fresh.length };
  }
  function remove(document, id) {
    document.mitreTechniques = (document.mitreTechniques || []).filter(item => item.id !== id);
  }
  // Official page of a tactic or technique from the bundled list. Other IDs have none.
  function url(id) {
    if (!catalog().has(id)) return null;
    return "https://attack.mitre.org/" + (id.startsWith("TA") ? "tactics/" + id : "techniques/" + id.replace(".", "/")) + "/";
  }

  function create({ getState, change, toast }) {
    const $ = id => document.getElementById(id);
    function element(tag, text, className) {
      const node = document.createElement(tag);
      if (text !== undefined) node.textContent = text;
      if (className) node.className = className;
      return node;
    }
    const input = $("mitre-input"), list = $("mitre-options"), chips = $("mitre-selected");
    const tacticsButton = $("mitre-tactics-button"), tacticsPanel = $("mitre-tactics");
    // The base tactics, one click each, for an alert that is not yet narrowed to a technique.
    tacticsPanel.append(...(window.SOCNote.mitreData?.tactics || []).map(([id, name]) => {
      const button = element("button", undefined, "mitre-tactic");
      button.type = "button";
      button.dataset.tactic = id;
      button.setAttribute("aria-pressed", "false");
      button.append(element("strong", id), " " + name);
      return button;
    }));
    function showTactics(open) {
      tacticsPanel.hidden = !open;
      tacticsButton.setAttribute("aria-expanded", String(open));
    }
    let signature = null, options = [], active = -1;
    const selected = () => getState().mitreTechniques || [];
    function refresh() {
      const next = JSON.stringify(selected());
      if (next === signature) return;
      signature = next;
      const chosen = new Set(selected().map(item => item.id));
      for (const button of tacticsPanel.children) button.setAttribute("aria-pressed", String(chosen.has(button.dataset.tactic)));
      chips.replaceChildren(...selected().map(item => {
        const chip = element("span", undefined, "mitre-chip");
        chip.setAttribute("role", "listitem");
        chip.title = label(item);
        chip.dataset.technique = item.id;
        const remove = element("button", "×");
        remove.type = "button";
        remove.dataset.removeTechnique = item.id;
        remove.title = "Remove " + item.id;
        remove.setAttribute("aria-label", "Remove " + label(item));
        chip.append(element("strong", item.id), element("span", item.name, "mitre-chip-name"), remove);
        return chip;
      }));
      if (document.activeElement === input) suggest();
    }
    function highlight(index) {
      active = index;
      Array.from(list.children).forEach((node, position) => node.setAttribute("aria-selected", String(position === active)));
      if (active >= 0) { input.setAttribute("aria-activedescendant", list.children[active].id); list.children[active].scrollIntoView({ block: "nearest" }); }
      else input.removeAttribute("aria-activedescendant");
    }
    function close() {
      options = [];
      list.hidden = true;
      list.replaceChildren();
      input.setAttribute("aria-expanded", "false");
      highlight(-1);
    }
    function suggest() {
      options = search(input.value, selected());
      if (!options.length) { close(); return; }
      list.replaceChildren(...options.map((item, index) => {
        const option = element("li", undefined, "mitre-option");
        option.id = "mitre-option-" + index;
        option.setAttribute("role", "option");
        option.dataset.index = index;
        option.append(element("strong", item.id), " " + item.name);
        return option;
      }));
      list.hidden = false;
      input.setAttribute("aria-expanded", "true");
      highlight(-1);
    }
    function choose(items) {
      if (!items.length) { toast("Pick a technique from the list, or type an ID such as T1059."); return; }
      let result;
      change("MITRE techniques", document => { result = add(document, items); });
      if (!result.ok) { toast(result.error); return; }
      if (!result.count) toast("Already selected");
      input.value = "";
      close();
    }
    input.addEventListener("input", suggest);
    input.addEventListener("focus", suggest);
    input.addEventListener("blur", close);
    input.addEventListener("keydown", event => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        if (!options.length) return;
        event.preventDefault();
        const step = event.key === "ArrowDown" ? 1 : -1;
        highlight(active < 0 ? (step > 0 ? 0 : options.length - 1) : (active + step + options.length) % options.length);
      } else if (event.key === "Enter") {
        if (!input.value.trim()) return;
        event.preventDefault();
        // The highlighted option, then typed IDs, then the best match.
        const typed = parse(input.value);
        choose(active >= 0 ? [options[active]] : typed.length ? typed : options.slice(0, 1));
      } else if (event.key === "Escape" && !list.hidden) {
        event.preventDefault();
        close();
      } else if (event.key === "Backspace" && !input.value && selected().length) {
        const last = selected().at(-1).id;
        change("MITRE technique removal", document => remove(document, last));
      }
    });
    // Keep the field focused while an option is clicked.
    list.addEventListener("mousedown", event => event.preventDefault());
    list.addEventListener("click", event => {
      const option = event.target.closest("[data-index]");
      if (option) { choose([options[Number(option.dataset.index)]]); input.focus(); }
    });
    chips.addEventListener("click", event => {
      const id = event.target.closest("[data-remove-technique]")?.dataset.removeTechnique;
      if (!id) return;
      change("MITRE technique removal", document => remove(document, id));
      input.focus();
    });
    tacticsButton.addEventListener("click", () => showTactics(tacticsPanel.hidden));
    tacticsPanel.addEventListener("click", event => {
      const id = event.target.closest("[data-tactic]")?.dataset.tactic;
      if (!id) return;
      if (selected().some(item => item.id === id)) change("MITRE tactic removal", document => remove(document, id));
      else change("MITRE tactics", document => { add(document, [{ id, name: catalog().get(id) || "" }]); });
    });
    document.addEventListener("click", event => {
      if (!tacticsPanel.hidden && !event.target.closest("#mitre-tactics, #mitre-tactics-button")) showTactics(false);
    });
    document.addEventListener("keydown", event => {
      if (event.key !== "Escape" || tacticsPanel.hidden) return;
      showTactics(false);
      tacticsButton.focus();
    });
    return Object.freeze({ refresh });
  }
  return Object.freeze({ ID, validate, parse, search, add, remove, label, url, create });
})();

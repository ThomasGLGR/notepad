"use strict";
window.SOCNote.remediationUI = (() => {
  function create({ getState, change, copyText, toast, focus, syncSource, onCatalogChange }) {
    const { remediationData: data, remediationEngine: engine, remediationStorage: storage, templates } = window.SOCNote;
    const $ = id => document.getElementById(id);
    const loaded = storage.load();
    let catalog = getState().remediationCatalog ? JSON.parse(JSON.stringify(getState().remediationCatalog)) : loaded.catalog.length ? loaded.catalog : data.defaults();
    const persist = loaded.enabled;
    let editor = null, version = 0, renderedVersion = -1;
    let recommendationSignature = "", activeSignature = "", selectedSignature = "";
    const collapsed = new Set();
    const session = () => getState().remediation;
    const findTactic = id => catalog.find(tactic => tactic.id === id);
    const findItem = id => {
      for (const tactic of catalog) {
        const item = tactic.remediations.find(item => item.id === id);
        if (item) return { tactic, item };
      }
      return null;
    };
    function element(tag, text, className) {
      const node = document.createElement(tag);
      if (text !== undefined) node.textContent = text;
      if (className) node.className = className;
      return node;
    }
    function button(label, action, id, title) {
      const node = element("button", label);
      node.type = "button";
      Object.assign(node.dataset, { action, id, focusKey: action + ":" + id });
      if (title) { node.title = title; node.setAttribute("aria-label", title); }
      return node;
    }
    function withFocus(container, render) {
      const active = document.activeElement;
      const key = container.contains(active) ? active.dataset.focusKey : null;
      render();
      if (key) {
        const replacement = Array.from(container.querySelectorAll("[data-focus-key]")).find(node => node.dataset.focusKey === key);
        if (replacement) replacement.focus({ preventScroll: true });
      }
    }
    function saveCatalog() {
      // Honor an existing opt-in without exposing catalogue settings in the workspace.
      if (persist) {
        const result = storage.save(catalog);
        if (!result.ok) toast(result.error);
      }
    }
    function modifyCatalog(mutate) {
      const before = JSON.stringify(catalog);
      mutate();
      if (before === JSON.stringify(catalog)) return;
      version += 1;
      saveCatalog();
      onCatalogChange?.(JSON.parse(JSON.stringify(catalog)));
      refresh();
    }
    function tacticOptions(select, placeholder) {
      const fragment = document.createDocumentFragment();
      if (placeholder) {
        const option = element("option", placeholder);
        option.value = "";
        fragment.append(option);
      }
      for (const tactic of catalog) {
        const option = element("option", tactic.name);
        option.value = tactic.id;
        fragment.append(option);
      }
      select.replaceChildren(fragment);
    }
    function setActiveTactics(ids) {
      if (!Array.isArray(ids)) throw new TypeError("setActiveTactics expects an array of tactic IDs.");
      const active = [...new Set(ids.filter(id => findTactic(id)))];
      active.forEach(id => collapsed.delete(id));
      change("remediation tactics", document => { document.remediation.activeTactics = active; });
      // Opening a collapsed category also works if the active IDs did not change.
      recommendationSignature = "";
      refresh();
    }
    function choose(id, checked) {
      const found = findItem(id);
      if (!found || !found.item.enabled) return;
      change("remediation selection", document => {
        const selected = document.remediation.selected;
        if (checked && !selected.some(item => item.id === id)) {
          const { tactic, item } = found;
          selected.push({ id, tacticId: tactic.id, tacticName: tactic.name, template: item.template, generic: item.generic, text: null });
        } else if (!checked) document.remediation.selected = selected.filter(item => item.id !== id);
      });
    }
    function row(tactic, item, prefix) {
      const node = element("div", undefined, "remediation-option" + (item.enabled ? "" : " remediation-disabled"));
      const label = element("label", undefined, "remediation-check");
      const checkbox = element("input");
      checkbox.type = "checkbox";
      checkbox.checked = session().selected.some(selected => selected.id === item.id);
      checkbox.disabled = !item.enabled;
      Object.assign(checkbox.dataset, { choose: item.id, focusKey: prefix + ":choose:" + item.id });
      const resolved = engine.resolve(item.template, getState(), item.generic);
      const phrase = element("span", resolved.text);
      phrase.title = resolved.missing.length ? "Missing values: " + resolved.missing.join(", ") + ". Generic wording available." : item.template;
      label.append(checkbox, phrase);
      const favorite = button(item.favorite ? "★" : "☆", "favorite", item.id, (item.favorite ? "Remove from favorites: " : "Add to favorites: ") + item.template);
      favorite.dataset.focusKey = prefix + ":favorite:" + item.id;
      favorite.className = "remediation-favorite";
      favorite.setAttribute("aria-pressed", String(item.favorite));
      node.append(label, favorite);
      return node;
    }
    function matches(tactic, item, terms) {
      const text = engine.normalize([tactic.name, item.template, item.generic, engine.resolve(item.template, getState(), item.generic).text].join(" "));
      return terms.every(term => text.includes(term));
    }
    function renderRecommendations() {
      const root = $("remediation-recommendations");
      withFocus(root, () => {
        const fragment = document.createDocumentFragment();
        const terms = engine.normalize($("remediation-search").value).split("_").filter(Boolean);
        const sortFavorites = items => [...items].sort((a, b) => Number(b.favorite) - Number(a.favorite));
        {
          const favorites = catalog.flatMap(tactic => tactic.remediations.filter(item => item.favorite && item.enabled && matches(tactic, item, terms)).map(item => ({ tactic, item })));
          if (favorites.length) {
            const group = element("details", undefined, "remediation-group");
            group.open = !collapsed.has("favorites");
            group.append(element("summary", "Favorites (" + favorites.length + ")"));
            favorites.forEach(({ tactic, item }) => group.append(row(tactic, item, "favorites")));
            group.addEventListener("toggle", () => { if (group.isConnected) group.open ? collapsed.delete("favorites") : collapsed.add("favorites"); });
            fragment.append(group);
          }
        }
        let total = 0;
        for (const tactic of catalog) {
          if (!terms.length && !session().activeTactics.includes(tactic.id)) continue;
          const items = sortFavorites(tactic.remediations.filter(item => item.enabled && matches(tactic, item, terms)));
          if (terms.length && !items.length) continue;
          total += items.length;
          const group = element("details", undefined, "remediation-group");
          group.dataset.tacticGroup = tactic.id;
          group.open = !!terms.length || (session().activeTactics.includes(tactic.id) && !collapsed.has(tactic.id));
          const summary = element("summary", tactic.name + " (" + items.length + ")");
          group.append(summary);
          items.forEach(item => group.append(row(tactic, item, tactic.id)));
          if (!items.length) group.append(element("p", "No actions", "empty-message"));
          group.addEventListener("toggle", () => { if (group.isConnected) group.open ? collapsed.delete(tactic.id) : collapsed.add(tactic.id); });
          fragment.append(group);
        }
        if (!total) fragment.append(element("p", terms.length ? "No matches" : "Choose a tactic", "empty-message"));
        root.replaceChildren(fragment);
      });
    }
    function renderActive() {
      const root = $("remediation-active-tactics");
      withFocus(root, () => {
        root.replaceChildren(...session().activeTactics.filter(id => findTactic(id)).map(id => {
          const name = findTactic(id).name;
          return button(name + " ×", "remove-tactic", id, "Hide tactic: " + name + ". Selected actions are retained.");
        }));
      });
    }
    function renderSelected() {
      const root = $("remediation-selected");
      const selected = session().selected;
      const signature = JSON.stringify(selected.map(item => item.id));
      if (signature !== selectedSignature) {
        selectedSignature = signature;
        withFocus(root, () => {
          const fragment = document.createDocumentFragment();
          if (!selected.length) fragment.append(element("p", "No actions", "empty-message"));
          selected.forEach((item, index) => {
            const node = element("div", undefined, "remediation-selected-row");
            const label = element("label", (index + 1) + ". " + item.tacticName);
            const text = element("textarea");
            text.rows = 2;
            text.maxLength = 10000;
            text.spellcheck = false;
            text.setAttribute("aria-label", "Remediation text " + (index + 1));
            text.value = engine.selectedText(item, getState());
            Object.assign(text.dataset, { selectedText: item.id, focusKey: "selected:" + item.id });
            label.append(text);
            const tools = element("div", undefined, "remediation-actions");
            const up = button("↑", "selected-up", item.id, "Move selected remediation up");
            const down = button("↓", "selected-down", item.id, "Move selected remediation down");
            up.disabled = index === 0;
            down.disabled = index === selected.length - 1;
            tools.append(button("Remove", "remove-selected", item.id), up, down, button("Reset", "reset-selected", item.id, "Reset action text"), button("Template", "save-selected", item.id, "Save as template"));
            node.append(label, tools);
            fragment.append(node);
          });
          root.replaceChildren(fragment);
        });
      }
      for (const input of root.querySelectorAll("[data-selected-text]")) {
        const item = selected.find(item => item.id === input.dataset.selectedText);
        const value = engine.selectedText(item, getState());
        // Preserve native typing, while allowing Undo to replace an active field.
        if ((document.activeElement !== input || item.text !== input.value) && input.value !== value) input.value = value;
        const reset = input.closest(".remediation-selected-row").querySelector('[data-action="reset-selected"]');
        reset.disabled = item.text === null;
      }
      $("copy-remediations-button").disabled = !engine.format(getState());
    }
    function refresh() {
      if (renderedVersion !== version) {
        renderedVersion = version;
        const editValue = $("remediation-edit-tactic").value;
        tacticOptions($("remediation-tactic"), "Choose a tactic");
        tacticOptions($("remediation-edit-tactic"));
        if (findTactic(editValue)) $("remediation-edit-tactic").value = editValue;
      }
      const active = JSON.stringify([session().activeTactics, version]);
      if (active !== activeSignature) { activeSignature = active; renderActive(); }
      const signature = JSON.stringify([version, $("remediation-search").value, session().activeTactics, session().selected.map(item => item.id), getState().variables]);
      if (signature !== recommendationSignature) { recommendationSignature = signature; renderRecommendations(); }
      renderSelected();
    }
    function openEditor({ tacticId, item = null, selected = null }) {
      editor = { id: item?.id || null };
      $("remediation-edit-heading").textContent = selected ? "Save as template" : item ? "Edit template" : "New action";
      $("remediation-edit-tactic").value = tacticId;
      $("remediation-edit-tactic").disabled = !!item;
      $("remediation-edit-template").value = selected ? (selected.text === null ? selected.template : selected.text) : item?.template || "";
      $("remediation-edit-generic").value = item?.generic || "";
      $("remediation-model-help").hidden = !selected;
      $("remediation-edit-form").hidden = false;
      $("remediation-edit-template").focus();
    }
    function closeEditor() {
      editor = null;
      $("remediation-edit-form").hidden = true;
      $("remediation-edit-template").value = "";
      $("remediation-edit-generic").value = "";
    }
    function move(array, item, direction) {
      const index = array.indexOf(item), next = index + direction;
      if (index < 0 || next < 0 || next >= array.length) return;
      [array[index], array[next]] = [array[next], array[index]];
    }
    function handleAction(event) {
      const target = event.target.closest("button[data-action]");
      if (!target) return;
      const { action, id } = target.dataset;
      if (action === "remove-tactic") { setActiveTactics(session().activeTactics.filter(value => value !== id)); return; }
      if (["selected-up", "selected-down", "remove-selected", "reset-selected", "save-selected"].includes(action)) {
        const selected = session().selected.find(item => item.id === id);
        if (!selected) return;
        if (action === "save-selected") {
          const found = findItem(id);
          openEditor({ tacticId: found?.tactic.id || selected.tacticId, item: found?.item, selected });
          return;
        }
        change("remediation edit", document => {
          const items = document.remediation.selected;
          if (action === "remove-selected") document.remediation.selected = items.filter(item => item.id !== id);
          else if (action === "reset-selected") selected.text = null;
          else move(items, selected, action === "selected-up" ? -1 : 1);
        });
        return;
      }
      const found = findItem(id);
      if (!found) return;
      const { item } = found;
      modifyCatalog(() => {
        if (action === "favorite") item.favorite = !item.favorite;
      });
    }
    $("remediation-panel").addEventListener("click", handleAction);
    $("remediation-recommendations").addEventListener("change", event => {
      if (event.target.dataset.choose) choose(event.target.dataset.choose, event.target.checked);
    });
    $("remediation-selected").addEventListener("input", event => {
      const id = event.target.dataset.selectedText;
      if (!id) return;
      change("remediation text", document => {
        const item = document.remediation.selected.find(item => item.id === id);
        if (item) item.text = event.target.value;
      }, { key: "remediation:" + id });
    });
    $("remediation-search").addEventListener("input", refresh);
    $("remediation-tactic").addEventListener("change", event => {
      if (event.target.value) setActiveTactics([...session().activeTactics, event.target.value]);
      event.target.value = "";
    });
    $("add-remediation-button").addEventListener("click", () => {
      openEditor({ tacticId: session().activeTactics.at(-1) || catalog[0].id });
    });
    $("remediation-cancel-edit").addEventListener("click", () => { closeEditor(); $("add-remediation-button").focus(); });
    $("remediation-edit-form").addEventListener("submit", event => {
      event.preventDefault();
      const tactic = findTactic($("remediation-edit-tactic").value);
      const template = $("remediation-edit-template").value.trim();
      if (!tactic || !template || !editor) return;
      const generic = $("remediation-edit-generic").value.trim();
      if (/\{[^{}]+\}/.test(generic)) { toast("Generic wording must work without variables."); return; }
      const found = editor.id ? findItem(editor.id) : null;
      closeEditor();
      modifyCatalog(() => {
        if (found) { found.item.template = template; found.item.generic = generic; }
        else tactic.remediations.push({ id: "custom-" + templates.createId(), template, generic, origin: "custom", enabled: true, favorite: false });
      });
      setActiveTactics([...session().activeTactics, tactic.id]);
      toast("Template saved");
      $("add-remediation-button").focus();
    });
    function copy() { syncSource(); copyText(engine.format(getState())); }
    $("copy-remediations-button").addEventListener("click", copy);
    function getTactics() {
      const ids = [...new Set([...session().activeTactics, ...session().selected.map(item => item.tacticId)])];
      return ids.map(id => {
        const tactic = findTactic(id);
        const selected = session().selected.find(item => item.tacticId === id);
        return { id, name: tactic?.name || selected?.tacticName || "", mitreId: tactic?.mitreId || "" };
      }).filter(tactic => tactic.name);
    }
    window.SOCNote.remediation = Object.freeze({ setActiveTactics, getTactics });
    if (loaded.error) toast(loaded.error);
    return Object.freeze({ refresh, copy, focus, setActiveTactics, getTactics, getCatalog: () => JSON.parse(JSON.stringify(catalog)) });
  }
  return Object.freeze({ create });
})();

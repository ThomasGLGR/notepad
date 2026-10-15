"use strict";
window.SOCNote.summaryEditor = (() => {
  function create({ getState, change, copyText, toast }) {
    const { pairs, formatter, entities } = window.SOCNote;
    const MAX_HASH_BYTES = 512 * 1024 * 1024;
    const SERVICE_NOW_URL = "https://CHANGEME";
    const $ = id => document.getElementById(id);
    const root = $("report-input"), form = $("summary-add-variable-form");
    const formHome = form.parentNode;
    let signature = "", dragging = null, addingParent = null;
    let hoverPoint = null, scrollFrame = null;
    const baselines = new WeakMap();
    const find = id => getState().variables.find(record => record.id === id);
    function element(tag, text, className) {
      const node = document.createElement(tag);
      if (text !== undefined) node.textContent = text;
      if (className) node.className = className;
      return node;
    }
    const insertionLine = element("div", undefined, "summary-drop-indicator");
    insertionLine.setAttribute("aria-hidden", "true");
    insertionLine.setAttribute("role", "presentation");
    function button(text, action, id, label) {
      const node = element("button", text);
      node.type = "button";
      node.dataset.pairAction = action;
      node.dataset.id = id;
      node.title = label;
      node.setAttribute("aria-label", label);
      return node;
    }
    function eyeIcon() {
      const ns = "http://www.w3.org/2000/svg";
      const icon = document.createElementNS(ns, "svg");
      icon.setAttribute("viewBox", "0 0 24 24");
      icon.setAttribute("fill", "none");
      icon.setAttribute("stroke", "currentColor");
      icon.setAttribute("stroke-width", "1.8");
      icon.setAttribute("stroke-linecap", "round");
      icon.setAttribute("stroke-linejoin", "round");
      icon.setAttribute("aria-hidden", "true");
      icon.setAttribute("focusable", "false");
      const outline = document.createElementNS(ns, "path");
      outline.setAttribute("d", "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z");
      const pupil = document.createElementNS(ns, "circle");
      pupil.setAttribute("cx", "12");
      pupil.setAttribute("cy", "12");
      pupil.setAttribute("r", "3");
      const slash = document.createElementNS(ns, "path");
      slash.setAttribute("d", "M3 3 21 21");
      slash.classList.add("entity-vt-eye-slash");
      icon.append(outline, pupil, slash);
      return icon;
    }
    function row(record, index) {
      const node = element("div", undefined, "summary-pair" + (record.parentId ? " summary-pair-child" : ""));
      node.setAttribute("role", "listitem");
      node.tabIndex = 0;
      node.draggable = true;
      node.dataset.variableId = record.id;
      if (record.parentId) node.dataset.parentId = record.parentId;
      const title = pairs.keys(record).join(" / ");
      const grip = button("⠿", "focus", record.id, "Drag category " + title);
      grip.className = "summary-pair-grip";
      grip.draggable = true;
      const leading = element("div", undefined, "summary-pair-leading");
      const serviceNow = element("a", undefined, "entity-servicenow");
      serviceNow.target = "_blank";
      serviceNow.rel = "noopener noreferrer";
      serviceNow.draggable = false;
      serviceNow.dataset.serviceNow = record.id;
      leading.append(grip);
      if (!record.parentId) {
        const add = button("+", "add-child", record.id, "Add a subcategory to " + title);
        add.className = "summary-add-child";
        leading.append(add);
      }
      const heading = element("div", undefined, "summary-pair-heading");
      const key = element("input", undefined, "summary-pair-key");
      key.type = "text";
      key.value = title;
      key.dataset.variableKey = record.id;
      key.setAttribute("aria-label", "Edit the title for category " + (index + 1));
      key.title = "For several keys sharing a value, separate the keys with /";
      key.maxLength = 300;
      key.spellcheck = false;
      key.readOnly = record.origin === "mitre";
      // The editor uses the bundled PNG; the report has the text link and arrow.
      const link = element("a", undefined, "entity-vt");
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.draggable = false;
      link.dataset.entityVt = "";
      const vtControls = element("div", undefined, "entity-vt-controls");
      const visibility = button(undefined, "vt-visibility", record.id, "Hide VirusTotal link in report");
      visibility.className = "entity-vt-visibility";
      visibility.dataset.entityVtVisibility = record.id;
      visibility.append(eyeIcon());
      vtControls.append(link, visibility);
      // A country code shows its flag, with the same report visibility eye as VirusTotal.
      const flagControls = element("div", undefined, "entity-vt-controls entity-flag-controls");
      const flag = element("span", undefined, "entity-flag");
      flag.dataset.entityFlag = record.id;
      flag.setAttribute("role", "img");
      const flagVisibility = button(undefined, "flag-visibility", record.id, "Hide flag in report");
      flagVisibility.className = "entity-vt-visibility";
      flagVisibility.dataset.entityFlagVisibility = record.id;
      flagVisibility.append(eyeIcon());
      flagControls.append(flag, flagVisibility);
      heading.append(key);
      const separator = element("span", ":", "summary-pair-separator");
      separator.setAttribute("aria-hidden", "true");
      const multiline = /[\r\n]/.test(record.value);
      const value = element(multiline ? "textarea" : "input", undefined, "summary-pair-value");
      if (multiline) value.rows = 3;
      else value.type = "text";
      value.value = pairs.displayValue(record);
      value.dataset.variableValue = record.id;
      value.setAttribute("aria-label", "Edit the value for " + title);
      value.maxLength = 10000;
      value.spellcheck = false;
      value.readOnly = record.origin === "mitre";
      const actions = element("div", undefined, "summary-pair-actions");
      const copy = button("⧉", "copy", record.id, "Copy only the value for " + title);
      copy.dataset.copyVariable = record.id;
      actions.append(vtControls, flagControls);
      actions.append(serviceNow, copy);
      if (record.origin !== "mitre") actions.append(button("×", "remove", record.id, "Remove category " + title));
      node.append(leading, heading, separator, value, actions);
      const urlOption = button("DFN", "defang", record.id, "Defanged URL for " + title);
      urlOption.className = "summary-url-option";
      urlOption.title = "Defanged URL";
      urlOption.dataset.defangUrl = record.id;
      urlOption.setAttribute("aria-pressed", String(record.defangUrl === true));
      actions.prepend(urlOption);
      const timeZoneControls = element("div", undefined, "summary-timezone-controls");
      const timeZone = element("select", undefined, "summary-timezone-select");
      timeZone.dataset.timeZone = record.id;
      timeZone.setAttribute("aria-label", "Time zone for " + title);
      timeZone.title = "Time zone in report";
      timeZoneControls.append(timeZone);
      actions.prepend(timeZoneControls);
      return node;
    }
    function refreshLink(node, record) {
      const serviceNow = node.querySelector("[data-service-now]");
      serviceNow.href = SERVICE_NOW_URL + "?" + new URLSearchParams({ value: record.value });
      serviceNow.title = "Open " + pairs.keys(record).join(" / ") + " in ServiceNow";
      serviceNow.setAttribute("aria-label", serviceNow.title);
      const href = entities.link(record), link = node.querySelector("[data-entity-vt]");
      link.hidden = !href;
      link.parentNode.hidden = !href;
      if (href) link.href = href;
      else link.removeAttribute("href");
      link.title = "VirusTotal report for " + pairs.keys(record).join(" / ") + " (new tab)";
      link.setAttribute("aria-label", link.title);
      const visibility = node.querySelector("[data-entity-vt-visibility]");
      const visible = record.hideVirusTotal !== true;
      visibility.setAttribute("aria-pressed", String(visible));
      visibility.title = (visible ? "Hide" : "Show") + " VirusTotal link in report";
      visibility.setAttribute("aria-label", visibility.title);
      const code = pairs.countryCode(record), flag = node.querySelector("[data-entity-flag]");
      flag.parentNode.hidden = !code;
      flag.textContent = pairs.countryFlag(record);
      flag.title = code ? (window.SOCNote.country?.name(code) || code) + " flag" : "";
      flag.setAttribute("aria-label", flag.title);
      const flagVisibility = node.querySelector("[data-entity-flag-visibility]");
      const flagVisible = record.hideFlag !== true;
      flagVisibility.setAttribute("aria-pressed", String(flagVisible));
      flagVisibility.title = (flagVisible ? "Hide" : "Show") + " flag in report";
      flagVisibility.setAttribute("aria-label", flagVisibility.title);
    }
    async function hashFile(id, file) {
      if (!globalThis.crypto?.subtle) { toast("Local hashing is unavailable in this browser."); return; }
      if (file.size > MAX_HASH_BYTES) { toast("File too large to hash locally (512 MB limit)."); return; }
      let hash;
      try {
        const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
        hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
      } catch { toast("Could not read the file."); return; }
      if (!find(id)) return;
      change("local file hash", document => { pairs.setMeta(document, id, "fileHash", hash); });
      toast("SHA256 computed locally");
    }
    function addFile(file) {
      let id = getState().variables.find(record => record.value === file.name && entities.kind(record) === "file")?.id;
      if (!id) {
        let result;
        change("dropped file", document => { result = pairs.add(document, ["File"], file.name); });
        if (!result?.ok) return null;
        id = result.id;
      }
      hashFile(id, file);
      return id;
    }
    function rowFor(id) { return Array.from(root.querySelectorAll("[data-variable-id]")).find(node => node.dataset.variableId === id); }
    function parkForm() { if (form.parentNode !== formHome) formHome.insertBefore(form, $("summary-drop-status")); }
    function positionForm() {
      if (form.hidden) return;
      const parent = addingParent && find(addingParent);
      if (addingParent && (!parent || parent.parentId)) { closeForm(); return; }
      form.classList.toggle("summary-add-variable-child", Boolean(parent));
      if (parent) { const row = rowFor(parent.id); if (row && row.nextElementSibling !== form) row.after(form); }
      else parkForm();
    }
    function openForm(parentId = null) {
      addingParent = parentId;
      form.hidden = false;
      positionForm();
      $("summary-new-key").focus();
    }
    function closeForm() {
      form.hidden = true;
      addingParent = null;
      parkForm();
      $("summary-new-key").value = "";
      $("summary-new-value").value = "";
    }
    function refresh() {
      const records = pairs.ordered(getState().variables);
      const next = JSON.stringify(records.map(record => [record.id, record.parentId, /[\r\n]/.test(record.value)]));
      if (next !== signature) {
        finishDrag();
        const active = document.activeElement;
        const formFocus = form.contains(active) ? active : null;
        const id = active.closest("[data-variable-id]")?.dataset.variableId;
        const focus = root.contains(active) && id ? { id, field: active.dataset.variableValue ? "value" : active.dataset.variableKey ? "key" : "row" } : null;
        parkForm();
        signature = next;
        const fragment = document.createDocumentFragment();
        if (!records.length) fragment.append(element("p", "No categories yet. Add a category or import your logs.", "empty-message"));
        records.forEach((record, index) => fragment.append(row(record, index)));
        const scroll = root.scrollTop;
        root.replaceChildren(fragment);
        positionForm();
        root.scrollTop = scroll;
        if (formFocus) formFocus.focus({ preventScroll: true });
        else if (focus) {
          const replacement = rowFor(focus.id);
          if (replacement) (focus.field === "row" ? replacement : replacement.querySelector(focus.field === "value" ? "[data-variable-value]" : "[data-variable-key]")).focus({ preventScroll: true });
        }
      }
      for (const node of root.querySelectorAll("[data-variable-id]")) {
        const record = find(node.dataset.variableId);
        const key = node.querySelector("[data-variable-key]"), value = node.querySelector("[data-variable-value]");
        if (document.activeElement !== key) key.value = pairs.keys(record).join(" / ");
        if (document.activeElement !== value) value.value = pairs.displayValue(record);
        const option = node.querySelector(".summary-url-option");
        option.hidden = !window.SOCNote.defang.isUrl(record.value);
        option.setAttribute("aria-pressed", String(record.defangUrl === true));
        const timeZone = node.querySelector("[data-time-zone]");
        timeZone.parentNode.hidden = !pairs.isDate(record);
        if (!timeZone.parentNode.hidden && !timeZone.options.length) for (const zone of pairs.TIME_ZONES) {
          const option = element("option", zone);
          option.value = zone;
          if (!zone) option.setAttribute("aria-label", "No time zone");
          timeZone.append(option);
        }
        // Older drafts may have hidden the annotation with the removed eye.
        timeZone.value = record.hideTimeZone === true ? "" : (record.timeZone ?? "UTC");
        timeZone.setAttribute("aria-label", "Time zone for " + pairs.keys(record).join(" / "));
        refreshLink(node, record);
        node.setAttribute("aria-label", (record.parentId ? "Subcategory of " + pairs.keys(find(record.parentId)).join(" / ") + ": " : "Category: ") + pairs.keys(record).join(" / ") + " : " + pairs.displayValue(record));
      }
      positionForm();
    }
    // One boundary spans the full Summary viewport, including child indentation.
    function dropLayout() {
      const viewport = root.getBoundingClientRect();
      const boundary = viewport.left + viewport.width / 15;
      const rows = Array.from(root.querySelectorAll(".summary-pair"), node => ({ node, rect: node.getBoundingClientRect() }));
      for (const { node, rect } of rows) {
        const width = Math.max(0, boundary - rect.left) + "px";
        if (node.style.getPropertyValue("--summary-reorder-width") !== width) node.style.setProperty("--summary-reorder-width", width);
      }
      return { rows, viewport, boundary };
    }
    // The left fifteenth reorders. On the right, the row under (or just above)
    // the pointer determines the parent and the exact child insertion point.
    function resolveDropTarget(position, rows, viewport) {
      const resolved = pairs.resolveDrop(getState(), dragging, position.id, position);
      if (!resolved?.fallback) return position;
      const target = rows.find(({ node }) => node.dataset.variableId === resolved.id);
      const children = rows.filter(({ node }) => node.dataset.parentId === resolved.id);
      const top = resolved.after ? (children.at(-1)?.rect.bottom ?? target.rect.bottom) : (target?.rect.top ?? rows.at(-1)?.rect.bottom ?? viewport.top);
      return { ...resolved, node: target?.node, parentNode: null, top };
    }
    function dropAt(clientX, clientY) {
      const { rows, viewport, boundary } = dropLayout();
      const inside = clientX >= viewport.left && clientX <= viewport.right;
      const nest = inside && clientX >= boundary;
      // Indented rows also accept drops in their left margin, so the full-width
      // reorder zone stays usable when the Summary viewport is narrow.
      const hit = inside && rows.find(({ rect }) => clientY >= rect.top && clientY <= rect.bottom);
      const above = !hit && rows.findLast(({ rect }) => clientY > rect.bottom);
      const target = hit || (nest ? above : null);
      if (target) {
        const id = target.node.dataset.variableId;
        const after = nest || clientY >= target.rect.top + target.rect.height / 2;
        const children = rows.filter(({ node }) => node.dataset.parentId === id);
        const parentNode = nest ? (rowFor(target.node.dataset.parentId) || target.node) : null;
        return resolveDropTarget({ id, nest, after, node: target.node, parentNode, top: nest ? target.rect.bottom : after ? (children.at(-1)?.rect.bottom ?? target.rect.bottom) : target.rect.top }, rows, viewport);
      }
      const next = rows.find(({ rect }) => clientY < rect.top + rect.height / 2);
      return resolveDropTarget({ id: next?.node.dataset.variableId, nest: false, after: false, node: next?.node, top: next?.rect.top ?? rows.at(-1)?.rect.bottom ?? viewport.top }, rows, viewport);
    }
    function clearFeedback() {
      insertionLine.remove();
      for (const node of root.querySelectorAll(".summary-nest-target")) node.classList.remove("summary-nest-target");
      $("summary-drop-status").textContent = "";
    }
    function showDropTarget(clientX, clientY) {
      const position = dropAt(clientX, clientY);
      insertionLine.remove();
      for (const node of root.querySelectorAll(".summary-nest-target")) node.classList.remove("summary-nest-target");
      const valid = pairs.canMove(getState(), dragging, position.id, position);
      let status;
      if (!valid) {
        status = "Move unavailable. Only one subcategory level is allowed; a category with children cannot be nested.";
      } else if (position.nest) {
        position.parentNode.classList.add("summary-nest-target");
        status = "Add as a subcategory of " + pairs.keys(find(position.parentNode.dataset.variableId)).join(" / ");
        if (position.node.dataset.parentId) status += ", after " + pairs.keys(find(position.id)).join(" / ");
      } else {
        status = position.id ? (position.fallback ? "Move as a top-level category " : "Move ") + (position.after ? "after " : "before ") + pairs.keys(find(position.id)).join(" / ") : "Move to the end at the top level";
      }
      if (valid && (!position.nest || position.node.dataset.parentId)) {
        insertionLine.style.top = (position.top - root.getBoundingClientRect().top + root.scrollTop - 1) + "px";
        insertionLine.style.left = position.node?.dataset.parentId ? (position.node.getBoundingClientRect().left - root.getBoundingClientRect().left + root.scrollLeft) + "px" : "10px";
        root.append(insertionLine);
      }
      if ($("summary-drop-status").textContent !== status) $("summary-drop-status").textContent = status;
      return valid;
    }
    function clearDrop() {
      hoverPoint = null;
      clearFeedback();
      if (scrollFrame !== null) cancelAnimationFrame(scrollFrame);
      scrollFrame = null;
    }
    function finishDrag() {
      clearDrop();
      for (const node of root.querySelectorAll(".summary-pair-dragging")) node.classList.remove("summary-pair-dragging");
      root.classList.remove("summary-drag-active");
      dragging = null;
    }
    function scrollDuringDrag() {
      if (scrollFrame !== null) return;
      scrollFrame = requestAnimationFrame(() => {
        scrollFrame = null;
        if (!hoverPoint || !dragging) return;
        const rect = root.getBoundingClientRect(), edge = 32;
        const step = hoverPoint.y < rect.top + edge ? -Math.min(12, (rect.top + edge - hoverPoint.y) / 2)
          : hoverPoint.y > rect.bottom - edge ? Math.min(12, (hoverPoint.y - rect.bottom + edge) / 2) : 0;
        const before = root.scrollTop;
        root.scrollTop += step;
        if (root.scrollTop !== before) { showDropTarget(hoverPoint.x, hoverPoint.y); scrollDuringDrag(); }
      });
    }
    root.addEventListener("focusin", event => {
      const id = event.target.closest("[data-variable-id]")?.dataset.variableId;
      if (id && event.target.matches("input, textarea")) baselines.set(event.target, find(id)?.value);
      if (event.target.dataset.variableValue && find(id)?.defangUrl) event.target.value = find(id).value;
    });
    root.addEventListener("input", event => {
      const input = event.target, id = input.dataset.variableValue || input.dataset.variableKey;
      if (!id) return;
      let result;
      change("category edit", document => {
        result = pairs.edit(document, id, input.dataset.variableValue ? { value: input.value } : { names: input.value.split("/") });
      }, { key: "summary-pair:" + id });
      input.setAttribute("aria-invalid", String(!result?.ok));
      if (result?.merged) toast("Keys merged");
    });
    root.addEventListener("change", event => {
      const id = event.target.dataset.timeZone;
      if (!id || !pairs.TIME_ZONES.includes(event.target.value) || !find(id) || !pairs.isDate(find(id))) return;
      change("time zone selection", document => {
        const record = document.variables.find(record => record.id === id);
        record.timeZone = event.target.value;
        delete record.hideTimeZone;
      });
    });
    root.addEventListener("focusout", event => {
      const input = event.target;
      if (!input.matches("input, textarea")) return;
      const record = find(input.dataset.variableValue || input.dataset.variableKey);
      if (!record) return;
      if (input.getAttribute("aria-invalid") === "true") {
        const original = baselines.get(input);
        if (input.dataset.variableValue && original) change("value restoration", document => { pairs.edit(document, record.id, { value: original }); }, { key: "summary-pair:" + record.id });
        input.value = input.dataset.variableValue ? pairs.displayValue(find(record.id) || record) : pairs.keys(record).join(" / ");
        input.removeAttribute("aria-invalid");
        toast("Each category needs a title and a non-empty value.");
      } else input.value = input.dataset.variableValue ? pairs.displayValue(record) : pairs.keys(record).join(" / ");
    });
    root.addEventListener("click", event => {
      const target = event.target.closest("[data-pair-action]");
      if (!target) return;
      const { pairAction: action, id } = target.dataset;
      const record = find(id);
      if (!record) return;
      if (action === "copy") copyText(pairs.displayValue(record));
      else if (action === "defang" && window.SOCNote.defang.isUrl(record.value)) change("URL defanging", document => {
        const current = document.variables.find(record => record.id === id);
        current.defangUrl = current.defangUrl !== true;
      });
      else if (action === "vt-visibility" && entities.link(record)) change("VirusTotal link visibility", document => {
        const current = document.variables.find(record => record.id === id);
        current.hideVirusTotal = current.hideVirusTotal !== true;
      });
      else if (action === "flag-visibility" && pairs.countryCode(record)) change("flag visibility", document => {
        const current = document.variables.find(record => record.id === id);
        current.hideFlag = current.hideFlag !== true;
      });
      else if (action === "focus") rowFor(id)?.focus();
      else if (action === "add-child" && !record.parentId) openForm(id);
      else if (action === "remove") change("category removal", document => { pairs.remove(document, id); });
    });
    root.addEventListener("dragstart", event => {
      const node = event.target.closest("[data-variable-id]");
      if (!node || !event.dataTransfer || event.target.matches("input, textarea, select, option, a")) return;
      const record = find(node.dataset.variableId);
      if (!record) return;
      finishDrag();
      dragging = record.id;
      node.classList.add("summary-pair-dragging");
      root.classList.add("summary-drag-active");
      dropLayout();
      event.dataTransfer.setData("application/x-soc-pair", record.id);
      event.dataTransfer.setData("text/plain", pairs.displayValue(record));
      event.dataTransfer.effectAllowed = "copyMove";
    });
    root.addEventListener("dragover", event => {
      if (!dragging || !Array.from(event.dataTransfer?.types || []).includes("application/x-soc-pair")) return;
      event.preventDefault();
      event.stopPropagation();
      hoverPoint = { x: event.clientX, y: event.clientY };
      event.dataTransfer.dropEffect = showDropTarget(hoverPoint.x, hoverPoint.y) ? "move" : "none";
      scrollDuringDrag();
    });
    root.addEventListener("dragleave", event => { if (!root.contains(event.relatedTarget)) clearDrop(); });
    root.addEventListener("drop", event => {
      const id = event.dataTransfer?.getData("application/x-soc-pair");
      if (!id || id !== dragging || !find(id)) return;
      event.preventDefault();
      event.stopPropagation();
      const position = dropAt(event.clientX, event.clientY);
      const valid = pairs.canMove(getState(), id, position.id, position);
      finishDrag();
      if (!valid) { toast("This move is unavailable. Subcategories are limited to one level."); return; }
      change(position.nest ? "subcategory nesting" : "category order", document => { pairs.move(document, id, position.id, position); });
      rowFor(id)?.focus({ preventScroll: true });
    });
    root.addEventListener("dragend", finishDrag);
    document.addEventListener("keydown", event => { if (event.key === "Escape" && dragging) { finishDrag(); event.preventDefault(); } });
    $("add-variable-button").addEventListener("click", () => openForm());
    $("summary-cancel-variable").addEventListener("click", () => { const parent = addingParent; closeForm(); (rowFor(parent) || root).focus(); });
    form.addEventListener("submit", event => {
      event.preventDefault();
      let result;
      change(addingParent ? "subcategory addition" : "category addition", document => { result = pairs.add(document, $("summary-new-key").value.split("/"), $("summary-new-value").value, addingParent); });
      if (!result?.ok) { toast(result?.duplicate ? "That value already belongs to another category. Drag it here to move it." : "Enter a title and a value on a single line."); return; }
      closeForm();
      if (result.merged) toast("Keys merged");
      rowFor(result.id)?.focus();
    });
    function reset() { finishDrag(); closeForm(); }
    const api = Object.freeze({ refresh, reset, addFile, getText: () => formatter.body(getState()), getValues: () => formatter.summaryValues(getState()) });
    window.SOCNote.summary = api;
    return api;
  }
  return Object.freeze({ create });
})();

// Regression tests for data integrity and automatic working-draft recovery. Node built-ins only.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { randomUUID } = require("node:crypto");

function modules({ blocked = false } = {}) {
  const saved = new Map();
  const localStorage = {
    getItem(key) { if (blocked) throw new Error("Storage blocked"); return saved.get(key) ?? null; },
    setItem(key, value) { if (blocked) throw new Error("Quota exceeded"); saved.set(key, value); },
    removeItem(key) { if (blocked) throw new Error("Storage blocked"); saved.delete(key); }
  };
  const window = { crypto: { randomUUID }, localStorage };
  const context = vm.createContext({ window, URL });
  for (const file of ["templates", "summary-data", "defang", "extractors", "parser", "formatter", "storage"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../js", file + ".js"), "utf8"), context, { filename: file + ".js" });
  }
  return { ...window.SOCNote, saved };
}


test("empty and demo documents initialize safely without writing storage", () => {
  const { templates, saved } = modules();
  assert.equal(templates.emptyDocument().rule, "");
  assert.equal(templates.emptyDocument().raw, "");
  assert.equal(templates.demoDocument().rule, "Suspicious PowerShell Execution");
  assert.equal(saved.size, 0);
});

test("arbitrary colon/equal keys work, repeated keys retain separate unique values", () => {
  const { parser } = modules();
  const parsed = parser.parse("ticket_id: INC-42\nUser = alice\nuser: bob\nUSER: alice\nClé libre : texte\nhttps://example.invalid\n203.0.113.42");
  assert.equal(parsed.variables.length, 4);
  assert.equal(parsed.variables[1].value, "alice");
  assert.equal(parsed.variables[2].value, "bob");
  assert.equal(parsed.variables[3].key, "Clé libre");
});

test("raw CRLF and whitespace remain exact after extraction", () => {
  const { templates, parser } = modules();
  const document = templates.emptyDocument();
  const raw = "  Alert: Test  \r\nUser: alice\r\n\r\n  unknown line\r\n";
  document.raw = raw;
  parser.merge(document, parser.parse(raw));
  assert.equal(document.raw, raw);
  assert.equal(document.variables[0].value, "Test");
});

test("source variables update without duplication; manual values stay independent", () => {
  const { templates, parser } = modules();
  const document = templates.emptyDocument();
  document.raw = "User: alice\nHost: ONE";
  parser.merge(document, parser.parse(document.raw));
  const id = document.variables[0].id;
  document.raw = "User: bob\nHost: TWO";
  parser.merge(document, parser.parse(document.raw));
  assert.notEqual(document.variables[0].id, id);
  assert.equal(document.variables[0].value, "bob");
  document.variables[0].origin = "manual";
  document.variables[0].value = "verified";
  document.raw = "User: charlie";
  parser.merge(document, parser.parse(document.raw));
  assert.equal(document.variables.length, 2);
  assert.equal(document.variables[0].value, "verified");
  assert.equal(document.variables[1].value, "charlie");
});

test("explicitly ignored raw keys are not reintroduced on extraction", () => {
  const { templates, parser } = modules();
  const document = templates.emptyDocument();
  document.raw = "User: alice\nHost: ONE";
  document.ignoredKeys.push("user");
  parser.merge(document, parser.parse(document.raw));
  assert.equal(document.variables.length, 1);
  assert.equal(document.variables[0].key, "Host");
});

test("report generation treats suspicious strings as data and contains only visible sections", () => {
  const { templates, formatter, parser } = modules();
  const document = templates.emptyDocument();
  document.rule = '<img src=x onerror=alert(1)>';
  document.raw = 'Host: ONE\nUser: alice';
  parser.merge(document, parser.parse(document.raw));
  document.extra = 'hidden metadata';
  document.capturedRaw = '# retained comment';
  assert.equal(formatter.format(document), '<img src=x onerror=alert(1)>\n\n==================================================\n                     SUMMARY\n==================================================\n\nHost: ONE\n\nUser: alice');
});

test("large input keeps raw and existing variables intact; extraction has clear limits", () => {
  const { templates, parser } = modules();
  const document = templates.demoDocument();
  const previous = JSON.stringify(document.variables);
  document.raw = "User: " + "x".repeat(parser.MAX_CHARACTERS);
  const parsed = parser.parse(document.raw);
  assert.equal(parsed.limited, true);
  parser.merge(document, parsed);
  assert.equal(JSON.stringify(document.variables), previous);
  const repeated = parser.parse(Array.from({ length: 205 }, (_, i) => "key_" + i + ": value_" + i).join("\n"));
  assert.equal(repeated.variables.length, 200);
  assert.equal(repeated.limited, true);
});

test("draft schema validates origin, IDs and types while discarding unknown fields", () => {
  const { templates, storage } = modules();
  const document = templates.demoDocument();
  document.extra = "discarded";
  assert.equal(storage.validate(document).extra, undefined);
  for (const invalid of [1, {}, false]) { document.rule = invalid; assert.equal(storage.validate(document), null); }
  document.rule = "Valid rule";
  document.variables.push({ ...document.variables[0] });
  assert.equal(storage.validate(document), null);
});

test("legacy migration retains original logs, rule, notes and facts", () => {
  const { storage, formatter } = modules();
  const old = { schemaVersion: 1, raw: "original\r\n", createdAt: "2026-10-06", updatedAt: "2026-10-06", isDemo: false,
    alert: { title: "Test", id: "ID", source: "EDR", severity: "High", detectedAt: "09:42" },
    users: [{ id: "a", value: "alice", context: "interactive" }], hosts: [], processes: [], network: [], iocs: [], timeline: [],
    observations: "verified fact", analystNotes: "human notes" };
  const migrated = storage.validate(old);
  assert.equal(migrated.schemaVersion, 4);
  assert.equal(migrated.raw, old.raw);
  assert.equal(migrated.rule, "Test");
  assert(formatter.format(migrated).includes("human notes"));
  assert(formatter.format(migrated).includes("alice — interactive"));
});

test("Current Analysis saving restores the complete working draft and clearing removes only investigation keys", () => {
  const { templates, storage, saved } = modules();
  const document = templates.demoDocument();
  document.analysis = "Working notes";
  assert.equal(storage.load().document, null);
  saved.set("unrelated", "keep");
  assert.equal(storage.save(document).ok, true);
  assert.equal(storage.load().document.raw, document.raw);
  assert.equal(storage.load().document.analysis, document.analysis);
  assert.equal(storage.load().document.rule, document.rule);
  assert.equal(storage.clear().ok, true);
  assert.equal(saved.size, 1);
  assert.equal(saved.get("unrelated"), "keep");
  assert.equal(storage.save(templates.emptyDocument()).ok, true);
  assert.equal(saved.size, 1);
});

test("corrupt Current Analysis is reported without overwriting it", () => {
  const { storage, saved } = modules();
  saved.set("soc-note-builder.current-analysis.v1", "{broken");
  const loaded = storage.load();
  assert.equal(loaded.document, null);
  assert.equal(loaded.writable, false);
  assert(loaded.error);
  assert.equal(saved.get("soc-note-builder.current-analysis.v1"), "{broken");
});

test("storage refusal does not crash or mutate working state", () => {
  const { templates, storage } = modules({ blocked: true });
  const document = templates.demoDocument();
  const before = JSON.stringify(document);
  assert.equal(storage.load().writable, false);
  assert.equal(storage.save(document).ok, false);
  assert.equal(storage.clear().ok, false);
  assert.equal(JSON.stringify(document), before);
});

test('log submission clears only pending input and retains values and exact original logs', () => {
  const { templates, parser, formatter, storage } = modules();
  const document = templates.emptyDocument();
  const raw = 'User: DOMAIN\\jdupont\r\nHost: PC-0042\r\nIP: 185.42.21.8\r\n';
  document.raw = raw;
  const result = parser.capture(document);
  assert.equal(result.ok, true);
  assert.equal(result.count, 3);
  assert.equal(document.raw, '');
  assert.equal(document.capturedRaw, raw);
  assert.equal(document.variables.length, 3);
  assert(document.variables.every(variable => variable.origin === 'captured'));
  assert(formatter.body(document).includes('DOMAIN\\jdupont'));
  parser.merge(document, parser.parse(document.raw));
  assert.equal(document.variables.length, 3, 'Empty input cannot erase captured values');
  assert.equal(parser.originalRaw(document), raw);
  assert.equal(storage.validate(document).capturedRaw, raw);
});

test('successive captures retain distinct values for repeated keys without changing analysis', () => {
  const { templates, parser, formatter } = modules();
  const document = templates.emptyDocument();
  document.raw = 'User: alice\nHost: ONE';
  parser.capture(document);
  const userId = document.variables.find(variable => variable.value === 'alice').id;
  document.raw = 'User: bob\nIP: 192.0.2.1';
  parser.merge(document, parser.parse(document.raw));
  document.analysis = 'Analyse manuelle à conserver.';
  parser.capture(document);
  assert.equal(document.variables.find(variable => variable.value === 'alice').id, userId);
  assert.equal(document.variables.filter(variable => variable.key === 'User').length, 2);
  assert.equal(document.variables.find(variable => variable.key === 'Host').value, 'ONE');
  assert.equal(document.variables.length, 4);
  assert.equal(document.analysis, 'Analyse manuelle à conserver.');
  assert.equal(formatter.body(document), 'User : alice\nHost : ONE\nUser : bob\nIP : 192.0.2.1');
  const final = formatter.format(document);
  assert(final.endsWith('==================================================\n                     ANALYSIS\n==================================================\n\nAnalyse manuelle à conserver.'));
});

test('empty or oversized submission retains input and facts; old saved documents gain blank analysis/archive', () => {
  const { templates, parser, storage } = modules();
  const document = templates.demoDocument();
  document.raw = '';
  const before = JSON.stringify(document);
  assert.equal(parser.capture(document).ok, false);
  assert.equal(JSON.stringify(document), before);
  document.raw = 'Host: ' + 'x'.repeat(parser.MAX_CHARACTERS);
  const oversized = JSON.stringify(document);
  assert.equal(parser.capture(document).ok, false);
  assert.equal(JSON.stringify(document), oversized);
  document.raw = '';
  delete document.analysis;
  delete document.capturedRaw;
  const migrated = storage.validate(document);
  assert.equal(migrated.analysis, '');
  assert.equal(migrated.capturedRaw, '');
  document.analysis = {invalid: true};
  assert.equal(storage.validate(document), null);
});

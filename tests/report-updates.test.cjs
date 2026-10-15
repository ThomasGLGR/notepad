// Logs cleaning, mitigation wording, MITRE ATT&CK techniques, report spacing and links. Node built-ins only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
function modules() {
  const saved = new Map();
  const window = {crypto: {randomUUID}, localStorage: {getItem: key => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value), removeItem: key => saved.delete(key)}};
  const context = vm.createContext({window, URL});
  const load = file => vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context, {filename: file});
  for (const file of ['templates', 'clean', 'country', 'entities', 'summary-data', 'json-import']) load('js/' + file + '.js');
  load('extension/capture-data.js');
  for (const file of ['defang', 'extractors', 'parser', 'remediation-data', 'remediation-engine', 'remediation-storage', 'mitre-data', 'mitre-ui', 'formatter', 'storage']) load('js/' + file + '.js');
  return window.SOCNote;
}
const capture = (id, value) => ({id, value, timestamp: 1, tabId: 1, windowId: 1, title: 'SIEM', url: 'https://siem.example/alert', context: ''});

test('cleaning removes pictographs and outer whitespace only; technical text is untouched', () => {
  const {clean} = modules();
  assert.equal(clean.text('\n\n  ⚠️ Alert: Suspicious login ✅  \n\n'), 'Alert: Suspicious login');
  assert.equal(clean.text('user: alice 🙂\r\n   ✅ indented line\r\nhost: PC-01\r\n\r\n'), 'user: alice\r\n   indented line\r\nhost: PC-01');
  assert.equal(clean.text('👨‍👩‍👧 family 🇫🇷 flag 👍🏽 ok 1️⃣'), 'family flag ok 1');
  for (const text of ['cmd:  powershell.exe   -enc  SQBFAFgA==', 'C:\\Program Files\\App\\a b.exe  --x=1 | findstr /i "a  b"', 'https://example.invalid/a%20b?x=1&y=#frag',
    '2026-10-13T10:15:30.123+02:00  185.42.21.8  fe80::1  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Microsoft® Windows™ © 2026 → étape n° 2 – “ok”', 'line one\n\n\n  line four\tTabbed', '日本語 ログ: 失敗']) {
    assert.equal(clean.text(text), text, text);
  }
  assert.equal(clean.text('  \n \n'), '');
  assert.equal(clean.text(42), 42);
});

test('Logs, extension captures and JSON imports are cleaned on the way to Summary', () => {
  const {templates, parser, jsonImport, formatter} = modules(), document = templates.emptyDocument();
  document.raw = '\r\n\r\n  🚨 Alert: Brute force ✅\r\ncommand_line: cmd.exe  /c   "whoami  /all" 🙂\r\n\r\n   \r\n';
  assert.equal(parser.capture(document).ok, true);
  assert.equal(document.capturedRaw, 'Alert: Brute force\r\ncommand_line: cmd.exe  /c   "whoami  /all"');
  assert.deepEqual(Array.from(document.variables, record => record.value), ['Brute force', 'cmd.exe  /c   "whoami  /all"']);
  assert.equal(parser.importCaptures(document, [capture('one', '  🔥 185.42.21.8  '), capture('two', 'EDR Action: Not mitigated ❌')]).ok, true);
  assert.equal(document.variables.find(record => record.key === 'IP').value, '185.42.21.8');
  assert.equal(document.variables.find(record => record.key === 'EDR Action').value, 'Unmitigated');
  assert.equal(jsonImport.importJSON(document, {'user.name': '  alice 👤 ', 'note': '\n\n first line\n\n  second  line 🙂\n\n', 'only.icon': ' ✅ ', 'count': 0, 'process.args': ['-a  -b', ' -c 🧪']}).ok, true);
  const value = key => document.variables.find(record => record.key === key)?.value;
  assert.equal(value('user.name'), 'alice');
  assert.equal(value('note'), 'first line\n\n  second  line');
  assert.equal(value('only.icon'), undefined, 'A value made only of pictographs is ignored like an empty one');
  assert.equal(value('count'), '0');
  assert.equal(value('process.args'), '-a  -b');
  assert.equal(value('process.args2'), '-c');
  assert(!/\p{Extended_Pictographic}/u.test(formatter.format(document)));
  document.raw = '   ✅  ';
  assert.equal(parser.capture(document).empty, true);
});

test('"Not mitigated" reads "Unmitigated" for new values and for values already saved', () => {
  const {templates, parser, pairs, jsonImport, formatter, storage} = modules(), document = templates.emptyDocument();
  document.raw = 'status: Not mitigated';
  parser.merge(document, parser.parse(document.raw));
  assert.equal(document.variables[0].value, 'Unmitigated');
  assert.equal(jsonImport.importJSON(document, {'edr.status': 'NOT_MITIGATED', 'comment': 'Not mitigated by the policy'}).ok, true);
  assert.equal(pairs.add(document, ['manual'], 'not mitigated').merged, true);
  assert.equal(document.variables.length, 2);
  assert.equal(document.variables[1].value, 'Not mitigated by the policy');
  // A draft saved before the change keeps its stored value and its pair; only the wording shown changes.
  const legacy = templates.emptyDocument();
  legacy.variables = [{id: 'a', key: 'EDR Action', keys: ['EDR Action'], value: 'Not mitigated', origin: 'captured'}, {id: 'b', key: 'EDR Action 2', keys: ['EDR Action 2'], value: 'Mitigated', origin: 'captured'}];
  const restored = storage.validate(legacy);
  assert.equal(restored.variables.length, 2);
  assert.equal(formatter.format(restored), '==================================================\n                     SUMMARY\n==================================================\n\nEDR Action: Unmitigated\n\nEDR Action 2: Mitigated');
  assert.equal(formatter.summaryValues(restored), 'Unmitigated\nMitigated');
  assert.equal(formatter.body(restored), 'EDR Action : Unmitigated\nEDR Action 2 : Mitigated');
});

test('the bundled ATT&CK catalogue is well formed and searchable by ID or name', () => {
  const {mitre, mitreData} = modules();
  assert(mitreData.techniques.length > 600);
  assert.equal(new Set(mitreData.techniques.map(([id]) => id)).size, mitreData.techniques.length);
  for (const [id, name] of mitreData.techniques) assert(mitre.ID.test(id) && typeof name === 'string' && name.trim() === name && name.length > 2 && name.length <= 200, id);
  const names = new Map(mitreData.techniques);
  assert.equal(names.get('T1059'), 'Command and Scripting Interpreter');
  assert.equal(names.get('T1078'), 'Valid Accounts');
  assert.equal(names.get('T1053.005'), 'Scheduled Task/Job: Scheduled Task');
  for (const [id] of mitreData.techniques) if (id.includes('.')) assert(names.has(id.split('.')[0]), id + ' has its parent technique');
  assert.equal(mitre.search('powershell')[0].id, 'T1059.001');
  assert.deepEqual(Array.from(mitre.search('t1059'), item => item.id).slice(0, 2), ['T1059', 'T1059.001']);
  assert.equal(mitre.search('1053.005')[0].id, 'T1053.005');
  assert.equal(mitre.search('valid accounts cloud')[0].id, 'T1078.004');
  assert.equal(mitre.search('t1059', [{id: 'T1059', name: ''}])[0].id, 'T1059.001', 'Selected techniques are not offered again');
  assert.equal(mitre.search('   ').length, 0);
  assert.equal(mitreData.tactics.length, 15);
  for (const [id, name] of mitreData.tactics) assert(/^TA\d{4}$/.test(id) && mitre.ID.test(id) && name.length > 3, id);
  assert.equal(mitre.search('ta0006')[0].id, 'TA0006');
  assert.equal(mitre.search('credential access')[0].id, 'TA0006');
  assert.equal(mitre.search('exfiltration')[0].id, 'TA0010');
  assert(mitre.search('a').length <= 8);
});

test('techniques are added, removed, saved and written at the start of the Summary', () => {
  const {templates, mitre, pairs, formatter, storage} = modules(), document = templates.emptyDocument();
  assert.equal(JSON.stringify(mitre.parse('t1059, T1078;T1053.005 t1059')), JSON.stringify([{id: 'T1059', name: 'Command and Scripting Interpreter'}, {id: 'T1078', name: 'Valid Accounts'}, {id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task'}]));
  assert.equal(JSON.stringify(mitre.parse('T9999 - Internal technique')), JSON.stringify([{id: 'T9999', name: 'Internal technique'}]));
  assert.equal(mitre.parse('powershell T12 TA06 T10590').length, 0);
  // Tactics are selected like techniques and lead the list, as in the matrix.
  assert.equal(JSON.stringify(mitre.parse('ta0006')), JSON.stringify([{id: 'TA0006', name: 'Credential Access'}]));
  assert.equal(mitre.add(document, mitre.parse('T1059 T1078 T1053.005')).count, 3);
  assert.equal(mitre.add(document, mitre.parse('T1078')).count, 0);
  mitre.remove(document, 'T1078');
  mitre.add(document, mitre.parse('T9999 - Internal technique'));
  mitre.add(document, mitre.parse('TA0002'));
  mitre.add(document, mitre.parse('TA0003'));
  document.rule = 'Suspicious task';
  pairs.add(document, ['host'], 'PC-0042');
  pairs.add(document, ['user'], 'alice');
  document.analysis = 'Reviewed.';
  assert.equal(formatter.format(document), 'Suspicious task\n\n==================================================\n                     SUMMARY\n==================================================\n\nMITRE ATT&CK: Execution (TA0002), Persistence (TA0003), Command and Scripting Interpreter (T1059), Scheduled Task/Job: Scheduled Task (T1053.005), Internal technique (T9999)\n\nhost: PC-0042\n\nuser: alice\n\n==================================================\n                     ANALYSIS\n==================================================\n\nReviewed.');
  // IDs from the bundled list link to their official page; a custom ID has no page.
  assert.deepEqual(Array.from(formatter.sections(document)[0].mitre, item => item.href), ['https://attack.mitre.org/tactics/TA0002/', 'https://attack.mitre.org/tactics/TA0003/',
    'https://attack.mitre.org/techniques/T1059/', 'https://attack.mitre.org/techniques/T1053/005/', null]);
  const alone = templates.emptyDocument();
  mitre.add(alone, mitre.parse('T1486'));
  assert.equal(formatter.format(alone), '==================================================\n                     SUMMARY\n==================================================\n\nMITRE ATT&CK: Data Encrypted for Impact (T1486)');
  assert.equal(formatter.body(document), 'host : PC-0042\nuser : alice', 'The editor text has no added blank lines');
  assert.equal(storage.save(document).ok, true);
  assert.equal(JSON.stringify(storage.load().document.mitreTechniques), JSON.stringify(document.mitreTechniques));
  // Techniques alone are worth saving; drafts saved before the selector load with none.
  const only = templates.emptyDocument();
  mitre.add(only, mitre.parse('T1486'));
  assert.equal(storage.isEmpty(only), false);
  const older = templates.emptyDocument();
  delete older.mitreTechniques;
  older.rule = 'Older draft';
  assert.equal(JSON.stringify(storage.validate(older).mitreTechniques), '[]');
  for (const bad of [[{id: 'T1', name: ''}], [{id: 'T1059', name: 'a\nb'}], [{id: 'T1059', name: ''}, {id: 'T1059', name: ''}], [{id: 'T1059'}], 'T1059', Array.from({length: 101}, (unused, index) => ({id: 'T' + String(1000 + index), name: ''}))]) {
    assert.equal(storage.validate({...document, mitreTechniques: bad}), null, JSON.stringify(bad).slice(0, 60));
  }
});

test('report fields carry safe links: VirusTotal and event references, never the suspicious URL', () => {
  const {templates, jsonImport, pairs, formatter, entities} = modules(), document = templates.emptyDocument();
  jsonImport.importJSON(document, {'event.url': 'https://siem.example.invalid/app/alerts/45821', 'url.full': 'https://auth-office365-update.com/login', 'source.ip': '98.56.54.185', 'event.reference': 'javascript:alert(1)'});
  const fields = formatter.sections(document)[0].fields;
  const field = key => fields.find(item => item.key === key);
  assert.equal(field('event.url').href, 'https://siem.example.invalid/app/alerts/45821');
  assert.equal(field('event.url').details.length, 0, 'A console link is a reference, not an indicator to analyze');
  assert.equal(field('url.full').href, null);
  assert.equal(field('url.full').details.length, 0, 'URL reports omit the automatic Domain detail');
  assert.equal(field('url.full').virusTotal, 'https://www.virustotal.com/gui/url/' + Buffer.from('https://auth-office365-update.com/login').toString('base64url'));
  assert.equal(field('source.ip').virusTotal, 'https://www.virustotal.com/gui/ip-address/98.56.54.185');
  assert.equal(field('source.ip').details.length, 0, 'VirusTotal is no longer a predefined detail line');
  assert.equal(field('event.reference').href, null);
  // References retain their full address; the plain report uses the VirusTotal label.
  const reference = document.variables.find(record => record.key === 'event.url');
  reference.defangUrl = true;
  assert.equal(formatter.sections(document)[0].fields[0].href, null);
  reference.defangUrl = false;
  assert.equal(entities.kind({key: 'URL', value: 'https://siem.example.invalid/x'}), 'url');
  const text = formatter.format(document);
  assert(text.includes('source.ip: 98.56.54.185 → VirusTotal'));
  assert(!text.includes('\n└── VirusTotal'));
  for (const item of formatter.sections(document)[0].fields) for (const href of [item.href, ...item.details.map(detail => detail.href)].filter(Boolean)) assert(text.includes(href), href);
});

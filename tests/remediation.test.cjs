// Remediation behavior and privacy checks using only Node built-ins.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');

function modules({ blocked = false, saved = new Map() } = {}) {
  const window = { crypto: { randomUUID }, localStorage: {
    getItem(key) { if (blocked) throw Error('Blocked'); return saved.get(key) ?? null; },
    setItem(key, value) { if (blocked) throw Error('Quota'); saved.set(key, value); },
    removeItem(key) { if (blocked) throw Error('Blocked'); saved.delete(key); }
  } };
  const context = vm.createContext({ window, URL });
  for (const file of ['templates', 'summary-data', 'extractors', 'parser', 'defang', 'remediation-data', 'remediation-engine', 'remediation-storage', 'formatter', 'storage']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../js', file + '.js'), 'utf8'), context, { filename: file + '.js' });
  }
  return { ...window.SOCNote, saved };
}
function choose(document, catalog, tacticId, index) {
  const tactic = catalog.find(tactic => tactic.id === tacticId);
  const item = tactic.remediations[index];
  document.remediation.selected.push({ id: item.id, tacticId, tacticName: tactic.name, template: item.template, generic: item.generic, text: null });
}
function parse(document, parser, raw) {
  document.raw = raw;
  parser.merge(document, parser.parse(raw));
}

test('all 14 configured tactics have safe default actions; no automatic selection', () => {
  const { remediationData: data, remediationEngine: engine, templates, parser, saved } = modules();
  const catalog = data.defaults();
  assert.equal(catalog.length, 14);
  assert.equal(new Set(catalog.flatMap(tactic => tactic.remediations.map(item => item.id))).size, 116);
  const document = templates.emptyDocument();
  parse(document, parser, 'USER: DOMAIN\\jdupont\nHOST: PC-0042\nIP: 185.42.21.8\nMITRE: Credential Access');
  assert.equal(document.remediation.selected.length, 0);
  assert.equal(document.remediation.activeTactics.length, 0);
  assert.equal(saved.size, 0);
  for (const tactic of catalog) {
    assert(tactic.remediations.length >= 5);
    for (const item of tactic.remediations) {
      assert.equal(item.origin, 'default');
      const empty = engine.resolve(item.template, templates.emptyDocument()).text;
      assert(!/undefined|null|\{[^{}]+\}/.test(empty), empty);
      choose(document, catalog, tactic.id, tactic.remediations.indexOf(item));
    }
  }
  assert.equal(engine.format(document).split('\n').length, 116);
});

test('case 1: multi-tactic recommendations interpolate and defang exactly', () => {
  const { templates, parser, remediationData: data, remediationEngine: engine, formatter, features } = modules();
  features.remediation = true; // The withdrawn section returns with this switch.
  const document = templates.emptyDocument();
  parse(document, parser, 'USER: DOMAIN\\jdupont\nHOST: PC-0042\nIP: 185.42.21.8');
  const catalog = data.defaults();
  choose(document, catalog, 'credential-access', 0);
  choose(document, catalog, 'credential-access', 1);
  choose(document, catalog, 'command-and-control', 0);
  choose(document, catalog, 'command-and-control', 3);
  const expected = '- Reset the password for the account DOMAIN\\jdupont.\n- Revoke active sessions for the account DOMAIN\\jdupont.\n- Block the IP address 185[.]42[.]21[.]8.\n- Isolate the host PC-0042.';
  assert.equal(engine.format(document), expected);
  assert.equal(formatter.format(document), '==================================================\n                     SUMMARY\n==================================================\n\nUSER: DOMAIN\\jdupont\n\nHOST: PC-0042\n\nIP: 185.42.21.8\n\n==================================================\n                   REMEDIATION\n==================================================\n\n' + expected);
  document.remediation.includeTactics = true;
  assert(engine.format(document).startsWith('Credential Access\n- '));
  assert(engine.format(document).includes('\n\nCommand and Control\n- '));
});

test('case 2: absent, empty, null and undefined values yield generic wording', () => {
  const { templates, remediationEngine: engine } = modules();
  const document = templates.emptyDocument();
  for (const value of [undefined, null, '', '  ', 'undefined', 'NULL']) {
    document.variables = [{ key: 'USER', value }];
    assert.equal(engine.resolve('Reset the password for the account {USER}.', document).text, 'Reset the password for the account under investigation.');
  }
  assert.equal(engine.resolve('Review {UNKNOWN}.', document).text, 'Review [to complete].');
  assert.equal(engine.resolve('Review {USER} and {HOST}.', document, 'Review the account and host under investigation.').text, 'Review the account and host under investigation.');
});

test('all ten variables support aliases, partial data and idempotent network neutralization', () => {
  const { templates, parser, remediationEngine: engine } = modules();
  const document = templates.emptyDocument();
  parse(document, parser, 'utilisateur: alice\nhôte: PC-1\nip: 185[.]42[.]21[.]8\nip source: 192.0.2.1\ndst_ip: 198.51.100.2\ndomaine: evil.invalid\nurl: https://evil.invalid/file\nsha256: abcdef\nfichier: C:\\a.exe\nprocessus: a.exe');
  const expected = 'alice|PC-1|185[.]42[.]21[.]8|192[.]0[.]2[.]1|198[.]51[.]100[.]2|evil[.]invalid|hxxps://evil[.]invalid/file|abcdef|C:\\a.exe|a.exe';
  assert.equal(engine.resolve('{USER}|{HOST}|{IP}|{SRC_IP}|{DST_IP}|{DOMAIN}|{URL}|{HASH}|{FILE}|{PROCESS}', document).text, expected);
  assert.equal(document.variables.find(variable => variable.key === 'url').value, 'https://evil.invalid/file');
  assert.equal(engine.resolve('Review {USER} on {MISSING}.', document, 'Review the account.').text, 'Review alice on [to complete].');
  document.variables[0].value = 'alice\nbob';
  assert.equal(engine.resolve('Review {USER}.', document).text, 'Review alice / bob.');
});

test('case 3: edited defaults, custom actions, favorites, order and categories persist only on opt-in', () => {
  const { remediationData: data, remediationStorage: storage, saved } = modules();
  const catalog = data.defaults();
  const tactic = catalog.find(tactic => tactic.id === 'credential-access');
  tactic.remediations[0].template = 'Renew the password for {USER}.';
  tactic.remediations[0].favorite = true;
  tactic.remediations[1].enabled = false;
  tactic.remediations.unshift({ id: 'custom', template: 'Review the account {USER}.', generic: '', origin: 'custom', favorite: true, enabled: true });
  catalog.push({ id: 'new-tactic', name: 'Custom category', mitreId: '', origin: 'custom', remediations: [] });
  assert.equal(storage.load().enabled, false);
  assert.equal(saved.size, 0);
  assert.equal(storage.setEnabled(true, catalog).ok, true);
  const reloaded = modules({ saved }).remediationStorage.load();
  assert.equal(reloaded.enabled, true);
  const restored = reloaded.catalog.find(tactic => tactic.id === 'credential-access');
  assert.equal(restored.remediations[0].id, 'custom');
  assert.equal(restored.remediations[1].template, 'Renew the password for {USER}.');
  assert.equal(restored.remediations[1].favorite, true);
  assert.equal(restored.remediations[2].enabled, false);
  assert.equal(reloaded.catalog.at(-1).name, 'Custom category');
});

test('case 4: investigation edits do not change models; selection survives catalogue removal and reset', () => {
  const { templates, remediationData: data, remediationEngine: engine, remediationStorage: storage, formatter, saved, features } = modules();
  features.remediation = true;
  const document = templates.emptyDocument();
  const catalog = data.defaults();
  choose(document, catalog, 'credential-access', 0);
  const selected = document.remediation.selected[0];
  selected.text = 'Reset the password within 30 minutes.';
  assert.equal(catalog.find(tactic => tactic.id === 'credential-access').remediations[0].template, 'Reset the password for the account {USER}.');
  catalog.length = 0;
  assert.equal(engine.format(document), '- Reset the password within 30 minutes.');
  document.analysis = 'Texte rédigé à la main.';
  assert.equal(formatter.format(document), '==================================================\n                   REMEDIATION\n==================================================\n\n- Reset the password within 30 minutes.\n\n==================================================\n                     ANALYSIS\n==================================================\n\nTexte rédigé à la main.');
  assert.equal(storage.save(data.defaults()).ok, true);
  assert(![...saved.values()].join('').includes(selected.text));
});

test('catalogue and explicitly saved investigation use independent storage; schema strips extra fields', () => {
  const { templates, remediationData: data, remediationStorage: catalogStorage, remediationEngine: engine, storage, saved } = modules();
  const catalog = data.defaults();
  catalog[0].raw = 'SECRET LOG';
  catalog[0].remediations[0].text = 'SECRET OVERRIDE';
  assert.equal(catalogStorage.save(catalog).ok, true);
  assert(!saved.get('soc-note-builder.remediation-catalog.v1').includes('SECRET'));
  const document = templates.emptyDocument();
  document.raw = 'CONFIDENTIAL INVESTIGATION';
  choose(document, catalog, 'credential-access', 0);
  document.remediation.selected[0].text = 'Session text';
  assert.equal(storage.save(document).ok, true);
  assert.equal(storage.load().document.remediation.selected[0].text, 'Session text');
  assert.equal(storage.clear().ok, true);
  assert.equal(saved.size, 1);
  assert.equal(catalogStorage.load().enabled, true);
  assert.equal(storage.save(document).ok, true);
  assert.equal(catalogStorage.setEnabled(false, catalog).ok, true);
  assert.equal(storage.load().document.raw, 'CONFIDENTIAL INVESTIGATION');
  delete document.remediation;
  assert.equal(storage.validate(document).remediation.selected.length, 0);
  document.remediation = engine.emptySession();
  document.remediation.selected.push({ id: 'a' });
  assert.equal(storage.validate(document), null);
});

test('corrupt/blocked catalogue storage reports failure without overwriting stored data', () => {
  const { saved, remediationStorage: storage } = modules();
  saved.set('soc-note-builder.remediation-catalog.v1', '{broken');
  assert.equal(storage.load().enabled, false);
  assert(storage.load().error);
  assert.equal(saved.get('soc-note-builder.remediation-catalog.v1'), '{broken');
  const blocked = modules({ blocked: true });
  assert(blocked.remediationStorage.load().error);
  assert.equal(blocked.remediationStorage.save(blocked.remediationData.defaults()).ok, false);
  assert.equal(blocked.remediationStorage.setEnabled(false).ok, false);
  assert.equal(storage.validate({ version: 1, tactics: [{ id: '__proto__' }] }), null);
});

test('injected values stay inert text and replacement strings are never evaluated', () => {
  const { templates, remediationEngine: engine } = modules();
  const document = templates.emptyDocument();
  const attack = '<img src="https://example.invalid" onerror="alert(1)"> $& {HOST}';
  document.variables = [{ key: 'USER', value: attack }];
  assert.equal(engine.resolve('Review the account {USER}.', document).text, 'Review the account ' + attack + '.');
  assert.equal(document.variables[0].value, attack);
});

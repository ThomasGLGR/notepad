// Countries, flags, VirusTotal links and entity details. Node built-ins only.
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
  for (const file of ['templates', 'country', 'entities', 'summary-data', 'json-import']) load('js/' + file + '.js');
  load('extension/capture-data.js');
  for (const file of ['defang', 'extractors', 'parser', 'remediation-data', 'remediation-engine', 'remediation-storage', 'formatter', 'storage']) load('js/' + file + '.js');
  return window.SOCNote;
}
const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const idOf = (document, value) => document.variables.find(record => record.value === value).id;

test('ISO codes and common French or English names give the code and its flag; unknown input is kept without a flag', () => {
  const {country} = modules();
  for (const [input, expected] of [['FR', 'FR 🇫🇷'], ['us', 'US 🇺🇸'], ['NL', 'NL 🇳🇱'], ['de', 'DE 🇩🇪'], ['France', 'FR 🇫🇷'], ['Pays-Bas', 'NL 🇳🇱'], ['pays bas', 'NL 🇳🇱'],
    ['États-Unis', 'US 🇺🇸'], ['Netherlands', 'NL 🇳🇱'], ['Allemagne', 'DE 🇩🇪'], ['UK', 'GB 🇬🇧'], ['USA', 'US 🇺🇸'], ['FR 🇫🇷', 'FR 🇫🇷'], ['🇩🇪', 'DE 🇩🇪']]) {
    assert.equal(country.display(country.normalize(input)), expected, input);
  }
  for (const input of ['zz', 'EU', 'Atlantide', 'F', 'FRA?']) {
    assert.equal(country.code(input), null, input);
    assert.equal(country.normalize(input), input);
    assert.equal(country.display(country.normalize(input)), input);
  }
  assert.equal(country.normalize('   '), '');
  assert.equal(country.flag('ZZ'), '');
  assert.equal(country.flag('fr'), '', 'Flags are built only from validated upper-case codes');
  assert.equal([...country.flag('NL')].map(symbol => symbol.codePointAt(0).toString(16)).join(' '), '1f1f3 1f1f1');
});

test('VirusTotal links are built locally for IPs, exact URLs and file hashes', () => {
  const {entities} = modules();
  assert.equal(entities.virusTotal.ip('98.56.54.185'), 'https://www.virustotal.com/gui/ip-address/98.56.54.185');
  assert.equal(entities.virusTotal.ip('185[.]42[.]21[.]8'), 'https://www.virustotal.com/gui/ip-address/185.42.21.8');
  assert.equal(entities.virusTotal.ip('2001:DB8::1'), 'https://www.virustotal.com/gui/ip-address/2001:db8::1');
  assert.equal(entities.virusTotal.file(sha256.toUpperCase()), 'https://www.virustotal.com/gui/file/' + sha256);
  assert.equal(entities.virusTotal.file('abcdef'), null);
  for (const [shown, exact] of [['hxxps://auth-office365-update[.]com/login', 'https://auth-office365-update.com/login'], ['https://example.invalid/a?b=c&d=é#f', 'https://example.invalid/a?b=c&d=é#f'],
    ['hxxp://198[.]51[.]100[.]7:8080/x', 'http://198.51.100.7:8080/x'], ['http://a.example/', 'http://a.example/'], ['http://a.example/xy', 'http://a.example/xy']]) {
    assert.equal(entities.virusTotal.urlId(shown), Buffer.from(exact).toString('base64url'), shown);
    assert.equal(entities.virusTotal.url(shown), 'https://www.virustotal.com/gui/url/' + Buffer.from(exact).toString('base64url'));
  }
  for (const value of ['javascript:alert(1)', 'example.invalid', 'https://', 'not a url', '']) assert.equal(entities.virusTotal.url(value), null);
  for (const address of ['10.0.0.5', '172.16.4.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '::1', 'fe80::1', 'fd00::1']) assert.equal(entities.link({key: 'ip', value: address}), null, address);
  assert.equal(entities.kind({key: 'x', value: '999.1.1.1'}), null);
  assert.equal(entities.kind({key: 'MITRE', value: '203.0.113.5', origin: 'mitre'}), null);
});

test('the report keeps metadata under its value and VirusTotal on the category line', () => {
  const {templates, pairs, formatter} = modules(), document = templates.emptyDocument();
  pairs.add(document, ['Adresse IP'], '98.56.54.185');
  pairs.add(document, ['File'], 'mail.txt');
  pairs.add(document, ['URL'], 'hxxps://auth-office365-update[.]com/login');
  pairs.add(document, ['User'], 'j.dupont');
  assert.equal(pairs.setMeta(document, idOf(document, '98.56.54.185'), 'country', 'nl').value, 'NL');
  pairs.setMeta(document, idOf(document, 'mail.txt'), 'filePath', ' C:\\Users\\j.dupont\\Downloads\\mail.txt ');
  pairs.setMeta(document, idOf(document, 'mail.txt'), 'fileHash', 'SHA256: ' + sha256.toUpperCase());
  pairs.setMeta(document, idOf(document, 'hxxps://auth-office365-update[.]com/login'), 'country', 'France');
  assert.equal(formatter.format(document), [
    '==================================================', '                     SUMMARY', '==================================================', '',
    'Adresse IP: 98.56.54.185 → VirusTotal',
    '└── Country     : NL 🇳🇱', '',
    'File: mail.txt → VirusTotal',
    '├── Path        : C:\\Users\\j.dupont\\Downloads\\mail.txt',
    '└── Hash SHA256 : ' + sha256, '',
    'URL: hxxps://auth-office365-update[.]com/login → VirusTotal',
    '└── Country     : FR 🇫🇷', '',
    'User: j.dupont'
  ].join('\n'));
  // No country, no Country line. A country is never guessed from the address or the domain.
  pairs.setMeta(document, idOf(document, '98.56.54.185'), 'country', '');
  assert.equal(Object.hasOwn(document.variables[0], 'country'), false);
  assert(formatter.format(document).includes('Adresse IP: 98.56.54.185 → VirusTotal\n\nFile:'));
  pairs.add(document, ['URL'], 'https://exemple.fr/login');
  assert(formatter.format(document).endsWith('URL: https://exemple.fr/login → VirusTotal'));
  assert(!formatter.format(document).includes('Domain      :'));
  assert.equal(formatter.summaryValues(document).split('\n').length, 5, 'Value-only copying is unchanged');
});

test('VirusTotal visibility is per category and survives saving, reparsing and duplicate merges', () => {
  const {templates,pairs,parser,formatter,entities,storage}=modules(), document=templates.emptyDocument();
  document.raw='IP: 98.56.54.185\nURL: https://example.invalid/path';
  parser.merge(document,parser.parse(document.raw));
  const [ip,url]=document.variables;
  ip.hideVirusTotal=true;
  assert.equal(formatter.sections(document)[0].fields[0].virusTotal,null);
  assert.equal(formatter.sections(document)[0].fields[1].virusTotal,entities.link(url));
  assert(formatter.format(document).includes('IP: 98.56.54.185\n\nURL: https://example.invalid/path → VirusTotal'));
  assert.equal(formatter.summaryValues(document),'98.56.54.185\nhttps://example.invalid/path');
  assert.equal(entities.link(ip),'https://www.virustotal.com/gui/ip-address/98.56.54.185','The editor logo can still open the report');
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  parser.merge(restored,parser.parse(restored.raw));
  assert.equal(restored.variables[0].hideVirusTotal,true);
  const source=pairs.add(restored,['Other URL'],'https://other.invalid').id;
  restored.variables.find(record=>record.id===source).hideVirusTotal=true;
  assert.equal(pairs.edit(restored,source,{value:url.value}).merged,true);
  assert.equal(restored.variables[1].hideVirusTotal,true);
  assert(!formatter.format(restored).includes('→ VirusTotal'));
  restored.variables[0].hideVirusTotal=false;
  assert(formatter.format(restored).includes('IP: 98.56.54.185 → VirusTotal'));
  assert.equal(storage.save(restored).ok,true);
  assert.notEqual(storage.load().document.variables[0].hideVirusTotal,true);
  restored.variables[0].hideVirusTotal='yes';
  assert.equal(storage.validate(restored),null);
});

test('upper-case country codes show a flag in the report unless hidden, and the choice is saved', () => {
  const {templates,pairs,formatter,storage}=modules(), document=templates.emptyDocument();
  for (const [key,value] of [['country','FR'],['direction','in'],['name','France'],['code','ZZ']]) pairs.add(document,[key],value);
  assert.deepEqual(Array.from(document.variables,pairs.countryFlag),['🇫🇷','','','']);
  assert(formatter.format(document).includes('country: FR 🇫🇷\n\ndirection: in\n\nname: France\n\ncode: ZZ'));
  assert.equal(formatter.summaryValues(document),'FR\nin\nFrance\nZZ','Copied values stay exact');
  document.variables[0].hideFlag=true;
  assert(formatter.format(document).includes('country: FR\n'));
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  assert.equal(restored.variables[0].hideFlag,true);
  assert.equal(pairs.edit(restored,restored.variables[0].id,{value:'DE'}).ok,true);
  assert(formatter.format(restored).includes('country: DE\n'),'Editing the code keeps the hidden choice');
  restored.variables[0].hideFlag=false;
  assert(formatter.format(restored).includes('country: DE 🇩🇪'));
  restored.variables[0].hideFlag='no';
  assert.equal(storage.validate(restored),null);
});

test('details stay with their own pair through saving, re-parsing, merging and removal', () => {
  const {templates, pairs, parser, storage} = modules(), document = templates.emptyDocument();
  document.raw = 'src: 203.0.113.7\ndst: 198.51.100.9';
  parser.merge(document, parser.parse(document.raw));
  pairs.setMeta(document, idOf(document, '203.0.113.7'), 'country', 'us');
  pairs.setMeta(document, idOf(document, '198.51.100.9'), 'country', 'Pays inconnu');
  document.raw += '\nuser: alice';
  parser.merge(document, parser.parse(document.raw));
  assert.deepEqual(Array.from(document.variables, record => record.country), ['US', 'Pays inconnu', undefined]);
  assert.equal(document.variables[0].origin, 'raw', 'A country does not turn a parsed value into a manual one');
  assert.equal(storage.save(document).ok, true);
  const restored = storage.load().document;
  assert.deepEqual(Array.from(restored.variables, record => record.country), ['US', 'Pays inconnu', undefined]);
  assert.equal(restored.schemaVersion, 4);
  // Editing one value onto another merges the pairs without replacing the kept country.
  pairs.add(restored, ['third'], '192.0.2.44');
  pairs.setMeta(restored, idOf(restored, '192.0.2.44'), 'country', 'DE');
  assert.equal(pairs.edit(restored, idOf(restored, '192.0.2.44'), {value: '203.0.113.7'}).merged, true);
  assert.equal(restored.variables.find(record => record.value === '203.0.113.7').country, 'US');
  for (const bad of [{country: 5}, {country: ''}, {country: 'x'.repeat(65)}, {filePath: 'a\nb'}, {fileHash: ['x']}]) {
    const broken = JSON.parse(JSON.stringify(document));
    Object.assign(broken.variables[0], bad);
    assert.equal(storage.validate(broken), null, JSON.stringify(bad));
  }
  assert.equal(pairs.setMeta(document, 'missing', 'country', 'FR').ok, false);
  assert.equal(pairs.setMeta(document, document.variables[0].id, 'value', 'x').ok, false);
});

test('JSON geo fields join the IP or URL of the same context and are never assigned arbitrarily', () => {
  const {templates, jsonImport, pairs} = modules(), document = templates.emptyDocument();
  const data = [
    {'source.ip': '98.56.54.185', 'source.geo.country_iso_code': 'nl', 'source.geo.country_name': 'Netherlands', 'destination.ip': '203.0.113.20', 'destination.geo.country_name': 'France', 'user.name': 'alice'},
    {'client.ip': '198.51.100.4', 'client.geo.country_iso_code': 'US'},
    {'url.full': 'https://login.example.invalid/a', 'geo.country_iso_code': 'DE'},
    {'host.ip': ['192.0.2.1', '192.0.2.2'], 'host.geo.country_iso_code': 'BE'},
    {'a.ip': '192.0.2.10', 'b.ip': '192.0.2.11', 'geo.country_iso_code': 'ES'},
    {'user.geo.country_iso_code': 'IT', 'server.ip': '192.0.2.30'}
  ];
  const result = jsonImport.importJSON(document, data);
  assert.equal(result.ok, true);
  const country = value => document.variables.find(record => record.value === value)?.country;
  assert.equal(country('98.56.54.185'), 'NL');
  assert.equal(country('203.0.113.20'), 'FR');
  assert.equal(country('198.51.100.4'), 'US');
  assert.equal(country('https://login.example.invalid/a'), 'DE');
  for (const value of ['192.0.2.1', '192.0.2.2', '192.0.2.10', '192.0.2.11', '192.0.2.30']) assert.equal(country(value), undefined, value);
  // Linked fields are absorbed; ambiguous or unrelated ones stay ordinary pairs.
  const keys = document.variables.flatMap(record => pairs.keys(record));
  for (const key of ['source.geo.country_iso_code', 'source.geo.country_name', 'destination.geo.country_name', 'client.geo.country_iso_code']) assert(!keys.includes(key), key);
  assert.equal(document.variables.find(record => record.value === 'BE').key, 'host.geo.country_iso_code');
  assert.equal(document.variables.find(record => record.value === 'ES').key, 'geo.country_iso_code');
  assert.equal(document.variables.find(record => record.value === 'IT').key, 'user.geo.country_iso_code');
  const snapshot = JSON.stringify(document.variables);
  assert.equal(jsonImport.importJSON(document, data).count, 0);
  assert.equal(JSON.stringify(document.variables), snapshot);
  // A country can still be set, changed or removed after the import; a later import does not replace it.
  pairs.setMeta(document, idOf(document, '98.56.54.185'), 'country', 'GB');
  assert.equal(jsonImport.importJSON(document, {'source.ip': '98.56.54.185', 'source.geo.country_iso_code': 'NL'}).ok, true);
  assert.equal(country('98.56.54.185'), 'GB');
  assert.equal(document.variables.find(record => record.value === 'NL').key, 'source.geo.country_iso_code');
});

test('JSON file fields form one file with its path and strongest hash, without mixing files', () => {
  const {templates, jsonImport, formatter, remediationEngine} = modules(), document = templates.emptyDocument();
  const md5 = 'd41d8cd98f00b204e9800998ecf8427e', other = 'a'.repeat(64);
  const result = jsonImport.importJSON(document, {attachments: [
    {'file.name': 'mail.txt', 'file.path': 'C:\\Users\\j.dupont\\Downloads\\mail.txt', 'file.hash.sha256': sha256, 'file.hash.md5': md5},
    {'file.name': 'invoice.pdf', 'file.hash.sha256': other}
  ], 'process.hash.sha256': 'b'.repeat(64)});
  assert.equal(result.ok, true);
  const file = name => document.variables.find(record => record.value === name);
  assert.equal(file('mail.txt').filePath, 'C:\\Users\\j.dupont\\Downloads\\mail.txt');
  assert.equal(file('mail.txt').fileHash, sha256);
  assert.equal(file('invoice.pdf').fileHash, other);
  assert.equal(file('invoice.pdf').filePath, undefined);
  assert.deepEqual(Array.from(document.variables, record => record.key), ['file.name', 'file.hash.md5', 'file.name2', 'process.hash.sha256']);
  const report = formatter.format(document);
  assert(report.includes('file.name: mail.txt → VirusTotal\n├── Path        : C:\\Users\\j.dupont\\Downloads\\mail.txt\n└── Hash SHA256 : ' + sha256));
  assert(report.includes('process.hash.sha256: ' + 'b'.repeat(64) + ' → VirusTotal'));
  // Remediation variables still see the path and hash carried by the file.
  const values = remediationEngine.values(document);
  assert.equal(values.FILE, 'mail.txt / C:\\Users\\j.dupont\\Downloads\\mail.txt / invoice.pdf');
  assert(values.HASH.includes(sha256) && values.HASH.includes(other) && values.HASH.includes(md5));
  assert.equal(jsonImport.importJSON(document, {attachments: [{'file.name': 'mail.txt', 'file.hash.sha256': sha256}]}).count, 0);
  // The same name with a different hash is another file: nothing is overwritten.
  assert.equal(jsonImport.importJSON(document, {'file.name': 'mail.txt', 'file.hash.sha256': 'c'.repeat(64)}).ok, true);
  assert.equal(file('mail.txt').fileHash, sha256);
  assert.equal(file('c'.repeat(64)).key, 'file.hash.sha256');
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
function modules() {
  const saved = new Map();
  const window = {crypto: {randomUUID}, localStorage: {
    getItem: key => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value), removeItem: key => saved.delete(key)
  }};
  const context = vm.createContext({window, URL});
  for (const file of ['templates', 'summary-data', 'extractors', 'parser', 'defang', 'remediation-data', 'remediation-engine', 'formatter', 'storage']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../js', file + '.js'), 'utf8'), context);
  }
  return window.SOCNote;
}

test('time zone controls recognize valid dates and labeled Unix timestamps without guessing IDs', () => {
  const {pairs} = modules();
  for (const value of ['2026-10-14', '2024-02-29T23:12:00.123456Z', '14/10/2026 23:12:00 +02:00', '14.10.2026', '14-10-2026 23:12']) {
    assert.equal(pairs.isDate({key:'Event', value}),true,value);
  }
  for (const value of ['2026-02-29', '2026-04-31', '2026-10-14T24:00:00Z', '2026-10-14T23:12:00+02:99', 'tomorrow', '20261014', 'https://example.invalid/2026-10-14']) {
    assert.equal(pairs.isDate({key:'timestamp', value}),false,value);
  }
  for (const key of ['timestamp', 'event.timestamp', 'timestamp_ms', 'Date', 'createdAt', 'detected_at']) {
    for (const value of ['1791885600', '1791885600123']) assert.equal(pairs.isDate({key, value}),true,key);
  }
  assert.equal(pairs.isDate({key:'alert_id', value:'1791885600'}),false);
  assert.equal(pairs.isDate({key:'Hash', value:'1791885600123'}),false);
});

test('reports append the selected time zone in parentheses while value copying stays exact', () => {
  const {templates,pairs,formatter} = modules(), document = templates.emptyDocument();
  const parent = pairs.add(document,['Event'],'event').id;
  const id = pairs.add(document,['timestamp'],'2026-10-14T23:12:00Z',parent).id;
  const record = document.variables.find(record=>record.id===id);
  assert(formatter.format(document).includes('Event: event\n└── timestamp: 2026-10-14T23:12:00Z (UTC)'));
  assert.equal(formatter.summaryValues(document),'event\n2026-10-14T23:12:00Z');
  record.timeZone = 'UTC+5:45';
  assert(formatter.format(document).includes('2026-10-14T23:12:00Z (UTC+5:45)'));
  record.hideTimeZone = true;
  assert(!formatter.format(document).includes('(UTC'));
  assert(formatter.format(document).includes('timestamp: 2026-10-14T23:12:00Z'));
  record.hideTimeZone = false;
  record.timeZone = '';
  assert(!formatter.format(document).includes('()'));
  assert(!formatter.format(document).includes('(UTC'));
  record.timeZone = 'UTC';
  pairs.edit(document,id,{value:'no date'});
  assert(!formatter.format(document).includes('(UTC)'),'A non-date value cannot acquire a time zone suffix');
  assert.equal(record.value,'no date');
});

test('time zone and visibility choices survive reload, re-parsing and duplicate-value merging', () => {
  const {templates,pairs,parser,storage,formatter} = modules(), document = templates.emptyDocument();
  document.raw = 'timestamp: 2026-10-14T23:12:00Z\nDate: 14/10/2026';
  parser.merge(document,parser.parse(document.raw));
  document.variables[0].timeZone = 'UTC+2';
  document.variables[0].hideTimeZone = true;
  document.variables[1].timeZone = '';
  parser.merge(document,parser.parse(document.raw));
  assert.equal(document.variables[0].timeZone,'UTC+2');
  assert.equal(document.variables[0].hideTimeZone,true);
  assert.equal(document.variables[1].timeZone,'');
  assert.equal(storage.save(document).ok,true);
  const restored = storage.load().document;
  assert.equal(restored.variables[0].timeZone,'UTC+2');
  assert.equal(restored.variables[0].hideTimeZone,true);
  assert.equal(restored.variables[1].timeZone,'','The empty option is distinct from the UTC default');
  assert(!formatter.format(restored).includes('(UTC'));
  const source = pairs.add(restored,['Other'],'2026-10-15').id;
  const sourceRecord = restored.variables.find(record=>record.id===source);
  sourceRecord.timeZone = 'UTC-4';
  sourceRecord.hideTimeZone = true;
  const target = pairs.add(restored,['Target'],'2026-10-16').id;
  pairs.edit(restored,source,{value:'2026-10-16'});
  assert.equal(restored.variables.find(record=>record.id===target).timeZone,'UTC-4');
  assert.equal(restored.variables.find(record=>record.id===target).hideTimeZone,true);
  assert.equal(storage.save(restored).ok,true);
});

test('draft validation rejects invalid time zones and visibility flags while old drafts default to UTC', () => {
  const {templates,pairs,storage,formatter} = modules(), document = templates.emptyDocument();
  pairs.add(document,['Date'],'2026-10-14');
  assert(formatter.format(storage.validate(document)).endsWith('Date: 2026-10-14 (UTC)'));
  for (const timeZone of [null, 2, true, 'Europe/Paris', 'UTC+25', '<img src=x>']) {
    const broken = JSON.parse(JSON.stringify(document));
    broken.variables[0].timeZone = timeZone;
    assert.equal(storage.validate(broken),null);
  }
  for (const hideTimeZone of [null, 1, 'yes']) {
    const broken = JSON.parse(JSON.stringify(document));
    broken.variables[0].hideTimeZone = hideTimeZone;
    assert.equal(storage.validate(broken),null);
  }
  document.variables[0].timeZone = '';
  document.variables[0].hideTimeZone = false;
  assert(storage.validate(document));
});

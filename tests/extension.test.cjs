const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {randomUUID, webcrypto} = require('node:crypto');
require('../js/json-import.js');
require('../extension/capture-data.js');
const {create, KEY, LEASE_MS} = require('../extension/capture-queue.js');

function session() {
  const saved = {};
  let blocked = false;
  return {
    saved,
    block(value) { blocked = value; },
    async get(key) { return structuredClone({[key]: saved[key]}); },
    async set(values) { if (blocked) throw Error('Quota'); Object.assign(saved, structuredClone(values)); }
  };
}
const source = (id, value = '185.10.20.5', extra = {}) => ({id, value, timestamp: 1000, tabId: 1, windowId: 1, title: 'SIEM', url: 'https://siem.example/alert', context: '', ...extra});
const owner = (tabId, clientId = 'client-' + tabId) => ({tabId, clientId, windowId: tabId});
function model({blocked = false} = {}) {
  const saved = new Map();
  const window = {crypto: {randomUUID}, localStorage: {
    getItem: key => saved.get(key) ?? null,
    setItem: (key, value) => { if (blocked) throw Error('Quota'); saved.set(key, value); },
    removeItem: key => saved.delete(key)
  }};
  const context = vm.createContext({window, URL});
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../extension/capture-data.js'), 'utf8'), context);
  for (const file of ['templates','country','summary-data','json-import','extractors','defang','parser','remediation-data','remediation-engine','remediation-storage','formatter','storage']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../js',file+'.js'),'utf8'),context);
  return {...window.SOCNote, saved};
}

test('several source tabs/windows and concurrent events share one lossless session queue', async () => {
  const storage = session();
  const queue = create({storage, isFocused: async () => true});
  await Promise.all(Array.from({length: 80}, (_, index) => queue.enqueue(source('c' + index, 'IP: 192.0.2.' + index, {timestamp: index, tabId: index + 1, windowId: index % 4 + 1}))));
  const records = (await queue.snapshot()).captures;
  assert.equal(records.length, 80);
  assert.equal(new Set(records.map(record => record.tabId)).size, 80);
  assert.equal(new Set(records.map(record => record.windowId)).size, 4);
  assert.deepEqual(records.map(record => record.timestamp), Array.from({length:80},(_,i)=>i));
});

test('only the currently focused Note Builder claims captures; focus changes transfer ownership', async () => {
  const storage = session();
  let focused = 10;
  const queue = create({storage, isFocused: async tabId => tabId === focused});
  await queue.enqueue(source('one'));
  assert.equal(await queue.claim(owner(20)), null);
  const first = await queue.claim(owner(10));
  assert.equal((await queue.snapshot()).captures[0].state, 'claimed');
  focused = 20;
  const second = await queue.claim(owner(20));
  assert.notEqual(first.token, second.token);
  assert.equal(await queue.acknowledge(owner(10), first.token, first.ids), false);
  assert.equal(await queue.acknowledge(owner(20), second.token, second.ids), true);
  assert.equal((await queue.snapshot()).captures.length, 0);
});

test('simultaneous consumers cannot obtain two claims, even if a focus provider misreports both', async () => {
  const queue = create({storage: session(), isFocused: async () => true});
  await queue.enqueue(source('one'));
  const claims = await Promise.all([queue.claim(owner(10)), queue.claim(owner(20))]);
  assert.equal(claims.filter(Boolean).length, 1);
});

test('requests never delete data; reload and worker restart recover an unacknowledged claim', async () => {
  const storage = session();
  const firstWorker = create({storage, isFocused: async () => true});
  await firstWorker.enqueue(source('one'));
  const first = await firstWorker.claim(owner(10, 'before-reload'));
  assert.equal(storage.saved[KEY].captures.length, 1);
  const restarted = create({storage, isFocused: async () => true});
  const recovered = await restarted.claim(owner(10, 'after-reload'));
  assert.notEqual(first.token, recovered.token);
  assert.equal(recovered.captures[0].id, 'one');
  assert.equal(await restarted.acknowledge(owner(10, 'after-reload'), recovered.token, []), false);
  assert.equal(await restarted.acknowledge(owner(10, 'after-reload'), recovered.token, recovered.ids), true);
});

test('expired leases and closed owner windows make captures available again', async () => {
  let clock = 1000;
  const storage = session();
  const queue = create({storage, isFocused: async () => true, now: () => clock});
  await queue.enqueue(source('one'));
  const first = await queue.claim(owner(10));
  clock += LEASE_MS + 1;
  const second = await queue.claim(owner(20));
  assert.notEqual(first.token, second.token);
  assert.equal(second.captures.length, 1);
});

test('captures arriving while a batch is claimed survive acknowledgement of that batch', async () => {
  const queue = create({storage: session(), isFocused: async () => true});
  await queue.enqueue(source('one'));
  const claimed = await queue.claim(owner(10));
  await queue.enqueue(source('two', '192.0.2.2'));
  await queue.acknowledge(owner(10), claimed.token, claimed.ids);
  assert.equal((await queue.snapshot()).captures[0].id, 'two');
});

test('storage failures retain the queue and never falsely acknowledge an import', async () => {
  const storage = session();
  const queue = create({storage, isFocused: async () => true});
  await queue.enqueue(source('one'));
  const claimed = await queue.claim(owner(10));
  storage.block(true);
  await assert.rejects(queue.acknowledge(owner(10), claimed.token, claimed.ids));
  assert.equal(storage.saved[KEY].captures.length, 1);
  storage.block(false);
  assert.equal(await queue.acknowledge(owner(10), claimed.token, claimed.ids), true);
});

test('capture classification recognizes unambiguous values but leaves bare usernames and malformed IPs Unknown', () => {
  const {extractors, parser} = model();
  const fixtures = [['185.10.20.5','IP'],['2001:db8::1','IP'],['https://example.invalid/path','URL'],['host.example.invalid','Domain'],['alice@example.invalid','Email'],['a'.repeat(64),'Hash'],['powershell.exe','Process'],['C:\\Logs\\alert.log','File'],['powershell.exe -NoProfile -File test.ps1','Command line'],['jdupont','Unknown'],['PC-0042','Unknown'],['999.10.20.5','Unknown']];
  for (const [value, type] of fixtures) assert.equal(extractors.classify(value), type, value);
  assert.equal(extractors.classify('jdupont', 'Username'), 'User');
  assert.equal(extractors.classify('PC-0042', 'Host name'), 'Hostname');
  assert.equal(parser.parse('185.10.20.5\njdupont').variables.length, 0, 'Existing Logs still require explicit fields');
});

test('a captured country code or flag gets the Country key; lower-case words and names do not', () => {
  const {extractors, parser, templates, formatter} = model();
  for (const value of ['FR', 'US', ' DE ']) assert.equal(extractors.classify(value), 'Country', value);
  for (const value of ['fr', 'in', 'France', 'ZZ', 'EU']) assert.notEqual(extractors.classify(value), 'Country', value);
  assert.deepEqual(Array.from(parser.parse('🇫🇷', {capture: true}).variables, field => [field.key, field.value]), [['Country', 'FR']]);
  assert.deepEqual(Array.from(parser.parse('Pays: FR', {capture: true}).variables, field => field.key), ['Pays'], 'An explicit label is kept');
  const document = templates.emptyDocument();
  const source = {method: 'selection', timestamp: Date.now(), tabId: 1, windowId: 1, title: 'Page', url: 'https://example.invalid/', context: ''};
  assert.equal(parser.importCaptures(document, [{...source, id: 'c1', value: 'FR\nDE'}]).ok, true);
  assert.deepEqual(Array.from(document.variables, record => record.key + '=' + record.value + '=' + record.captureType), ['Country=FR=Country', 'Country 2=DE=Country']);
  assert(formatter.format(document).includes('Country: FR 🇫🇷\n\nCountry 2: DE 🇩🇪'));
});

test('date captures validate calendar days and times without changing the original representation',()=>{
  const {extractors,parser}=model();
  for(const value of ['2026-10-13','2024-02-29T08:15:30.123Z','13/10/2026 08:15:30 +02:00','13-10-2026 08:15','13.10.2026','2000-02-29 00:00:00 UTC']) {
    assert.equal(extractors.classify(value),'Date',value);
    const record=parser.parse(value,{capture:true}).variables[0];
    assert.equal(record.key,'Date');
    assert.equal(record.value,value);
  }
  for(const value of ['2026-02-29','1900-02-29','2026-04-31','2026-13-01','2026-00-01','2026-10-00','0000-01-01','13/10/2026 24:00','2026-10-13T08:60:00Z','2026-10-13T08:00:00+02:99','20261013','1791885600','13/10','2026-10-13 arbitrary text']) assert.equal(extractors.classify(value),'Unknown',value);
});

test('UUID and Windows SID captures recognize bounded complete identifiers and reject malformed values',()=>{
  const {extractors}=model();
  for(const value of ['550e8400-e29b-41d4-a716-446655440000','{550E8400-E29B-41D4-A716-446655440000}','urn:uuid:550e8400-e29b-41d4-a716-446655440000','00000000-0000-0000-0000-000000000000']) assert.equal(extractors.classify(value),'UUID',value);
  for(const value of ['S-1-5-18','S-1-5-21-3623811015-3361044348-30300820-1013','S-1-0-0','S-1-0x010000000000-1','S-1-5-4294967295']) assert.equal(extractors.classify(value),'SID',value);
  for(const value of ['550e8400-e29b-41d4-a716-44665544000','{550e8400-e29b-41d4-a716-446655440000','S-1-5','S-2-5-18','S-1-05-18','S-1-5-4294967296','S-1-4294967296-18','S-1-5-'+Array(16).fill('1').join('-')]) assert.equal(extractors.classify(value),'Unknown',value);
  assert.equal(extractors.classify('550e8400e29b41d4a716446655440000'),'Hash','Compact hex remains a hash without guessing UUID');
});

test('EDR Action recognizes mitigation status while generic booleans and actions need an EDR label',()=>{
  const {extractors,parser}=model();
  for(const value of ['Mitigated','Not mitigated','Unmitigated','NOT_MITIGATED','Non atténué']) {
    assert.equal(extractors.classify(value),'EDR Action',value);
    assert.equal(parser.parse(value,{capture:true}).variables[0].value,value);
  }
  for(const value of ['true','false','Blocked','Allowed','Success']) {
    assert.equal(extractors.classify(value),'Unknown',value);
    assert.equal(extractors.classify(value,'EDR Action'),'EDR Action');
  }
  assert.equal(extractors.classify('false','mitigation_status'),'EDR Action');
  const explicit=parser.parse('EDR Action: Not mitigated',{capture:true}).variables[0];
  assert.equal(explicit.key,'EDR Action');
  assert.equal(explicit.captureType,'EDR Action');
});

test('new capture types number distinct values and survive storage and report generation',()=>{
  const {templates,parser,storage,formatter}=model();
  const document=templates.emptyDocument();
  const values=['2026-10-13','2026-10-14','550e8400-e29b-41d4-a716-446655440000','S-1-5-18','Mitigated','Not mitigated'];
  const records=values.map((value,index)=>source('new-type-'+index,value));
  assert.equal(parser.importCaptures(document,records).ok,true);
  assert.deepEqual(Array.from(document.variables,item=>item.key),['Date','Date 2','UUID','SID','EDR Action','EDR Action 2']);
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  assert.deepEqual(Array.from(restored.variables,item=>item.value),values);
  assert.deepEqual(Array.from(restored.variables,item=>item.captureType),['Date','Date','UUID','SID','EDR Action','EDR Action']);
  assert(formatter.format(restored).includes('EDR Action 2: Not mitigated'));
  assert.equal(parser.parse(values.join('\n')).variables.length,0,'Bare values in ordinary Logs still need explicit keys');
});

test('capture imports use the existing parser, number distinct fields, and preserve all authored state', () => {
  const {templates, parser, remediationEngine} = model();
  const document = templates.demoDocument();
  const before = structuredClone(document);
  const result = parser.importCaptures(document, [source('one'),source('two','192.0.2.2'),source('three','192.0.2.3'),source('four','jdupont'),source('five','Host: HOST-1\nUser: alice')]);
  assert.equal(result.ok, true);
  const ips = document.variables.filter(record => record.captureType === 'IP');
  assert.deepEqual(Array.from(ips, record => record.key), ['IP','IP 2','IP 3']);
  assert.equal(document.variables.find(record => record.value === 'jdupont').key, 'Unknown');
  for (const key of ['rule','raw','capturedRaw','sourceFileName','analysis','remediation']) assert.equal(JSON.stringify(document[key]), JSON.stringify(before[key]));
  assert(remediationEngine.values(document).IP.includes('192[.]0[.]2[.]3'), 'Numbered fields still resolve through existing remediation aliases');
});

test('duplicate values appear once while different capture sources and durable receipt IDs survive reload', () => {
  const {templates, parser, storage, formatter} = model();
  const document = templates.emptyDocument();
  const captures = [source('one'),source('two','185.10.20.5',{tabId:2,windowId:2,title:'EDR',url:'https://edr.example/event'})];
  parser.importCaptures(document, captures);
  assert.equal(document.variables.length, 1);
  assert.equal(document.extensionCaptures.length, 2);
  assert.equal(storage.save(document).ok, true);
  const restored = storage.load().document;
  assert.equal(parser.importCaptures(restored, captures).count, 0);
  assert.equal(restored.variables.length, 1);
  assert.equal(restored.extensionCaptures[1].title, 'EDR');
  assert(!formatter.format(restored).includes('https://edr.example/event'), 'Provenance stays out of the report');
});

test('capture import allows deleted values again while retaining live duplicates and URL defanging', () => {
  const {templates, parser, pairs, formatter} = model();
  const document = templates.emptyDocument();
  pairs.add(document, ['destination_ip'], '185.10.20.5');
  parser.importCaptures(document,[source('one'),source('url','https://example.invalid/path')]);
  assert.equal(document.variables[0].key,'destination_ip');
  document.variables[1].defangUrl = true;
  assert(formatter.format(document).includes('hxxps://example[.]invalid/path'));
  const removed=document.variables[0];
  const retained=document.variables[1];
  pairs.remove(document,removed.id);
  assert.equal(document.ignoredValues.includes(removed.value),false);
  assert.equal(parser.importCaptures(document,[source('one')]).count,0,'A prior receipt cannot replay a deleted value');
  assert.equal(document.variables.length,1);
  parser.importCaptures(document,[source('another')]);
  assert(document.variables.some(record => record.value === '185.10.20.5' && record.id!==removed.id));
  assert.equal(document.variables[0].id,retained.id);
  assert.equal(document.variables[0].defangUrl,true);
  assert.equal(document.extensionCaptures.length,3);
  parser.importCaptures(document,[source('repeat')]);
  assert.equal(document.variables.length,2,'Live values remain deduplicated');
});

test('untrusted metadata is validated; oversized selections fail without partial imports', () => {
  const {templates, parser, storage} = model();
  const document = templates.emptyDocument();
  assert.equal(parser.importCaptures(document,[source('bad','a'.repeat(500001))]).ok,false);
  assert.equal(document.variables.length,0);
  assert.equal(parser.importCaptures(document,[source('valid'),source('too-many',Array.from({length:201},(_,i)=>'key: value-'+i).join('\n'))]).ok,false);
  assert.equal(document.variables.length,0);
  assert.equal(storage.validate({...document,extensionCaptures:[source('bad','valid',{timestamp:'yesterday'})]}),null);
});

test('literal HTML and script-like text remain data in parser, storage and report', () => {
  const {templates, parser, storage, formatter} = model();
  const document = templates.emptyDocument();
  const attack = '<img src=x onerror=alert(1)>';
  parser.importCaptures(document,[source('literal',attack)]);
  assert.equal(document.variables[0].value,attack);
  assert.equal(storage.save(document).ok,true);
  assert(formatter.format(storage.load().document).includes(attack));
});

test('the SIEM content script installs one JSON receiver in the page', () => {
  const listeners = [];
  const window = {addEventListener: (type, handler) => listeners.push(type)};
  const context = vm.createContext({window, location: {origin: 'https://siem.example.invalid'}, chrome: {runtime: {}}});
  context.globalThis = context;
  for (const file of ['json-receiver', 'json-receiver-start']) vm.runInContext(fs.readFileSync(path.join(__dirname, '../extension', file + '.js'), 'utf8'), context);
  vm.runInContext('installSOCJSONReceiver()', context);
  assert.deepEqual(listeners, ['message'], 'A later activation does not add a second receiver');
});

test('manifest requests only gesture-scoped capture permissions and page access limited to one SIEM JSON receiver', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname,'../manifest.json'),'utf8'));
  assert.equal(manifest.manifest_version,3);
  assert.deepEqual(manifest.permissions.sort(),['activeTab','clipboardRead','clipboardWrite','offscreen','scripting','storage']);
  assert.equal(manifest.host_permissions,undefined);
  // The only permanent page access is the JSON receiver on one https SIEM address (CHANGEME until set).
  assert.equal(manifest.content_scripts.length,1);
  const [receiver]=manifest.content_scripts;
  assert.deepEqual(receiver.js,['extension/json-receiver.js','extension/json-receiver-start.js']);
  assert.equal(receiver.run_at,'document_start');
  assert.equal(receiver.matches.length,1);
  assert.match(receiver.matches[0],/^https:\/\/[^*/]+\/.*$/,'One https host, without wildcard hosts or <all_urls>');
  assert.equal(manifest.externally_connectable,undefined);
  assert.equal(manifest.commands['capture-selection'].suggested_key.default,'Ctrl+Shift+X');
  assert.deepEqual(Object.keys(manifest.commands),['capture-selection']);
});

function workerHarness(selected = {value:'185.10.20.5',context:'Source IP',focused:true}, {focusedTabId=10,focusedWindowId=1,clipboardText='',clipboardAllowed=true,clipboardWriteAllowed=clipboardAllowed} = {}) {
  const storage = session(), listeners = {}, targets = [], shortcutTargets = [], jsonTargets = [];
  let title = '', refuseInjection = false, offscreenOpen = false, clipboardReads = 0;
  const clipboardWrites = [];
  const event = name => ({addListener(listener) {listeners[name] = listener;}});
  const chrome = {
    runtime: {id:'test-extension', getURL: file=>'chrome-extension://test-extension/'+file,
      onInstalled:event('installed'),onStartup:event('startup'),onMessage:event('message'),
      getContexts:async filter=>filter.contextTypes.includes('OFFSCREEN_DOCUMENT') ? (offscreenOpen ? [{documentUrl:'chrome-extension://test-extension/extension/clipboard-reader.html'}] : []) : [{tabId:10,windowId:1,documentId:'builder-document'}],
      sendMessage:async message=>{
        if(message.type==='write') {clipboardWrites.push(message.text);clipboardText=message.text;return {ok:true,requestId:message.requestId};}
        clipboardReads++;return {ok:true,requestId:message.requestId,text:clipboardText};}},
    permissions:{contains:async request=>request.permissions[0]==='clipboardWrite'?clipboardWriteAllowed:clipboardAllowed},
    offscreen:{createDocument:async()=>{assert.equal(offscreenOpen,false);offscreenOpen=true;},closeDocument:async()=>{offscreenOpen=false;}},
    storage:{session:{...storage,setAccessLevel:async()=>{}},onChanged:event('storage')},
    commands:{onCommand:event('command')},
    action:{onClicked:event('action'),setBadgeText:async()=>{},setBadgeBackgroundColor:async()=>{},setTitle:async value=>{title=value.title;}},
    windows:{getLastFocused:async()=>({id:focusedWindowId,focused:true})},
    tabs:{get:async id=>({id,windowId:focusedWindowId,active:id===focusedTabId}),query:()=>{throw Error('Do not guess the source tab');}},
    scripting:{executeScript:async options=>{
      const isShortcut = options.func.name === 'installSOCClipboardShortcut';
      (isShortcut ? shortcutTargets : options.func.name === 'installSOCJSONReceiver' ? jsonTargets : targets).push(options.target);
      if(refuseInjection)throw Error('Restricted frame');
      return isShortcut ? [] : selected?[{frameId:options.target.frameIds?.[0] || 0,result:selected}]:[];
    }}
  };
  const context = vm.createContext({chrome,crypto:{randomUUID,subtle:webcrypto.subtle},URL,TextEncoder,setTimeout,clearTimeout});
  context.importScripts = (...files) => files.forEach(file=>vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension',file),'utf8'),context));
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/service-worker.js'),'utf8'),context);
  return {listeners,targets,shortcutTargets,jsonTargets,refuse(){refuseInjection=true;},title:()=>title,
    clipboardReads:()=>clipboardReads,clipboardWrites,clipboardText:()=>clipboardText,offscreenOpen:()=>offscreenOpen,
    capture:tab=>context.captureCommand(tab),captureClipboard:tab=>context.captureClipboard(tab),
    snapshot:()=>vm.runInContext('queue.snapshot()',context),
    async settle() {for(let i=0;i<20;i++)await new Promise(resolve=>setImmediate(resolve));}};
}

test('registered shortcut uses its supplied tab across windows and never queries another active tab', async () => {
  const worker = workerHarness();
  for (const tab of [{id:21,windowId:7,title:'SIEM',url:'https://siem.example/'},{id:22,windowId:8,title:'EDR',url:'https://edr.example/'}]) worker.listeners.command('capture-selection',tab);
  await worker.settle();
  const captures = (await worker.snapshot()).captures;
  assert.equal(captures.length,2);
  assert.deepEqual(Array.from(captures,record=>record.tabId),[21,22]);
  assert.deepEqual(Array.from(captures,record=>record.windowId),[7,8]);
  assert.deepEqual(worker.targets.map(target=>target.tabId),[21,22]);
});

test('removed commands and the context menu cannot trigger capture', async () => {
  const worker = workerHarness();
  assert.equal(worker.listeners.menu,undefined);
  worker.listeners.command('capture-clipboard',{id:22,windowId:8,url:'https://identity.example/'});
  await worker.settle();
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal(worker.clipboardReads(),0);
  assert.equal(worker.clipboardWrites.length,0);
});

test('an empty clipboard and no readable selection create no capture, including restricted pages', async () => {
  const worker=workerHarness(null);
  worker.listeners.command('capture-selection',{id:21,windowId:7,url:'https://siem.example/'});
  worker.listeners.command('capture-selection',{id:22,windowId:8,url:'chrome://settings/'});
  worker.listeners.command('capture-selection',{id:23,windowId:8,url:'edge://extensions/'});
  worker.listeners.command('capture-selection',undefined);
  await worker.settle();
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal(worker.targets.length,1);
});

test('address-bar focus captures neither the URL nor a stale selection and leaves the clipboard untouched', async () => {
  const worker=workerHarness({value:'stale page text',context:'User',focused:false,url:'https://different-frame.example/'},{focusedTabId:21,focusedWindowId:7});
  const url='https://siem.example/alerts?id=42#details';
  worker.listeners.command('capture-selection',{id:21,windowId:7,title:'SIEM',url});
  await worker.settle();
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal(worker.clipboardReads(),0);
  assert.equal(worker.clipboardWrites.length,0);
});

test('a focused page with no selection does not silently capture its URL', async()=>{
  const worker=workerHarness({value:'',context:'',focused:true,url:'https://siem.example/'},{focusedTabId:21,focusedWindowId:7});
  worker.listeners.command('capture-selection',{id:21,windowId:7,url:'https://siem.example/'});
  await worker.settle();
  assert.equal((await worker.snapshot()).captures.length,0);
});

test('rapid window switching retains the event source selection instead of substituting another URL',async()=>{
  const worker=workerHarness({value:'selected source text',context:'',focused:false,url:'https://siem.example/'},{focusedTabId:22,focusedWindowId:8});
  worker.listeners.command('capture-selection',{id:21,windowId:7,url:'https://siem.example/'});
  await worker.settle();
  const captures=(await worker.snapshot()).captures;
  assert.equal(captures[0].value,'selected source text');
  assert.equal(captures[0].tabId,21);
  assert.equal(captures[0].windowId,7);
});

test('failed selection injection does not fall back to the clipboard',async()=>{
  const worker=workerHarness(undefined,{clipboardText:'Private clipboard'});
  worker.refuse();
  assert.equal((await worker.capture({id:21,windowId:7,url:'https://siem.example/'})).ok,false);
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal(worker.clipboardReads(),0);
  assert.equal(worker.clipboardText(),'Private clipboard');
});

test('selection reader reports browser focus even for an empty page or a password input',()=>{
  for (const activeElement of [{tagName:'BODY'},{tagName:'INPUT',type:'password'}]) {
    const context=vm.createContext({document:{title:'SIEM',hasFocus:()=>false,activeElement},location:{href:'https://siem.example/'},window:{getSelection:()=>({toString:()=>''})},Node:{ELEMENT_NODE:1}});
    vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/selection.js'),'utf8'),context);
    const result=vm.runInContext('readSOCSelection()',context);
    assert.equal(result.focused,false);
    assert.equal(result.url,'https://siem.example/');
    assert.equal(result.value,'');
  }
});

test('web-page messages cannot claim the capture queue or spoof a Note Builder document', async () => {
  const worker=workerHarness();
  const message={type:'soc-capture/claim',tabId:10,clientId:'client'};
  assert.equal(worker.listeners.message(message,{id:'test-extension',url:'https://siem.example/',frameId:0},()=>assert.fail('Unexpected response')),false);
  assert.equal(worker.listeners.message(message,{id:'another-extension',url:'chrome-extension://test-extension/index.html',frameId:0},()=>assert.fail('Unexpected response')),false);
  const response=await new Promise(resolve=>worker.listeners.message(message,{id:'test-extension',url:'chrome-extension://test-extension/index.html',frameId:0,documentId:'spoofed-document'},resolve));
  assert.equal(response.ok,false);
});

test('capturing an existing live-log value preserves it through subsequent log replacement',()=>{
  const {templates,parser}=model();
  const document=templates.emptyDocument();
  document.raw='source_ip: 185.10.20.5';
  parser.merge(document,parser.parse(document.raw));
  parser.importCaptures(document,[source('one')]);
  document.raw='Host: NEXT';
  parser.merge(document,parser.parse(document.raw));
  assert.equal(document.variables.find(record=>record.value==='185.10.20.5').key,'source_ip');
});

test('captured explicit blocks retain grouped network roles and numbered role aliases',()=>{
  const {templates,parser,remediationEngine}=model();
  const document=templates.emptyDocument();
  parser.importCaptures(document,[source('roles','source_ip: 192.0.2.1\ndestination_ip: 192.0.2.1\nsource_ip: 192.0.2.2')]);
  assert.equal(document.variables.length,2);
  assert.deepEqual(Array.from(document.variables[0].keys),['source_ip','destination_ip']);
  assert.equal(document.variables[1].key,'source_ip 2');
  assert.equal(remediationEngine.values(document).SRC_IP,'192[.]0[.]2[.]1 / 192[.]0[.]2[.]2');
  assert.equal(remediationEngine.values(document).DST_IP,'192[.]0[.]2[.]1');
  const ignored=templates.emptyDocument();
  ignored.ignoredKeys.push('source_ip');
  parser.importCaptures(ignored,[source('filtered','source_ip: 192.0.2.1\ndestination_ip: 192.0.2.1')]);
  assert.deepEqual(Array.from(ignored.variables[0].keys),['destination_ip']);
});

const captureTab = {id:21,windowId:7,title:'SIEM',url:'https://siem.example/'};

test('selection capture saves only the selection and copies it without reading the previous clipboard', async()=>{
  const clipboardText='URL: https://clipboard.example/\r\nIP: 192.0.2.88';
  const worker=workerHarness(undefined,{clipboardText});
  const result=await worker.capture(captureTab);
  assert.equal(result.count,1);
  const records=(await worker.snapshot()).captures;
  assert.deepEqual(Array.from(records,item=>item.method),['selection']);
  assert.equal(records[0].value,'185.10.20.5');
  assert.equal(records[0].tabId,captureTab.id);
  assert.equal(worker.clipboardReads(),0);
  assert.deepEqual(worker.clipboardWrites,['185.10.20.5']);
  assert.equal(worker.clipboardText(),'185.10.20.5');
  assert.equal(worker.offscreenOpen(),false);
  assert.equal(worker.shortcutTargets[0].tabId,captureTab.id);
});

test('selection copying preserves literal text and line breaks without clipboard-read permission', async()=>{
  const text='  <img src=x>\r\n\r\n    Indented\nLast line';
  const worker=workerHarness({value:text,focused:true},{clipboardAllowed:false,clipboardWriteAllowed:true});
  assert.equal((await worker.capture(captureTab)).count,1);
  assert.equal((await worker.snapshot()).captures.length,1);
  assert.equal(worker.clipboardReads(),0);
  assert.equal(worker.clipboardText(),text);
});

test('clipboard-only capture never injects, reads a selection or overwrites the clipboard',async()=>{
  const worker=workerHarness(undefined,{clipboardText:'Clipboard only'});
  assert.equal((await worker.captureClipboard(captureTab)).ok,true);
  const records=(await worker.snapshot()).captures;
  assert.equal(records.length,1);
  assert.equal(records[0].value,'Clipboard only');
  assert.equal(records[0].method,'clipboard');
  assert.equal(worker.targets.length,0);
  assert.equal(worker.shortcutTargets.length,0);
  assert.equal(worker.clipboardWrites.length,0);
  assert.equal(worker.clipboardText(),'Clipboard only');
});

test('selection capture with no readable selection never imports or overwrites the previous clipboard',async()=>{
  for (const tab of [captureTab,{...captureTab,url:'chrome://settings/'}]) {
    const worker=workerHarness(null,{clipboardText:'Clipboard fallback'});
    assert.equal((await worker.capture(tab)).ok,false);
    assert.equal((await worker.snapshot()).captures.length,0);
    assert.equal(worker.clipboardReads(),0);
    assert.equal(worker.clipboardText(),'Clipboard fallback');
    assert.equal(worker.offscreenOpen(),false);
  }
});

test('clipboard permission refusal preserves selection and reports clipboard-only failure',async()=>{
  const worker=workerHarness(undefined,{clipboardAllowed:false,clipboardText:'Do not read'});
  const selection=await worker.capture(captureTab);
  assert.equal(selection.ok,true);
  assert.equal(selection.count,1);
  assert.match(selection.warning,/clipboard copy unavailable/);
  const clipOnly=await worker.captureClipboard(captureTab);
  assert.equal(clipOnly.ok,false);
  assert.equal((await worker.snapshot()).captures.length,1);
  assert.equal(worker.clipboardReads(),0);
});

test('startup, installation and queue changes neither read nor write the clipboard',async()=>{
  const worker=workerHarness(undefined,{clipboardText:'Private clipboard'});
  worker.listeners.installed();
  worker.listeners.startup();
  worker.listeners.storage({[KEY]:{}},'session');
  await worker.settle();
  assert.equal(worker.clipboardReads(),0);
  assert.equal(worker.offscreenOpen(),false);
  assert.equal(worker.clipboardWrites.length,0);
  assert.equal((await worker.snapshot()).captures.length,0);
});

test('concurrent clipboard-only gestures serialize reads and retain every capture',async()=>{
  const worker=workerHarness(undefined,{clipboardText:'Repeated explicit capture'});
  await Promise.all(Array.from({length:12},()=>worker.captureClipboard(captureTab)));
  assert.equal(worker.clipboardReads(),12);
  assert.equal(worker.offscreenOpen(),false);
  assert.equal((await worker.snapshot()).captures.length,12);
});

test('a queued clipboard import waits for the preceding selection copy',async()=>{
  const worker=workerHarness(undefined,{clipboardText:'Previous clipboard'});
  const results=await Promise.all([worker.capture(captureTab),worker.captureClipboard(captureTab)]);
  assert(results.every(result=>result.ok));
  const records=(await worker.snapshot()).captures;
  assert.deepEqual(Array.from(records,record=>record.value),['185.10.20.5','185.10.20.5']);
  assert.deepEqual(Array.from(records,record=>record.method),['selection','clipboard']);
  assert.equal(worker.clipboardReads(),1);
  assert.deepEqual(worker.clipboardWrites,['185.10.20.5']);
});

test('an oversized selection is not copied when the queue rejects it',async()=>{
  const worker=workerHarness({value:'x'.repeat(500001),focused:true},{clipboardText:'Previous clipboard'});
  assert.equal((await worker.capture(captureTab)).ok,false);
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal(worker.clipboardText(),'Previous clipboard');
  assert.equal(worker.clipboardWrites.length,0);
});

test('only a focused authenticated Note Builder can request clipboard capture',async()=>{
  const worker=workerHarness(undefined,{clipboardText:'From tool'});
  const message={type:'soc-capture/clipboard',clientId:'client',tabId:10};
  const sender={id:'test-extension',url:'chrome-extension://test-extension/index.html',frameId:0,documentId:'builder-document'};
  const result=await new Promise(resolve=>worker.listeners.message(message,sender,resolve));
  assert.equal(result.ok,true);
  assert.equal(worker.clipboardReads(),1);
  assert.equal('text' in result,false);
  const background=workerHarness(undefined,{focusedTabId:22,clipboardText:'Do not read'});
  const denied=await new Promise(resolve=>background.listeners.message(message,sender,resolve));
  assert.equal(denied.ok,false);
  assert.equal(background.clipboardReads(),0);
  assert.equal(worker.listeners.message(message,{...sender,url:'https://siem.example/'},()=>assert.fail()),false);
});

test('clipboard provenance survives draft recovery without assigning a source field label',()=>{
  const {templates,parser,storage}=model();
  const document=templates.emptyDocument();
  assert.equal(parser.importCaptures(document,[source('clip','Bare clipboard text',{method:'clipboard'})]).ok,true);
  assert.equal(document.variables[0].key,'Unknown');
  assert.equal(storage.save(document).ok,true);
  assert.equal(storage.load().document.extensionCaptures[0].method,'clipboard');
  assert.equal(parser.importCaptures(document,[source('spoof','text',{method:'page-scrape'})]).ok,false);
});

test('page clipboard alias handles only a focused trusted Ctrl+Alt+X and is installed once',()=>{
  let handler, registrations=0, calls=0, focused=true, prevented=0;
  const context=vm.createContext({
    document:{hasFocus:()=>focused,addEventListener:(name,listener)=>{registrations++;handler=listener;}},
    chrome:{runtime:{sendMessage:async message=>{assert.equal(message.type,'soc-clipboard/hotkey');calls++;return {ok:true};}}}
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/clipboard-shortcut.js'),'utf8'),context);
  context.installSOCClipboardShortcut();context.installSOCClipboardShortcut();
  assert.equal(registrations,1);
  const key={isTrusted:true,repeat:false,ctrlKey:true,altKey:true,shiftKey:false,metaKey:false,key:'x',getModifierState:()=>false,preventDefault:()=>prevented++,stopPropagation:()=>{}};
  for (const change of [{isTrusted:false},{repeat:true},{shiftKey:true},{metaKey:true},{getModifierState:()=>true},{key:'c'}]) handler({...key,...change});
  focused=false;handler(key);focused=true;
  assert.equal(calls,0);
  handler(key);
  assert.equal(calls,1);
  assert.equal(prevented,1);
});

test('Tampermonkey JSON receive/status validates its source and deduplicates repeated sends after acknowledgement',async()=>{
  const worker=workerHarness();
  const sender={id:'test-extension',url:captureTab.url,tab:captureTab,frameId:0};
  const message={type:'soc-json/import',requestId:'siem-one',data:JSON.stringify([{'host.hostname':'ONE'},{'host.hostname':'TWO'}])};
  for(const change of [{id:'foreign'},{frameId:1},{tab:undefined},{url:'chrome://settings/'}]) assert.equal(worker.listeners.message(message,{...sender,...change},()=>assert.fail('Unexpected reply')),false);
  const send=(data,senderOverride=sender)=>new Promise(resolve=>worker.listeners.message(data,senderOverride,resolve));
  const results=await Promise.all([send(message),send(message)]);
  assert(results.every(result=>result.ok));
  assert.equal(results[0].status,'queued');assert.equal(results[1].duplicate,true);
  const pending=await worker.snapshot();
  assert.equal(pending.captures.length,1);
  assert.equal(pending.captures[0].method,'json');
  const status=await send({type:'soc-json/status',requestId:'siem-one'});
  assert.equal(status.status,'queued');
  const consumer={id:'test-extension',url:'chrome-extension://test-extension/index.html',frameId:0,documentId:'builder-document'};
  const claim=await send({type:'soc-capture/claim',tabId:10,clientId:'json-client'},consumer);
  assert.equal(claim.ok,true);
  assert.equal((await send({type:'soc-capture/ack',tabId:10,clientId:'json-client',token:claim.claim.token,ids:claim.claim.ids},consumer)).ok,true);
  assert.equal((await send(message)).status,'imported');
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal((await send({...message,data:'{"broken":'})).ok,false);
  assert.equal((await send({...message,data:'{"host.hostname":"DIFFERENT"}'})).ok,false);
  assert.equal((await send({type:'soc-json/status',requestId:'siem-one'},{...sender,url:'https://other.example/'})).ok,false);
  assert.equal(worker.clipboardReads(),0);assert.equal(worker.clipboardWrites.length,0);
});

test('malformed JSON selection and clipboard captures are reported before entering the queue',async()=>{
  const worker=workerHarness({value:'{"broken":',focused:true},{clipboardText:'{"also.broken":'});
  assert.equal((await worker.capture(captureTab)).ok,false);
  assert.equal((await worker.captureClipboard(captureTab)).ok,false);
  assert.equal((await worker.snapshot()).captures.length,0);
  assert.equal(worker.clipboardWrites.length,0);
  assert(worker.title().includes('Invalid JSON'));
});

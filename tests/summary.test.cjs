const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { randomUUID } = require('node:crypto');
function modules() {
  const saved = new Map();
  const window = { crypto: {randomUUID}, localStorage: {
    getItem: key => saved.get(key) ?? null, setItem: (key, value) => saved.set(key, value), removeItem: key => saved.delete(key)
  } };
  const context = vm.createContext({ window, URL });
  for (const file of ['templates', 'summary-data', 'extractors', 'parser', 'defang', 'remediation-data', 'remediation-engine', 'formatter', 'storage']) vm.runInContext(fs.readFileSync(path.join(__dirname, '../js', file + '.js'), 'utf8'), context);
  return {...window.SOCNote, saved};
}
function capture(document, parser, raw) { document.raw = raw; return parser.capture(document); }

test('multiple destination IPs create separate draggable records and duplicate IPs appear once', () => {
  const { templates, parser, formatter } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'destination_ip: 192.0.2.1\ndestination_ip: 192.0.2.2\ndestination_ip: 192.0.2.1');
  assert.equal(document.variables.length, 2);
  assert(document.variables.every(record => record.key === 'destination_ip'));
  assert.equal(formatter.body(document), 'destination_ip : 192.0.2.1\ndestination_ip : 192.0.2.2');
  assert.equal(formatter.summaryValues(document), '192.0.2.1\n192.0.2.2');
  assert.equal(new Set(document.variables.map(record => record.id)).size, 2);
});

test('one unique value can retain multiple keys without losing network roles', () => {
  const { templates, parser, formatter, remediationEngine: engine } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'src_ip: 192.0.2.1\ndst_ip: 192.0.2.1\nSRC_IP: 192.0.2.1');
  assert.equal(document.variables.length, 1);
  assert.equal(document.variables[0].keys.join(','), 'src_ip,dst_ip');
  assert.equal(formatter.body(document), 'src_ip / dst_ip : 192.0.2.1');
  assert.equal(formatter.summaryValues(document), '192.0.2.1');
  assert.equal(engine.resolve('{SRC_IP} -> {DST_IP}', document).text, '192[.]0[.]2[.]1 -> 192[.]0[.]2[.]1');
});

test('successive imports append new values, deduplicate old ones and retain record IDs and order', () => {
  const { templates, parser } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'destination_ip: 192.0.2.1\nhost: ONE');
  const id = document.variables[0].id;
  capture(document, parser, 'destination_ip: 192.0.2.2\ndestination_ip: 192.0.2.1');
  assert.equal(document.variables.length, 3);
  assert.equal(document.variables[0].id, id);
  assert.equal(document.variables.map(record => record.value).join(','), '192.0.2.1,ONE,192.0.2.2');
  document.raw = '';
  parser.merge(document, parser.parse(''));
  assert.equal(document.variables.length, 3);
});

test('inline edits preserve uniqueness and duplicate values merge keys instead of duplicating records', () => {
  const { templates, parser, pairs } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'destination_ip: 192.0.2.1\nsource_ip: 192.0.2.2');
  const id = document.variables[1].id;
  assert.equal(pairs.edit(document, id, {value:'192.0.2.1'}).merged, true);
  assert.equal(document.variables.length, 1);
  assert.equal(document.variables[0].keys.join(','), 'destination_ip,source_ip');
  assert.equal(document.ignoredValues[0], '192.0.2.2');
  assert.equal(pairs.add(document, ['network'], '192.0.2.1').merged, true);
  assert.equal(document.variables.length, 1);
  assert.equal(pairs.add(document, ['destination_ip'], '192.0.2.3').ok, true);
  assert.equal(document.variables.length, 2);
  assert.equal(pairs.edit(document, document.variables[0].id, {value:''}).ok, false);
  assert.equal(pairs.edit(document, document.variables[0].id, {value:'a\nb'}).ok, false);
});

test('edited source values remain excluded and other values with that key remain available', () => {
  const { templates, parser, pairs } = modules();
  const document = templates.emptyDocument();
  const raw = 'destination_ip: 192.0.2.1\ndestination_ip: 192.0.2.2';
  capture(document, parser, raw);
  pairs.edit(document, document.variables[0].id, {value:'192.0.2.3'});
  capture(document, parser, raw + '\ndestination_ip: 192.0.2.4');
  assert.equal(document.variables.map(record => record.value).join(','), '192.0.2.3,192.0.2.2,192.0.2.4');
});

test('deleted values can be imported again after reload while live values stay unique', () => {
  const { templates, parser, pairs, storage } = modules();
  const document = templates.emptyDocument();
  const raw = 'destination_ip: 192.0.2.1\ndestination_ip: 192.0.2.2';
  capture(document, parser, raw);
  const [removed, retained] = document.variables;
  assert.equal(pairs.remove(document, removed.id).ok, true);
  assert.equal(document.variables.length, 1);
  assert.equal(document.ignoredValues.includes(removed.value), false);
  storage.save(document);
  const restored = storage.load().document;
  capture(restored, parser, raw + '\nsource_ip: 192.0.2.1');
  assert.equal(restored.variables.length, 2);
  assert.equal(restored.variables[0].id, retained.id);
  const imported = restored.variables.find(record => record.value === removed.value);
  assert.notEqual(imported.id, removed.id);
  assert.equal(imported.keys.join(','), 'destination_ip,source_ip');
  capture(restored, parser, raw);
  assert.equal(restored.variables.length, 2);
});

test('deletion clears an existing exclusion for that value without clearing other edit exclusions', () => {
  const { templates, parser, pairs } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'User: alice\nHost: ONE');
  const [user, host] = document.variables;
  pairs.edit(document, user.id, { names: ['Account'] });
  pairs.edit(document, host.id, { value: 'TWO' });
  assert.equal(document.ignoredValues.join(','), 'alice,ONE');
  pairs.remove(document, user.id);
  assert.equal(document.ignoredValues.join(','), 'ONE');
  capture(document, parser, 'User: alice\nHost: ONE');
  assert.equal(document.variables.map(record => record.value).join(','), 'TWO,alice');
});

test('every distinct value is available to remediation placeholders rather than only the first key match', () => {
  const { templates, parser, remediationEngine: engine } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'destination_ip: 192.0.2.1\ndst_ip: 192.0.2.2\ndst_ip: 192.0.2.1');
  assert.equal(engine.resolve('Block the destination {DST_IP}.', document).text, 'Block the destination 192[.]0[.]2[.]1 / 192[.]0[.]2[.]2.');
});

test('saved pair order and keys survive reload; invalid duplicate-value schemas are rejected', () => {
  const { templates, parser, storage } = modules();
  const document = templates.emptyDocument();
  capture(document, parser, 'destination_ip: 192.0.2.1\ndestination_ip: 192.0.2.2');
  document.variables.reverse();
  assert.equal(storage.save(document).ok, true);
  const restored = storage.load().document;
  assert.equal(restored.schemaVersion, 4);
  assert.equal(restored.variables.map(record => record.value).join(','), '192.0.2.2,192.0.2.1');
  document.variables.push({...document.variables[0], id:'another-id'});
  assert.equal(storage.validate(document), null);
});

test('V2 migration splits concatenated values and preserves previous prose in analysis', () => {
  const { templates, storage, formatter } = modules();
  const document = templates.emptyDocument();
  document.schemaVersion = 2;
  document.variables = [{id:'old', key:'dst_ip', value:'192.0.2.1\n192.0.2.2', origin:'captured'}, {id:'other', key:'source_ip', value:'192.0.2.1', origin:'captured'}];
  document.draft = 'Conclusion ancienne à conserver.';
  document.analysis = 'Analyse actuelle.';
  delete document.ignoredValues;
  const migrated = storage.validate(document);
  assert.equal(migrated.schemaVersion, 4);
  assert.equal(migrated.variables.length, 2);
  assert.equal(migrated.variables[0].keys.join(','), 'dst_ip,source_ip');
  assert(migrated.analysis.includes('Conclusion ancienne à conserver.'));
  assert(!formatter.body(migrated).includes('Conclusion'));
});

test('MITRE context is added as unique Summary pairs with tactic IDs and follows the chosen tactics', () => {
  const {templates,pairs,parser,formatter}=modules();
  const document=templates.emptyDocument();
  capture(document,parser,'USER: alice');
  const tactics=[{id:'credential-access',name:'Credential Access',mitreId:'TA0006'},{id:'lateral-movement',name:'Lateral Movement',mitreId:'TA0008'}];
  pairs.syncMitre(document,tactics);
  assert.equal(document.variables.length,3);
  assert.equal(formatter.body(document),'USER : alice\nMITRE : Credential Access (TA0006)\nMITRE : Lateral Movement (TA0008)');
  const automatic=document.variables.find(record=>record.origin==='mitre');
  assert.equal(pairs.edit(document,automatic.id,{value:'Another tactic'}).ok,false);
  document.variables.reverse();
  pairs.syncMitre(document,tactics);
  assert.equal(document.variables[0].value,'Lateral Movement (TA0008)');
  pairs.syncMitre(document,[tactics[0]]);
  assert.equal(document.variables.length,2);
  assert.equal(document.variables.find(record=>record.origin==='mitre').id,automatic.id);
  pairs.syncMitre(document,[]);
  assert.equal(document.variables.length,1);
  assert.equal(document.variables[0].value,'alice');
});

test('automatic MITRE context preserves unique values and survives explicit investigation persistence', () => {
  const {templates,pairs,storage,parser}=modules();
  const document=templates.emptyDocument();
  capture(document,parser,'context: Credential Access (TA0006)');
  const tactic={id:'credential-access',name:'Credential Access',mitreId:'TA0006'};
  pairs.syncMitre(document,[tactic]);
  assert.equal(document.variables.length,1);
  assert.equal(document.variables[0].keys.join(','),'context,MITRE');
  pairs.syncMitre(document,[tactic,{id:'execution',name:'Execution',mitreId:'TA0002'}]);
  document.remediation.activeTactics=['credential-access','execution'];
  assert.equal(storage.save(document).ok,true);
  const loaded=storage.load().document;
  const derived=loaded.variables.find(record=>record.origin==='mitre');
  assert.equal(derived.tacticId,'execution');
  assert.equal(derived.value,'Execution (TA0002)');
});

test('Defanged URL is opt-in and affects presentation/copy/report while preserving original values', () => {
  const {templates,parser,pairs,formatter}=modules();
  const document=templates.emptyDocument();
  capture(document,parser,'URL: https://example.invalid/path\nHost: PC-01');
  const record=document.variables[0];
  const raw=record.value;
  assert.equal(pairs.displayValue(record),raw);
  record.defangUrl=true;
  assert.equal(pairs.displayValue(record),'hxxps://example[.]invalid/path');
  assert.equal(formatter.summaryValues(document),'hxxps://example[.]invalid/path\nPC-01');
  assert(formatter.format(document).includes('URL: hxxps://example[.]invalid/path'));
  assert.equal(record.value,raw);
  assert(document.capturedRaw.includes(raw));
  record.defangUrl=false;
  assert.equal(pairs.displayValue(record),raw);
});

test('URL choices survive draft reload, reparsing and duplicate-value merging', () => {
  const {templates,parser,pairs,storage}=modules();
  const document=templates.emptyDocument();
  document.raw='URL: https://example.invalid';
  parser.merge(document,parser.parse(document.raw));
  const record=document.variables[0];
  record.defangUrl=true;
  parser.merge(document,parser.parse(document.raw));
  assert.equal(document.variables[0].defangUrl,true);
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  assert.equal(restored.variables[0].defangUrl,true);
  assert.equal(restored.variables[0].value,'https://example.invalid');
  assert.equal(pairs.displayValue(restored.variables[0]),'hxxps://example[.]invalid');
  pairs.add(restored,['url'],'https://other.invalid');
  restored.variables[1].defangUrl=true;
  pairs.edit(restored,restored.variables[1].id,{value:'https://example.invalid'});
  assert.equal(restored.variables.length,1);
  assert.equal(restored.variables[0].defangUrl,true);
  restored.variables[0].defangUrl='yes';
  assert.equal(storage.validate(restored),null);
});

test('URL detection recognizes HTTP(S), FTP and already-neutralized URLs without evaluating other strings', () => {
  const {defang}=modules();
  for(const value of ['https://example.invalid/path','http://192.0.2.1:8080','hxxps://example[.]invalid/path','ftp://example.invalid/file','ftps://example.invalid/file']) assert.equal(defang.isUrl(value),true,value);
  for(const value of ['',null,undefined,'PC-01','192.0.2.1','C:\\file.exe','javascript:alert(1)','data:text/html,<img src=x>','https://','http://invalid host/path']) assert.equal(defang.isUrl(value),false);
});

test('manual subcategories are grouped under their parent, persisted and limited to one level', () => {
  const {templates,pairs,storage,formatter}=modules(), document=templates.emptyDocument();
  const parent=pairs.add(document,['Network'],'network').id;
  const other=pairs.add(document,['Host'],'PC-01').id;
  const first=pairs.add(document,['Source'],'192.0.2.1',parent).id;
  const second=pairs.add(document,['Destination'],'192.0.2.2',parent).id;
  assert.equal(document.variables.map(record=>record.id).join(','),[parent,first,second,other].join(','));
  assert.equal(pairs.add(document,['Too deep'],'192.0.2.3',first).ok,false);
  assert.equal(pairs.add(document,['Missing'],'192.0.2.4','missing').ok,false);
  assert.equal(pairs.add(document,['Duplicate'],'PC-01',parent).duplicate,true);
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  assert.equal(restored.variables[1].parentId,parent);
  assert.equal(formatter.format(restored),'==================================================\n                     SUMMARY\n==================================================\n\nNetwork: network\n├── Source: 192.0.2.1\n└── Destination: 192.0.2.2\n\nHost: PC-01');
  assert.equal(formatter.summaryValues(restored),'network\n192.0.2.1\n192.0.2.2\nPC-01');
});

test('drag moves whole parent blocks and reorders or reparents children without permitting cycles', () => {
  const {templates,pairs}=modules(), document=templates.emptyDocument();
  const parent=pairs.add(document,['A'],'A').id;
  const child=pairs.add(document,['a1'],'a1',parent).id;
  const other=pairs.add(document,['B'],'B').id;
  const next=pairs.add(document,['C'],'C').id;
  assert.equal(pairs.move(document,parent,other,{after:true}).ok,true);
  assert.equal(document.variables.map(record=>record.value).join(','),'B,A,a1,C');
  assert.equal(pairs.move(document,parent,next,{nest:true}).ok,false,'Parents with children cannot create a second child level');
  assert.equal(pairs.move(document,parent,child,{nest:true}).ok,false);
  assert.equal(pairs.move(document,next,child).ok,false,'The left side cannot turn a root into a child');
  assert.equal(pairs.move(document,next,child,{nest:true}).ok,true,'The right side inserts a sibling below a child');
  assert.equal(document.variables.find(record=>record.id===next).parentId,parent);
  assert.equal(document.variables.map(record=>record.value).join(','),'B,A,a1,C');
  assert.equal(pairs.move(document,next,child).ok,true,'A left-side sibling target keeps the same parent');
  assert.equal(document.variables.map(record=>record.value).join(','),'B,A,C,a1');
  assert.equal(pairs.move(document,child,other,{nest:true}).ok,true,'A child can change parents');
  assert.equal(document.variables.map(record=>record.value).join(','),'B,a1,A,C');
  assert.equal(pairs.move(document,child,parent,{after:true}).ok,true,'A root target detaches the child');
  assert.equal(document.variables.map(record=>record.value).join(','),'B,A,C,a1');
  assert.equal(document.variables.at(-1).parentId,undefined);
});

test('right-side nesting follows the hovered row, keeping one child level and exact sibling order', () => {
  const {templates,pairs,storage}=modules(), document=templates.emptyDocument();
  const parent=pairs.add(document,['A'],'A').id;
  const first=pairs.add(document,['a1'],'a1',parent).id;
  pairs.add(document,['a2'],'a2',parent);
  const other=pairs.add(document,['B'],'B').id;
  const otherFirst=pairs.add(document,['b1'],'b1',other).id;
  const otherLast=pairs.add(document,['b2'],'b2',other).id;
  const next=pairs.add(document,['C'],'C').id;
  const last=pairs.add(document,['D'],'D').id;
  const order=()=>document.variables.map(record=>record.value).join(',');
  const parentOf=id=>document.variables.find(record=>record.id===id).parentId;
  assert.equal(pairs.move(document,next,parent,{nest:true}).ok,true);
  assert.equal(order(),'A,C,a1,a2,B,b1,b2,D','A root target inserts as its first child');
  assert.equal(pairs.canMove(document,last,first,{nest:true}),true);
  assert.equal(pairs.move(document,last,first,{nest:true}).ok,true);
  assert.equal(order(),'A,C,a1,D,a2,B,b1,b2','A child target inserts directly after that child');
  assert.equal(parentOf(last),parent);
  assert.equal(pairs.move(document,otherLast,first,{nest:true}).ok,true);
  assert.equal(order(),'A,C,a1,b2,D,a2,B,b1','A child can join another parent at the hovered position');
  assert.equal(parentOf(otherLast),parent);
  assert.equal(pairs.move(document,next,otherFirst,{nest:true}).ok,true);
  assert.equal(order(),'A,a1,b2,D,a2,B,b1,C');
  assert.equal(parentOf(next),other);
  const before=JSON.stringify(document.variables);
  for (const [source,target] of [[parent,first],[parent,otherFirst],[next,next]]) {
    assert.equal(pairs.canMove(document,source,target,{nest:true}),false);
    assert.equal(pairs.move(document,source,target,{nest:true}).ok,false);
  }
  assert.equal(JSON.stringify(document.variables),before,'Rejected drops preserve the hierarchy');
  assert.equal(storage.save(document).ok,true);
  assert.equal(storage.load().document.variables.map(record=>record.value).join(','),order());
});

test('impossible drops resolve to the first top-level gap below the target without splitting blocks', () => {
  const {templates,pairs,storage}=modules(), document=templates.emptyDocument();
  const first=pairs.add(document,['A'],'A').id;
  const firstChild=pairs.add(document,['a1'],'a1',first).id;
  pairs.add(document,['a2'],'a2',first);
  const second=pairs.add(document,['B'],'B').id;
  const secondChild=pairs.add(document,['b1'],'b1',second).id;
  const last=pairs.add(document,['C'],'C').id;
  const order=()=>document.variables.map(record=>record.value).join(',');
  function drop(source,target,options) {
    const resolved=pairs.resolveDrop(document,source,target,options);
    assert(resolved);
    assert.equal(resolved.fallback,true);
    assert.equal(resolved.nest,false);
    assert.equal(pairs.move(document,source,resolved.id,resolved).ok,true);
    assert(storage.validate(document));
    return resolved;
  }
  const belowFirst=drop(last,firstChild,{nest:false});
  assert.equal(belowFirst.id,first);
  assert.equal(belowFirst.after,true);
  assert.equal(order(),'A,a1,a2,C,B,b1','A root dropped on a child lands after the complete parent block');
  assert.equal(document.variables.find(record=>record.id===last).parentId,undefined);
  const belowSecond=drop(first,secondChild,{nest:true});
  assert.equal(belowSecond.id,second);
  assert.equal(order(),'C,B,b1,A,a1,a2','A parent that cannot nest moves with all of its children');
  const self=drop(first,firstChild,{nest:true});
  assert.equal(self.id,undefined);
  assert.equal(order(),'C,B,b1,A,a1,a2','Dropping on the last source block stays in place');
  pairs.move(document,first,last);
  assert.equal(order(),'A,a1,a2,C,B,b1');
  const beforeNext=drop(first,firstChild,{nest:true});
  assert.equal(beforeNext.id,last);
  assert.equal(beforeNext.after,false);
  assert.equal(order(),'A,a1,a2,C,B,b1','The gap after the source is anchored before the next parent');
  drop(firstChild,firstChild,{nest:true});
  assert.equal(order(),'A,a2,a1,C,B,b1');
  assert.equal(document.variables.find(record=>record.id===firstChild).parentId,undefined,'An impossible child drop promotes it to a root');
  assert.equal(pairs.resolveDrop(document,'missing',second,{nest:true}),null);
  assert.equal(pairs.resolveDrop(document,last,'missing',{nest:true}),null);
  const valid=pairs.resolveDrop(document,last,secondChild,{nest:true});
  assert.equal(valid.fallback,undefined,'Allowed nesting keeps the original target');
  assert.equal(valid.id,secondChild);
  assert.equal(valid.nest,true);
});

test('removing or merging a category preserves children and a valid hierarchy', () => {
  const {templates,pairs,storage}=modules(), document=templates.emptyDocument();
  const parent=pairs.add(document,['A'],'A').id;
  const first=pairs.add(document,['a1'],'a1',parent).id;
  const second=pairs.add(document,['a2'],'a2',parent).id;
  const target=pairs.add(document,['B'],'B').id;
  assert.equal(pairs.edit(document,parent,{value:'a1'}).merged,true);
  assert.equal(document.variables.find(record=>record.id===first).parentId,undefined,'Merging a parent into its child promotes that child');
  assert.equal(document.variables.find(record=>record.id===second).parentId,first);
  assert.equal(storage.save(document).ok,true);
  assert.equal(pairs.edit(document,first,{value:'B'}).merged,true);
  assert.equal(document.variables.find(record=>record.id===second).parentId,target);
  assert.equal(pairs.remove(document,target).ok,true);
  assert.equal(document.variables.length,1);
  assert.equal(document.variables[0].id,second);
  assert.equal(document.variables[0].parentId,undefined);
  assert.equal(storage.save(document).ok,true);
});

test('saved hierarchies reject missing parents, self-parenting, cycles and third levels', () => {
  const {templates,pairs,storage}=modules(), document=templates.emptyDocument();
  const parent=pairs.add(document,['A'],'A').id;
  const child=pairs.add(document,['a1'],'a1',parent).id;
  pairs.add(document,['B'],'B');
  for (const parentId of [child,'missing','',42]) {
    const broken=JSON.parse(JSON.stringify(document));
    broken.variables[1].parentId=parentId;
    assert.equal(storage.validate(broken),null);
  }
  const deep=JSON.parse(JSON.stringify(document));
  deep.variables[2].parentId=child;
  assert.equal(storage.validate(deep),null);
  const cycle=JSON.parse(JSON.stringify(document));
  cycle.variables[0].parentId=child;
  assert.equal(storage.validate(cycle),null);
  const legacy=JSON.parse(JSON.stringify(document));
  delete legacy.variables[1].parentId;
  assert(storage.validate(legacy).variables.every(record=>!record.parentId),'Older flat drafts do not acquire predefined subcategories');
});

test('reparsing and repeat imports retain custom parent relationships', () => {
  const {templates,pairs,parser,storage}=modules(), document=templates.emptyDocument();
  document.raw='Group: network\nAddress: 192.0.2.1';
  parser.merge(document,parser.parse(document.raw));
  const [parent,child]=document.variables;
  pairs.move(document,child.id,parent.id,{nest:true});
  parser.merge(document,parser.parse(document.raw));
  assert.equal(document.variables[1].parentId,parent.id);
  assert.equal(storage.save(document).ok,true);
  parser.capture(document);
  capture(document,parser,'Address: 192.0.2.1\nHost: PC-01');
  assert.equal(document.variables[1].parentId,parent.id);
  assert.equal(document.variables.length,3);
});

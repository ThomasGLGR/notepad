const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
const {prepare} = require('../js/json-import.js');
require('../extension/capture-data.js');
const {create} = require('../extension/capture-queue.js');
function model() {
  const saved=new Map(), window={crypto:{randomUUID},localStorage:{getItem:key=>saved.get(key)??null,setItem:(key,value)=>saved.set(key,value),removeItem:key=>saved.delete(key)}};
  const context=vm.createContext({window,URL});
  for(const file of ['templates','summary-data','json-import']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../js',file+'.js'),'utf8'),context);
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/capture-data.js'),'utf8'),context);
  for(const file of ['defang','extractors','parser','remediation-data','remediation-engine','remediation-storage','formatter','storage']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../js',file+'.js'),'utf8'),context);
  return window.SOCNote;
}
const source=(id,data)=>({id:'json:'+id,method:'json',value:JSON.stringify(data),timestamp:1,tabId:1,windowId:2,title:'SIEM',url:'https://siem.example/alert',context:''});
test('JSON objects and arrays preserve dotted keys, distinct repeated fields, IDs and prior notes',()=>{
  const {templates,jsonImport,pairs}=model(), document=templates.emptyDocument();
  document.rule='Existing rule';document.analysis='Unchanged notes';document.raw='Pending logs';document.capturedRaw='Older source';
  pairs.add(document,['user.name'],'alice');
  const originalId=document.variables[0].id;
  const data=[{'user.name':'alice','host.hostname':'ONE','process.command_line':'cmd /c whoami'},{'host.hostname':'TWO'},{'host.hostname':'THREE'},{'host.hostname':'TWO'}];
  const result=jsonImport.importJSON(document,data);
  assert.equal(result.ok,true);
  assert.deepEqual(Array.from(document.variables,record=>record.key),['user.name','host.hostname','process.command_line','host.hostname2','host.hostname3']);
  assert.equal(document.variables[0].id,originalId);
  assert.equal(new Set(document.variables.map(record=>record.id)).size,5);
  assert.equal(document.rule,'Existing rule');assert.equal(document.analysis,'Unchanged notes');assert.equal(document.raw,'Pending logs');assert.equal(document.capturedRaw,'Older source');
  const ids=document.variables.map(record=>record.id);
  assert.equal(jsonImport.importJSON(document,data).count,0);
  assert.deepEqual(document.variables.map(record=>record.id),ids);
});
test('JSON suffixes avoid both existing fields and literal numbered keys in the same import',()=>{
  const {templates,jsonImport,pairs}=model(), document=templates.emptyDocument();
  pairs.add(document,['host.hostname'],'ONE');
  assert.equal(jsonImport.importJSON(document,{'host.hostname':'TWO','host.hostname2':'Literal numbered field'}).ok,true);
  assert.deepEqual(Array.from(document.variables,record=>record.key),['host.hostname','host.hostname3','host.hostname2']);
});

test('deleted JSON values can be imported again with a new send while existing values remain unique',()=>{
  const {templates,parser,pairs,storage}=model(), document=templates.emptyDocument();
  const data={'host.hostname':'ONE','user.name':'alice','event.details':{process:'cmd',user:'SYSTEM'}};
  assert.equal(parser.importCaptures(document,[source('first',data)]).ok,true);
  const removed=document.variables.find(record=>record.key==='event.details');
  const retained=document.variables.filter(record=>record.id!==removed.id).map(record=>record.id);
  pairs.remove(document,removed.id);
  assert.equal(document.variables.length,2);
  storage.save(document);
  const restored=storage.load().document;
  assert.equal(parser.importCaptures(restored,[source('first',data)]).count,0,'The previous send receipt still prevents automatic replay');
  assert.equal(restored.variables.length,2);
  assert.equal(parser.importCaptures(restored,[source('second',data)]).ok,true);
  assert.equal(restored.variables.length,3);
  assert.deepEqual(Array.from(restored.variables.slice(0,2),record=>record.id),Array.from(retained));
  assert.notEqual(restored.variables[2].id,removed.id);
  assert.equal(restored.variables[2].value,removed.value);
  parser.importCaptures(restored,[source('third',data)]);
  assert.equal(restored.variables.length,3);
});

test('the provided squad JSON expands member objects into unprefixed fields and retains all powers',()=>{
  const {templates,jsonImport,storage}=model(), document=templates.emptyDocument();
  const squad=JSON.parse(fs.readFileSync(path.join(__dirname,'fixtures/superhero-squad.json'),'utf8'));
  const result=jsonImport.importJSON(document,squad);
  assert.equal(result.ok,true);
  assert.equal(result.count,25);
  assert.equal(document.variables.find(record=>record.key==='name').value,'Molecule Man');
  assert.equal(document.variables.find(record=>record.key==='name2').value,'Madame Uppercut');
  assert.equal(document.variables.find(record=>record.key==='name3').value,'Eternal Flame');
  assert.equal(document.variables.find(record=>record.key==='age3').value,'1000000');
  assert.equal(document.variables.find(record=>record.key==='powers11').value,'Interdimensional travel');
  assert.equal(document.variables.find(record=>record.key==='active').value,'true');
  assert(!document.variables.some(record=>record.key.includes('members') || record.value.includes('"name"')));
  assert.equal(jsonImport.importJSON(document,squad).count,0);
  assert.equal(storage.save(document).ok,true);
  assert.equal(storage.load().document.variables.length,25);
});

test('nested arrays of objects deduplicate their leaf fields without changing dotted keys',()=>{
  const result=prepare({groups:[{members:[{'user.name':'alice'},{'user.name':'bob'},{'user.name':'alice'}]},{members:[{'user.name':'charlie'}]}]});
  assert.equal(result.ok,true);
  assert.deepEqual(result.fields,[{key:'user.name',value:'alice'},{key:'user.name',value:'bob'},{key:'user.name',value:'charlie'}]);
});
test('JSON values support zero, false, arrays and nested literal objects while ignoring empty fields',()=>{
  const result=prepare({'user.name':['alice','bob','alice'],'empty':'  ','null':null,'array':[],'object':{},'zero':0,'false':false,'host.data':{hostname:'ONE'},'details':'Line one\n\n  Line two'});
  assert.equal(result.ok,true);
  assert.deepEqual(result.fields,[{key:'user.name',value:'alice'},{key:'user.name',value:'bob'},{key:'zero',value:'0'},{key:'false',value:'false'},{key:'host.data',value:'{"hostname":"ONE"}'},{key:'details',value:'Line one\n\n  Line two'}]);
});
test('JSON imports retain exact strings, literal dangerous keys and multiline values through autosave',()=>{
  const {templates,jsonImport,storage,formatter}=model(), document=templates.emptyDocument();
  const data=JSON.parse('{"__proto__":"literal","constructor":"value"," user.name ":"  alice  ","process.command_line":"Line one\\r\\n\\r\\n  Line two"}');
  assert.equal(jsonImport.importJSON(document,data).ok,true);
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  assert.equal(restored.variables.find(record=>record.key===' user.name ').value,'  alice  ');
  assert.equal(restored.variables.find(record=>record.key==='process.command_line').value,'Line one\r\n\r\n  Line two');
  assert(formatter.format(restored).includes('Line one\r\n\r\n  Line two'));
  assert.equal({}.literal,undefined);
});
test('malformed, unsupported and oversized JSON imports are atomic',()=>{
  const {templates,jsonImport}=model(), document=templates.emptyDocument();
  jsonImport.importJSON(document,{'host.hostname':'ONE'});
  const before=JSON.stringify(document);
  const tooMany=Object.fromEntries(Array.from({length:201},(_,i)=>['field.'+i,String(i)]));
  for(const data of ['{"bad":',null,1,['bad'],[{'valid':'value'},null],tooMany,{'a':'x'.repeat(500001)},{a:NaN},{a:undefined}]) {
    assert.equal(jsonImport.importJSON(document,data).ok,false,String(data));
    assert.equal(JSON.stringify(document),before);
  }
});
test('all capture paths recognize JSON and persist send receipts without replay after reload',()=>{
  const {templates,parser,storage}=model(), document=templates.emptyDocument();
  for(const method of ['json','clipboard','selection']) {
    const item={...source(method,[{'host.hostname':'ONE'},{'host.hostname':'TWO'}]),method};
    const result=parser.importCaptures(document,[item]);
    assert.equal(result.ok,true);
    assert.equal(result.jsonSends,1);
  }
  assert.equal(document.variables.length,2);
  assert.equal(storage.save(document).ok,true);
  const restored=storage.load().document;
  assert.equal(parser.importCaptures(restored,[source('json',[{'host.hostname':'ONE'},{'host.hostname':'TWO'}])]).count,0);
  assert.equal(parser.importCaptures(restored,[source('json',{'host.hostname':'CHANGED'})]).ok,false);
  assert.equal(restored.variables.length,2);
});
test('mixed batches cannot commit an earlier capture when a later JSON import is invalid',()=>{
  const {templates,parser}=model(), document=templates.emptyDocument();
  const before=JSON.stringify(document);
  const invalid={...source('bad',{}),method:'clipboard',value:'{"broken":'};
  assert.equal(parser.importCaptures(document,[{...source('good',{}),method:'selection',value:'IP: 192.0.2.1'},invalid]).ok,false);
  assert.equal(JSON.stringify(document),before);
});
test('JSON dotted aliases feed existing remediation placeholders without selecting actions',()=>{
  const {templates,jsonImport,remediationEngine}=model(), document=templates.emptyDocument();
  assert.equal(jsonImport.importJSON(document,[{'user.name':'alice','host.hostname':'ONE','destination.ip':'192.0.2.1'},{'host.hostname':'TWO','destination.ip':'192.0.2.2'}]).ok,true);
  const values=remediationEngine.values(document);
  assert.equal(values.USER,'alice');assert.equal(values.HOST,'ONE / TWO');assert.equal(values.DST_IP,'192[.]0[.]2[.]1 / 192[.]0[.]2[.]2');
  assert.equal(document.remediation.selected.length,0);assert.equal(document.remediation.activeTactics.length,0);
});
test('local JSON receipts survive acknowledgement and worker recreation; background claims exclude ordinary captures',async()=>{
  const saved={},storage={get:async key=>structuredClone({[key]:saved[key]}),set:async values=>Object.assign(saved,structuredClone(values))};
  let queue=create({storage,isFocused:async()=>false});
  const item={...source('send',{'host.hostname':'ONE'}),digest:'a'.repeat(64)};
  await queue.enqueue({...item,id:'text',method:'selection',value:'Existing selection',digest:undefined});
  await queue.enqueue(item);
  const previousOwner={clientId:'before-reload',tabId:9,windowId:9};
  const previousClaim=await queue.claim(previousOwner,{jsonOnly:true});
  queue=create({storage,isFocused:async()=>false});
  const owner={clientId:'consumer',tabId:9,windowId:9};
  const claim=await queue.claim(owner,{jsonOnly:true});
  assert.notEqual(claim.token,previousClaim.token);
  assert.equal(await queue.acknowledge(previousOwner,previousClaim.token,previousClaim.ids),false);
  assert.deepEqual(claim.ids,['json:send']);
  assert.equal(await queue.reportJSONError({...owner,clientId:'other'},claim.token,'Storage unavailable'),false);
  assert.equal(await queue.reportJSONError(owner,claim.token,'Storage unavailable'),true);
  assert.equal((await queue.snapshot()).jsonReceipts[0].error,'Storage unavailable');
  assert.equal(await queue.acknowledge(owner,claim.token,claim.ids),true);
  assert.equal((await queue.snapshot()).jsonReceipts[0].status,'imported');
  assert.equal((await queue.snapshot()).jsonReceipts[0].error,undefined);
  queue=create({storage,isFocused:async()=>false});
  await queue.enqueue(item);
  assert.equal((await queue.snapshot()).captures.length,1);
  await assert.rejects(queue.enqueue({...item,digest:'b'.repeat(64)}),/reused/);
  assert.equal((await queue.snapshot()).captures[0].id,'text');
});

test('the activated-page receiver accepts only its own window/origin and returns status without payload',async()=>{
  let handler,registrations=0;
  const sent=[],replies=[],origin='https://siem.example';
  const window={addEventListener:(name,callback)=>{registrations++;handler=callback;},postMessage:(data,target)=>{assert.equal(target,origin);replies.push(data);}};
  const context=vm.createContext({window,location:{origin},chrome:{runtime:{sendMessage:async message=>{sent.push(message);return {ok:true,status:'queued'};}}}});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/json-receiver.js'),'utf8'),context);
  context.installSOCJSONReceiver();context.installSOCJSONReceiver();assert.equal(registrations,1);
  const data={channel:'soc-note-json/v1',type:'send',requestId:'siem-one',data:{'host.hostname':'ONE'}};
  const event={source:window,origin,data};
  for(const change of [{source:{}},{origin:'https://foreign.example'},{data:{...data,channel:'foreign'}},{data:{...data,type:'result'}},{data:{...data,requestId:''}}]) await handler({...event,...change});
  assert.equal(sent.length,0);assert.equal(replies.length,0);
  await handler(event);
  assert.equal(sent[0].type,'soc-json/import');assert.equal(sent[0].data,'{"host.hostname":"ONE"}');
  assert.equal(replies[0].ok,true);assert.equal('data' in replies[0],false);
  await handler({...event,data:{...data,data:'x'.repeat(500001)}});
  assert.equal(sent.length,1);assert.equal(replies[1].ok,false);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {randomUUID} = require('node:crypto');
const code = name => fs.readFileSync(path.join(__dirname,'../extension',name),'utf8');

function reader(text, {pasteAllowed=true,copyAllowed=true}={}) {
  let messageHandler, reads=0, prevented=0;
  const handlers={},writes=[];
  const input={value:'',focus(){},select(){},addEventListener(name,handler){handlers[name]=handler;},removeEventListener(name){delete handlers[name];}};
  const context=vm.createContext({
    SOCCaptureData:{MAX_VALUE:500000},
    document:{getElementById:()=>input,execCommand(command){
      if(command==='copy') {
        if(copyAllowed) handlers.copy({clipboardData:{setData(type,value){assert.equal(type,'text/plain');writes.push(value);}},preventDefault(){prevented++;}});
        return false;
      }
      assert.equal(command,'paste');reads++;
      if(pasteAllowed) handlers.paste({clipboardData:{getData(type){assert.equal(type,'text/plain');return text;}},preventDefault(){prevented++;}});
      return false; // Cancelled default insertion still delivers the paste event.
    }},
    chrome:{runtime:{id:'extension',getURL:file=>'chrome-extension://extension/'+file,onMessage:{addListener(handler){messageHandler=handler;}}}}
  });
  vm.runInContext(code('clipboard-reader.js'),context);
  return {context,input,writes,reads:()=>reads,prevented:()=>prevented,handler:()=>handlers.paste || handlers.copy || null,message:messageHandler};
}

test('offscreen paste reads only plain text, including literal HTML and line breaks, and clears its buffer',()=>{
  const text='<img src=x onerror=alert(1)>\r\n\r\n  indented';
  const item=reader(text);
  assert.equal(item.context.readClipboardText(),text);
  assert.equal(item.reads(),1);
  assert.equal(item.prevented(),1);
  assert.equal(item.input.value,'');
  assert.equal(item.handler(),null);
});

test('a denied or oversized offscreen paste fails without retaining clipboard text',()=>{
  for(const item of [reader('x'.repeat(500001)),reader('secret',{pasteAllowed:false})]) {
    assert.throws(()=>item.context.readClipboardText(),/Clipboard/);
    assert.equal(item.input.value,'');
    assert.equal(item.handler(),null);
  }
});

test('offscreen copy writes only the selected plaintext and preserves exact line breaks',()=>{
  const text='  <img src=x>\r\n\r\n    Indented\nLast line';
  const item=reader('Previous clipboard');
  item.context.writeClipboardText(text);
  assert.deepEqual(item.writes,[text]);
  assert.equal(item.reads(),0);
  assert.equal(item.prevented(),1);
  assert.equal(item.input.value,'');
  assert.equal(item.handler(),null);
});

test('denied, invalid and oversized offscreen copies fail and clear the local buffer',()=>{
  for(const [item,text] of [[reader('Previous clipboard',{copyAllowed:false}),'Selected text'],[reader('Previous clipboard'),'x'.repeat(500001)],[reader('Previous clipboard'),undefined]]) {
    assert.throws(()=>item.context.writeClipboardText(text),/Clipboard/);
    assert.equal(item.input.value,'');
    assert.equal(item.handler(),null);
    assert.deepEqual(item.writes,[]);
  }
});

test('the clipboard reader rejects page, offscreen and foreign senders before reading',()=>{
  const item=reader('Sensitive text');
  const message={target:'soc-clipboard-reader',type:'read',requestId:'nonce'};
  const sender={id:'extension',url:'chrome-extension://extension/extension/service-worker.js'};
  for(const type of ['read','write']) for(const change of [{id:'foreign'},{url:'https://example.com/'},{tab:{id:1}},{documentId:'page-document'}]) {
    assert.equal(item.message({...message,type,text:'Malicious overwrite'},{...sender,...change},()=>assert.fail('Unexpected clipboard response')),false);
  }
  item.message({...message,requestId:''},sender,()=>assert.fail('Unexpected clipboard response'));
  assert.equal(item.reads(),0);
  assert.equal(item.writes.length,0);
  let result;
  item.message(message,sender,value=>{result=value;});
  assert.equal(result.ok,true);
  assert.equal(result.requestId,'nonce');
  assert.equal(result.text,'Sensitive text');
  item.message({...message,type:'write',text:'Selected text'},sender,value=>{result=value;});
  assert.equal(result.ok,true);
  assert.equal('text' in result,false,'Copy acknowledgement does not echo selected text');
  assert.deepEqual(item.writes,['Selected text']);
});

test('clipboard client serializes copying followed by reading and checks the corresponding permissions',async()=>{
  let open=false,text='Previous clipboard';
  const operations=[],permissions=[];
  const context=vm.createContext({crypto:{randomUUID},setTimeout,clearTimeout,SOCCaptureData:{MAX_VALUE:500000},chrome:{
    permissions:{contains:async request=>{permissions.push(request.permissions[0]);return true;}},
    runtime:{getURL:file=>'chrome-extension://extension/'+file,getContexts:async()=>open?[{}]:[],sendMessage:async message=>{
      assert.equal(open,true);
      operations.push(message.type);
      await new Promise(resolve=>setImmediate(resolve));
      if(message.type==='write') {text=message.text;return {ok:true,requestId:message.requestId};}
      return {ok:true,requestId:message.requestId,text};
    }},
    offscreen:{createDocument:async()=>{assert.equal(open,false);open=true;},closeDocument:async()=>{assert.equal(open,true);open=false;}}
  }});
  vm.runInContext(code('clipboard-client.js'),context);
  const selected='Selected text\r\n\r\n  Second line';
  const results=await Promise.all([context.SOCCaptureClipboard.writeText(selected),context.SOCCaptureClipboard.readText()]);
  assert.equal(results[1],selected);
  assert.deepEqual(operations,['write','read']);
  assert.deepEqual(permissions,['clipboardWrite','clipboardRead']);
  assert.equal(open,false);
});

test('clipboard client serializes reads, closes a failed reader and recovers after a mismatched response',async()=>{
  let open=false,created=0,closed=0,reads=0;
  const context=vm.createContext({crypto:{randomUUID},setTimeout,clearTimeout,SOCCaptureData:{MAX_VALUE:500000},chrome:{
    permissions:{contains:async()=>true},
    runtime:{getURL:file=>'chrome-extension://extension/'+file,getContexts:async()=>open?[{}]:[],sendMessage:async message=>{
      assert.equal(open,true);
      await new Promise(resolve=>setImmediate(resolve));
      reads++;
      return {ok:true,requestId:reads===1?'wrong-nonce':message.requestId,text:'Recovered clipboard'};
    }},
    offscreen:{createDocument:async()=>{assert.equal(open,false);open=true;created++;},closeDocument:async()=>{assert.equal(open,true);open=false;closed++;}}
  }});
  vm.runInContext(code('clipboard-client.js'),context);
  const results=await Promise.allSettled([context.SOCCaptureClipboard.readText(),context.SOCCaptureClipboard.readText()]);
  assert.equal(results[0].status,'rejected');
  assert.match(results[0].reason.message,/Clipboard read unavailable/);
  assert.equal(results[1].value,'Recovered clipboard');
  assert.equal(created,2);
  assert.equal(closed,2);
  assert.equal(open,false);
});

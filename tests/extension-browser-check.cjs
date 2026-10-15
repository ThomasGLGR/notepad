// Real MV3 integration checks. Requires a recent Chrome with Extensions.loadUnpacked.
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

(async () => {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'soc-extension-browser-'));
  const server = http.createServer((request, response) => {
    response.writeHead(200, {'Content-Type':'text/html'});
    response.end('<!doctype html><title>' + (request.url === '/siem' ? 'SIEM' : 'EDR') + '</title><table><thead><tr><th>Source IP</th></tr></thead><tbody><tr><td id="value">185.10.20.5</td></tr></tbody></table><p id="unknown">jdupont</p><label for="user">Username</label><input id="user" value="jdupont">');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const chrome = spawn(process.env.SOC_BROWSER || '/usr/bin/google-chrome', ['--headless=new','--no-sandbox','--disable-gpu','--disable-dev-shm-usage','--disable-background-networking','--disable-sync','--disable-default-apps','--no-first-run','--enable-unsafe-extension-debugging','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'], {stdio:['ignore','ignore','pipe']});
  let socket;
  try {
    const endpoint = await new Promise((resolve, reject) => {
      let output = '';
      const timeout = setTimeout(() => reject(Error('Chrome launch timed out')), 15000);
      chrome.on('error', error => {clearTimeout(timeout); reject(error);});
      chrome.stderr.on('data', chunk => {
        output += chunk;
        const match = /DevTools listening on (ws:\/\/\S+)/.exec(output);
        if (match) {clearTimeout(timeout); resolve(match[1]);}
      });
    });
    socket = new WebSocket(endpoint);
    await new Promise((resolve, reject) => {socket.addEventListener('open', resolve, {once:true}); socket.addEventListener('error', reject, {once:true});});
    let nextId = 0;
    const pending = new Map(), events = [];
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (!message.id) {events.push(message); return;}
      const promise = pending.get(message.id);
      pending.delete(message.id);
      message.error ? promise.reject(Error(JSON.stringify(message.error))) : promise.resolve(message.result);
    });
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, {resolve,reject});
      socket.send(JSON.stringify({id,method,params,...(sessionId ? {sessionId} : {})}));
    });
    const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
    const until = async (condition, label) => {
      for (let attempt = 0; attempt < 150; attempt++) {if (await condition()) return; await wait(40);}
      throw Error('Timed out: ' + label);
    };
    const attach = async targetId => {
      const {sessionId} = await send('Target.attachToTarget', {targetId,flatten:true});
      for (const method of ['Runtime.enable','Log.enable','Network.enable']) await send(method,{},sessionId);
      const command = (method, params = {}) => send(method,params,sessionId);
      const evaluate = async expression => {
        const result = await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});
        if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
        return result.result.value;
      };
      return {targetId,sessionId,command,evaluate};
    };
    const targetFor = async url => {
      let target;
      await until(async () => {target = (await send('Target.getTargets')).targetInfos.find(info => info.url === url); return !!target;}, 'target ' + url);
      return attach(target.targetId);
    };
    const {id} = await send('Extensions.loadUnpacked',{path:path.resolve(__dirname,'..')});
    const builderURL = 'chrome-extension://' + id + '/index.html';
    const worker = await targetFor('chrome-extension://' + id + '/extension/service-worker.js');
    // Headless Chrome reports every OS window as focused. Supply the window
    // selected by this test, while retaining real tabs, permissions and injection.
    await worker.evaluate('windowTestFocusedId=null; windowTestGetLastFocused=chrome.windows.getLastFocused.bind(chrome.windows); chrome.windows.getLastFocused=()=>windowTestFocusedId===null?windowTestGetLastFocused():chrome.windows.get(windowTestFocusedId);');
    const queue = () => worker.evaluate('queue.snapshot()');
    const nativeTab = tabId => worker.evaluate('chrome.tabs.get(' + tabId + ')');
    const focus = async tabId => {
      await worker.evaluate(`(async () => {const tab = await chrome.tabs.get(${tabId}); windowTestFocusedId=tab.windowId; await chrome.tabs.update(tab.id,{active:true}); await chrome.windows.update(tab.windowId,{focused:true});})()`);
      await wait(50);
    };
    const createWindow = url => worker.evaluate(`chrome.windows.create({url:${JSON.stringify(url)},type:'normal'})`);
    const sourceOneWindow = await createWindow(base + '/siem');
    const sourceTwoWindow = await createWindow(base + '/edr');
    const sourceOne = {tabId:sourceOneWindow.tabs[0].id, ...(await targetFor(base+'/siem'))};
    const sourceTwo = {tabId:sourceTwoWindow.tabs[0].id, ...(await targetFor(base+'/edr'))};
    for (const source of [sourceOne, sourceTwo]) {
      await focus(source.tabId);
      await until(() => source.evaluate('document.readyState === "complete" && !!document.getElementById("value")'), 'source loaded before activeTab grant');
      const tabs = (await send('Target.getTargets',{filter:[{type:'tab',exclude:false},{exclude:true}]})).targetInfos;
      const tabTarget = tabs.find(target => target.url === (source === sourceOne ? base + '/siem' : base + '/edr'));
      if (!tabTarget) throw Error('Tab target unavailable: ' + JSON.stringify(tabs));
      await send('Extensions.triggerAction',{id,targetId:tabTarget.targetId});
      await wait(100);
    }
    const builder = await targetFor(builderURL);
    await until(() => builder.evaluate('!!window.SOCNote?.report'), 'app initialization');
    builder.tabId = await builder.evaluate('chrome.tabs.getCurrent().then(tab=>tab.id)');
    await focus(builder.tabId);
    const fill = async (selector, value) => builder.evaluate(`(() => {const input=document.querySelector(${JSON.stringify(selector)}); input.focus(); input.value=${JSON.stringify(value)}; input.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText'}));})()`);
    await fill('#rule-input','Existing rule');
    await fill('#analysis-input','Analyst-written analysis\n\nMust stay unchanged.');
    await fill('#raw-input','Host: LOCAL-ONE');
    await builder.evaluate('document.getElementById("process-source-button").click(); SOCNote.remediation.setActiveTactics(["credential-access"]); document.querySelector("[data-choose=credential-access-1]").click(); window.dispatchEvent(new Event("pagehide"));');
    const before = await builder.evaluate('SOCNote.storage.load().document');
    const otherTab = await worker.evaluate(`chrome.tabs.create({url:${JSON.stringify(builderURL)},active:false,windowId:${(await nativeTab(builder.tabId)).windowId}})`);
    let otherTarget;
    await until(async () => {otherTarget=(await send('Target.getTargets')).targetInfos.find(info=>info.url===builderURL && info.targetId!==builder.targetId);return !!otherTarget;},'second Note Builder');
    const other = {...(await attach(otherTarget.targetId)),tabId:otherTab.id};
    await until(() => other.evaluate('!!window.SOCNote?.report'), 'second app initialization');

    async function select(source, selector, value) {
      await focus(source.tabId);
      await until(() => source.evaluate('!!document.getElementById("value")'), 'source document: ' + source.tabId + ' ' + await source.evaluate('location.href'));
      await source.evaluate(`(() => {
        document.activeElement.blur();
        const node=document.querySelector(${JSON.stringify(selector)});
        if (${JSON.stringify(value)} !== null) node.textContent=${JSON.stringify(value)};
        const selection=window.getSelection(); selection.removeAllRanges();
        const range=document.createRange(); range.selectNodeContents(node); selection.addRange(range);
      })()`);
    }
    const capture = source => worker.evaluate(`chrome.tabs.get(${source.tabId}).then(tab=>captureSelection(tab))`);
    await select(sourceOne,'#value','185.10.20.5');
    await capture(sourceOne);
    await select(sourceTwo,'#value','192.0.2.2');
    await capture(sourceTwo);
    await select(sourceOne,'#unknown','jdupont');
    await capture(sourceOne);
    await focus(sourceTwo.tabId);
    await sourceTwo.evaluate('window.getSelection().removeAllRanges(); document.getElementById("user").focus(); document.getElementById("user").select();');
    await capture(sourceTwo);
    const pendingCaptures = (await queue()).captures;
    assert.equal(pendingCaptures.length,4);
    assert.equal(new Set(pendingCaptures.map(record=>record.windowId)).size,2);
    assert.equal(pendingCaptures[0].context,'Source IP');
    assert.equal(pendingCaptures[3].context,'Username');
    assert.equal(await other.evaluate('SOCNote.storage.load().document.extensionCaptures?.length || 0'),0);
    await focus(builder.tabId);
    await until(async () => (await queue()).captures.length === 0,'automatic import and acknowledgement');
    const imported = await builder.evaluate('SOCNote.storage.load().document');
    assert.equal(imported.extensionCaptures.length,4);
    assert.equal(imported.variables.find(record=>record.value==='185.10.20.5').key,'IP');
    assert.equal(imported.variables.find(record=>record.value==='192.0.2.2').key,'IP 2');
    assert.equal(imported.variables.find(record=>record.value==='jdupont').key,'Unknown');
    for (const key of ['rule','analysis','raw','capturedRaw','sourceFileName','remediation']) assert.deepEqual(imported[key],before[key],key+' unchanged');
    assert.equal(await other.evaluate('document.getElementById("capture-count")'),null,'Summary has no capture counter');
    assert.equal(await other.evaluate('Array.from(document.querySelectorAll("[data-variable-value]"), input => input.value).includes("185.10.20.5")'),false,'Inactive Note Builder does not import');

    // A duplicate from another tab/window keeps its own provenance, not a second row.
    await select(sourceTwo,'#value','185.10.20.5');
    await capture(sourceTwo);
    await focus(other.tabId);
    await until(async () => (await queue()).captures.length===0,'second focused builder imports');
    const duplicate = await other.evaluate('SOCNote.storage.load().document');
    assert.equal(duplicate.extensionCaptures.length,5);
    assert.equal(duplicate.variables.filter(record=>record.value==='185.10.20.5').length,1);
    assert.equal(new Set(duplicate.extensionCaptures.filter(record=>record.value==='185.10.20.5').map(record=>record.title)).size,2);

    // Reload after durable import but before acknowledgement. The receipt prevents replay.
    await other.evaluate(`window.originalSendMessage=chrome.runtime.sendMessage.bind(chrome.runtime); chrome.runtime.sendMessage=(message,...rest)=>message.type==='soc-capture/ack'?new Promise(()=>{}):originalSendMessage(message,...rest);`);
    await select(sourceOne,'#value','203.0.113.7');
    await capture(sourceOne);
    await focus(other.tabId);
    await until(() => other.evaluate('SOCNote.storage.load().document.extensionCaptures.length===6'),'durable import before ack');
    assert.equal((await queue()).captures.length,1,'Unacknowledged source retained');
    await other.command('Page.reload');
    await until(() => other.evaluate('!!window.SOCNote?.report'),'reloaded app');
    await until(async () => (await queue()).captures.length===0,'retry acknowledges saved receipt');
    const recovered = await other.evaluate('SOCNote.storage.load().document');
    assert.equal(recovered.extensionCaptures.length,6);
    assert.equal(recovered.variables.filter(record=>record.value==='203.0.113.7').length,1);

    // Selected HTML remains literal text throughout the selection workflow.
    await select(sourceOne,'#unknown','Literal <img src=x onerror=alert(1)>');
    await capture(sourceOne);
    await focus(other.tabId);
    await until(async () => (await queue()).captures.length===0,'literal selection import');
    assert.equal(await other.evaluate('document.querySelectorAll("#report-input img, #final-report-input img").length'),0);
    assert((await other.evaluate('SOCNote.report.getText()')).includes('Literal <img'));
    // A failed autosave cannot acknowledge or visibly commit the next input.
    await other.evaluate('window.testStorageSet=Storage.prototype.setItem; Storage.prototype.setItem=function(){throw Error("Forced quota failure");};');
    await select(sourceOne,'#value','198.51.100.9');
    await capture(sourceOne);
    await focus(other.tabId);
    await until(()=>other.evaluate('!document.getElementById("draft-error").hidden'),'autosave failure is reported');
    await until(async()=>{const pending=await queue();return pending.captures.length===1 && !pending.claim;},'failed import releases the claim');
    assert.equal(await other.evaluate('SOCNote.report.getText().includes("198.51.100.9")'),false);
    assert.equal((await queue()).captures.length,1,'Failed autosave retains the capture');
    await other.evaluate('Storage.prototype.setItem=window.testStorageSet; window.dispatchEvent(new Event("focus"));');
    await until(async()=> (await queue()).captures.length===0,'recovered autosave acknowledges import');
    assert.equal(await other.evaluate('SOCNote.report.getText().includes("198.51.100.9")'),true);
    await focus(sourceOne.tabId);
    await sourceOne.evaluate('window.getSelection().removeAllRanges(); document.activeElement.blur()');
    await capture(sourceOne);
    assert.equal((await queue()).captures.length,0,'No selection creates no capture');
    await sourceOne.evaluate('const password=document.getElementById("user"); password.type="password"; password.focus(); password.select();');
    await capture(sourceOne);
    assert.equal((await queue()).captures.length,0,'Password inputs are not captured');
    await worker.evaluate('captureSelection({id:12345,windowId:1,url:"chrome://settings/"})');
    assert.equal((await queue()).captures.length,0,'Restricted pages create no capture');
    // Browser UI focus is not exposed by headless Chrome. Simulate only that
    // document-focus signal, retaining real activeTab injection and tab URL data.
    await select(sourceOne,'#unknown','Old selected page text');
    await worker.evaluate(`windowTestReadSelection=readSOCSelection; readSOCSelection=function(){return {value:window.getSelection().toString(),context:'',title:document.title,url:location.href,focused:false};};`);
    try {
      await capture(sourceOne);
      assert.equal((await queue()).captures.length,0,'Address-bar focus captures neither a URL nor a stale selection');
    } finally {
      await worker.evaluate('readSOCSelection=windowTestReadSelection; delete windowTestReadSelection;');
    }
    // Seed synthetic text before testing the real system-clipboard reader.
    await send('Browser.grantPermissions',{permissions:['clipboardReadWrite','clipboardSanitizedWrite']});
    const clipText='URL: https://clipboard.example.invalid/path\r\nIP: 192.0.2.88';
    await focus(other.tabId);
    await other.command('Page.bringToFront');
    await other.evaluate(`navigator.clipboard.writeText(${JSON.stringify(clipText)})`);
    const selectedText='Selected page value\n\n  Indented <b>literal</b>\nLast line';
    await sourceOne.evaluate('document.getElementById("unknown").style.whiteSpace="pre-wrap";');
    await select(sourceOne,'#unknown',selectedText);
    await sourceOne.command('Page.bringToFront');
    const selectionResult=await worker.evaluate(`chrome.tabs.get(${sourceOne.tabId}).then(tab=>captureCommand(tab))`);
    assert.equal(selectionResult.ok,true,JSON.stringify(selectionResult));
    assert.equal(selectionResult.warning,undefined,JSON.stringify(selectionResult));
    const selectionCaptures=(await queue()).captures;
    assert.equal(selectionCaptures.length,1,'Selection shortcut adds only the selection');
    assert.equal(selectionCaptures[0].method,'selection');
    assert.equal(selectionCaptures[0].value,selectedText);
    assert.equal(await sourceOne.evaluate('navigator.clipboard.readText()'),selectedText,'Selection shortcut preserves line breaks, indentation and literal HTML');
    await sourceOne.evaluate('window.getSelection().removeAllRanges();');
    const emptySelection=await worker.evaluate(`chrome.tabs.get(${sourceOne.tabId}).then(tab=>captureCommand(tab))`);
    assert.equal(emptySelection.ok,false);
    assert.equal((await queue()).captures.length,1,'No selection does not import the previous clipboard');
    assert.equal(await sourceOne.evaluate('navigator.clipboard.readText()'),selectedText,'No selection leaves the clipboard untouched');
    assert.equal((await worker.evaluate('chrome.runtime.getContexts({contextTypes:["OFFSCREEN_DOCUMENT"]})')).length,0,'Offscreen document closes after copying');
    await focus(other.tabId);
    await until(async()=> (await queue()).captures.length===0,'Selection imports');
    const clipboardDraft=await other.evaluate('SOCNote.storage.load().document');
    assert(!clipboardDraft.variables.some(record=>record.value==='https://clipboard.example.invalid/path'),'Previous clipboard is not imported by the selection shortcut');
    assert(!clipboardDraft.variables.some(record=>record.value==='192.0.2.88'));
    await other.command('Page.bringToFront');
    await other.evaluate(`navigator.clipboard.writeText(${JSON.stringify(clipText)})`);
    await focus(sourceTwo.tabId);
    const clipboardOnly=await worker.evaluate(`chrome.tabs.get(${sourceTwo.tabId}).then(tab=>captureClipboard(tab))`);
    assert.equal(clipboardOnly.ok,true,JSON.stringify(clipboardOnly));
    assert.equal((await queue()).captures.length,1);
    assert.equal((await queue()).captures[0].value.replace(/\r\n?/g,'\n'),clipText.replace(/\r\n?/g,'\n'));
    assert.equal((await queue()).captures[0].method,'clipboard');
    await focus(other.tabId);
    await until(async()=> (await queue()).captures.length===0,'Clipboard-only import');
    await other.command('Page.bringToFront');
    assert.equal((await other.evaluate('navigator.clipboard.readText()')).replace(/\r\n?/g,'\n'),clipText.replace(/\r\n?/g,'\n'),'Clipboard-only shortcut leaves the clipboard intact');
    const importedClipboard=await other.evaluate('SOCNote.storage.load().document');
    assert(importedClipboard.variables.some(record=>record.value==='https://clipboard.example.invalid/path'));
    assert(importedClipboard.variables.some(record=>record.value==='192.0.2.88'));
    const clipboardChord=async page=>{
      await page.command('Input.dispatchKeyEvent',{type:'keyDown',modifiers:3,key:'x',code:'KeyX',windowsVirtualKeyCode:88});
      await page.command('Input.dispatchKeyEvent',{type:'keyUp',modifiers:3,key:'x',code:'KeyX',windowsVirtualKeyCode:88});
    };
    // Ctrl+Alt+X is a DOM alias because Chrome prohibits Ctrl+Alt commands.
    await other.evaluate('navigator.clipboard.writeText("Page alias clipboard")');
    await focus(sourceOne.tabId);
    await sourceOne.command('Page.bringToFront');
    await until(()=>sourceOne.evaluate('document.hasFocus()'),'page alias focus');
    await sourceOne.evaluate('document.dispatchEvent(new KeyboardEvent("keydown",{key:"x",ctrlKey:true,altKey:true,bubbles:true}));');
    await wait(100);
    assert.equal((await queue()).captures.length,0,'Synthetic page events do not read the clipboard');
    await clipboardChord(sourceOne);
    await until(async()=> (await queue()).captures.length===1,'trusted page clipboard alias');
    assert.equal((await queue()).captures[0].value,'Page alias clipboard');
    assert.equal((await queue()).captures[0].method,'clipboard');
    await focus(other.tabId);
    await other.command('Page.bringToFront');
    await until(async()=> (await queue()).captures.length===0,'page alias import');
    await other.evaluate('navigator.clipboard.writeText("Tool alias clipboard")');
    await other.evaluate('document.querySelector("#report-input .summary-pair").focus()');
    const countBeforeAlias=await other.evaluate('SOCNote.storage.load().document.extensionCaptures.length');
    await other.evaluate('document.dispatchEvent(new KeyboardEvent("keydown",{key:"x",ctrlKey:true,altKey:true,bubbles:true}));');
    await wait(100);
    assert.equal(await other.evaluate('SOCNote.storage.load().document.extensionCaptures.length'),countBeforeAlias,'Synthetic tool events do not read the clipboard');
    await clipboardChord(other);
    await until(()=>other.evaluate(`SOCNote.storage.load().document.extensionCaptures.length===${countBeforeAlias+1}`),'trusted tool clipboard alias');
    await until(async()=> (await queue()).captures.length===0,'tool alias acknowledgement');
    assert.equal(await other.evaluate('SOCNote.storage.load().document.extensionCaptures.at(-1).value'),'Tool alias clipboard');
    assert.equal((await worker.evaluate('chrome.runtime.getContexts({contextTypes:["OFFSCREEN_DOCUMENT"]})')).length,0);
    const typedValues=['2026-10-13T10:15:30Z','13/10/2026 12:15:30 +02:00','550e8400-e29b-41d4-a716-446655440000','S-1-5-18','Mitigated','Not mitigated'];
    for(const value of typedValues) {
      await select(sourceOne,'#unknown',value);
      await sourceOne.command('Page.bringToFront');
      await capture(sourceOne);
    }
    assert.deepEqual((await queue()).captures.map(record=>record.value),typedValues,'Capture rendered selections from the focused page');
    await focus(other.tabId);
    await until(async()=> (await queue()).captures.length===0,'new capture types import and acknowledge');
    const typedDraft=await other.evaluate('SOCNote.storage.load().document');
    // The captured selection is kept as sent; Summary reads "Unmitigated".
    const summaryValues=typedValues.map(value=>value==='Not mitigated'?'Unmitigated':value);
    assert.deepEqual(summaryValues.map(value=>typedDraft.variables.find(record=>record.value===value)?.key),['Date','Date 2','UUID','SID','EDR Action','EDR Action 2']);
    await other.command('Page.reload');
    await until(()=>other.evaluate('!!window.SOCNote?.report'),'new types restored after reload');
    const restoredTypes=await other.evaluate('SOCNote.storage.load().document');
    assert.deepEqual(summaryValues.map(value=>restoredTypes.variables.find(record=>record.value===value).captureType),['Date','Date','UUID','SID','EDR Action','EDR Action']);
    for (const value of typedValues.slice(0,2)) {
      const id=restoredTypes.variables.find(record=>record.value===value).id;
      assert.equal(await other.evaluate(`document.querySelector('[data-time-zone="${id}"]').value`),'UTC','Captured dates receive the default time zone');
      assert.equal(await other.evaluate(`document.querySelector('[data-time-zone="${id}"]').parentNode.hidden`),false);
      assert((await other.evaluate('SOCNote.report.getText()')).includes(value+' (UTC)'));
    }
    for(const key of ['rule','analysis','raw','capturedRaw','sourceFileName','remediation']) assert.deepEqual(restoredTypes[key],before[key],key+' unchanged by new capture types');
    // An existing clipboard-only SIEM export also imports real JSON.
    await other.command('Page.bringToFront');
    const clipboardJSON={members:[{'clipboard.json':'First'},{'clipboard.json':'Second'}]};
    await other.evaluate(`navigator.clipboard.writeText(${JSON.stringify(JSON.stringify(clipboardJSON))});`);
    await clipboardChord(other);
    await until(()=>other.evaluate('SOCNote.storage.load().document.variables.some(record=>record.key==="clipboard.json2")'),'JSON clipboard import');
    assert.equal(await other.evaluate('navigator.clipboard.readText()'),JSON.stringify(clipboardJSON),'JSON clipboard import does not modify the existing export');
    // A page script speaks the documented postMessage protocol to the real
    // isolated-world receiver. SIEM and Note Builder remain in two separate browser windows.
    const jsonSource=(await nativeTab(sourceTwo.tabId)).windowId===(await nativeTab(other.tabId)).windowId?sourceOne:sourceTwo;
    assert.notEqual((await nativeTab(jsonSource.tabId)).windowId,(await nativeTab(other.tabId)).windowId);
    await jsonSource.evaluate(`window.testSend=(type,requestId,data)=>new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{removeEventListener('message',listen);reject(Error('No receiver'));},5000);
      function listen(event){if(event.source!==window||event.data?.channel!=='soc-note-json/v1'||event.data.type!=='result'||event.data.requestId!==requestId)return;removeEventListener('message',listen);clearTimeout(timer);resolve(event.data);}
      addEventListener('message',listen);
      postMessage({channel:'soc-note-json/v1',type,requestId,...(type==='send'?{data:typeof data==='string'?data:JSON.stringify(data)}:{})},location.origin);
    })`);
    await focus(jsonSource.tabId);await jsonSource.command('Page.bringToFront');
    const siemJSON=[{'user.name':'json-analyst','host.hostname':'JSON-HOST-ONE','process.command_line':'first line\n\n  second line'},{'host.hostname':'JSON-HOST-TWO','payload':'<img src="https://example.invalid/exfil" onerror="window.compromised=1">'},{'host.hostname':'JSON-HOST-TWO'}];
    siemJSON[0].members=[{name:'Molecule Man'},{name:'Madame Uppercut'}];
    const sendJSON=(data,id)=>jsonSource.evaluate(`testSend('send',${JSON.stringify(id)},${JSON.stringify(data)}).then(result=>result,error=>({ok:false,error:error.message}))`);
    const received=await sendJSON(siemJSON,'siem-cross-window');
    assert.equal(received.ok,true,JSON.stringify(received));
    assert(['queued','imported'].includes(received.status));
    try {
      await until(async()=> (await queue()).captures.length===0,'background JSON import and acknowledgement across windows');
    } catch (error) {
      console.error('JSON diagnostic',JSON.stringify({queue:await queue(),consumer:await worker.evaluate('jsonConsumer()'),contexts:await worker.evaluate('chrome.runtime.getContexts({contextTypes:["TAB"],documentUrls:[BUILDER_URL]})'),other:await other.evaluate('({focus:document.hasFocus(),visibility:document.visibilityState,error:document.getElementById("draft-error").textContent,toast:document.getElementById("toast").textContent,tab:chrome.tabs.getCurrent().then(tab=>tab.id)})')}));
      throw error;
    }
    const jsonDraft=await other.evaluate('SOCNote.storage.load().document');
    assert.equal(jsonDraft.variables.find(record=>record.value==='JSON-HOST-TWO').key,'host.hostname2');
    assert.equal(jsonDraft.variables.find(record=>record.key==='process.command_line').value,'first line\n\n  second line');
    assert.equal(jsonDraft.variables.find(record=>record.key==='name').value,'Molecule Man');
    assert.equal(jsonDraft.variables.find(record=>record.key==='name2').value,'Madame Uppercut');
    assert(!jsonDraft.variables.some(record=>record.key==='members'));
    assert.equal(await other.evaluate('document.querySelector("textarea[data-variable-value]").value'),'first line\n\n  second line');
    for(const key of ['rule','analysis','raw','capturedRaw','sourceFileName','remediation']) assert.deepEqual(jsonDraft[key],before[key],key+' unchanged by background JSON');
    assert.equal(await worker.evaluate('windowTestFocusedId'),(await nativeTab(jsonSource.tabId)).windowId,'JSON delivery does not steal SIEM window focus');
    await until(async()=> (await jsonSource.evaluate("testSend('status','siem-cross-window')")).status==='imported','imported status reported to the source page');
    assert.equal(await other.evaluate('document.querySelectorAll("#report-input img,#final-report-input img").length'),0);
    const sourceCount=jsonDraft.extensionCaptures.length;
    const replay=await sendJSON(siemJSON,'siem-cross-window');
    assert.equal(replay.duplicate,true);assert.equal(replay.status,'imported');
    assert.equal((await queue()).captures.length,0);
    assert.equal(await other.evaluate('SOCNote.storage.load().document.extensionCaptures.length'),sourceCount);
    const wrongID=await sendJSON({'host.hostname':'Changed payload'},'siem-cross-window');
    assert.equal(wrongID.ok,false);assert(wrongID.error.includes('reused'));
    const invalidJSON=await sendJSON('{"broken":','siem-invalid');
    assert.equal(invalidJSON.ok,false);assert(invalidJSON.error.includes('Invalid JSON'));
    assert.equal((await queue()).captures.length,0);
    // A save failure remains queued, is reported to the sender, and recovers.
    await other.evaluate('window.jsonTestSet=Storage.prototype.setItem; Storage.prototype.setItem=function(){throw Error("Forced quota");};');
    assert.equal((await sendJSON({'recovery.field':'Retried JSON'},'siem-recovery')).ok,true);
    await until(async()=> (await queue()).jsonReceipts?.some(receipt=>receipt.id==='json:siem-recovery' && receipt.error),'JSON save failure reported to sender');
    assert.equal(await other.evaluate('SOCNote.report.getText().includes("Retried JSON")'),false);
    assert.equal((await queue()).captures.length,1);
    await other.evaluate('Storage.prototype.setItem=window.jsonTestSet;');
    await until(async()=> (await queue()).captures.length===0,'background JSON save recovery');
    assert.equal(await other.evaluate('SOCNote.report.getText().includes("Retried JSON")'),true);
    const recoveredJSON=await other.evaluate('SOCNote.storage.load().document');
    await other.command('Page.reload');
    await until(()=>other.evaluate('!!window.SOCNote?.report'),'JSON draft reload');
    assert.deepEqual(await other.evaluate('SOCNote.storage.load().document.variables.map(record=>record.id)'),recoveredJSON.variables.map(record=>record.id));
    // The shipped Tampermonkey userscript copies its table and sends the same rows in one click.
    await focus(jsonSource.tabId);await jsonSource.command('Page.bringToFront');
    await jsonSource.evaluate(`document.body.insertAdjacentHTML('beforeend','<div id="details_list_table_wrapper"><table id="details_list_table"><thead><tr><th>user.name</th><th>Status <i></i></th><th>source.ip</th></tr></thead><tbody><tr><td>userscript-analyst</td><td>Open</td><td><a class="enrich-data" data-info="203.0.113.77">203.0.113.77 <i></i></a></td></tr><tr><td>userscript-second</td><td>Closed</td><td>198.51.100.9</td></tr></tbody></table></div>')`);
    const userscript=(await fs.readFile(path.join(__dirname,'../tampermonkey/optimus-export-json.user.js'),'utf8')).replace('REMPLACER_PAR_LE_LOGO_BASE64','data:image/gif;base64,R0lGODlhAQABAAAAACw=');
    await jsonSource.evaluate(userscript);
    const userscriptRows=[{'user.name':'userscript-analyst','source.ip':'203.0.113.77'},{'user.name':'userscript-second','source.ip':'198.51.100.9'}];
    const userscriptValues=()=>other.evaluate('SOCNote.storage.load().document.variables.map(record=>record.value)');
    await jsonSource.evaluate('document.getElementById("optimus-json-button").click()');
    await until(async()=> (await userscriptValues()).includes('userscript-second'),'userscript sends its table');
    assert.equal(await jsonSource.evaluate('navigator.clipboard.readText()'),JSON.stringify(userscriptRows,null,2),'The same click still copies the formatted JSON');
    const userscriptDraft=await other.evaluate('SOCNote.storage.load().document');
    assert.equal(userscriptDraft.variables.find(record=>record.value==='203.0.113.77').key,'source.ip');
    assert(!userscriptDraft.variables.some(record=>['Open','Closed'].includes(record.value)),'Excluded columns are neither copied nor sent');
    await until(()=>jsonSource.evaluate('!!document.getElementById("optimus-json-toast")?.textContent.includes("importée(s) dans Notepad++++")'),'userscript import confirmation');
    // Each click is a new send, so a value deleted from Summary returns.
    const deletedUserscriptId=userscriptDraft.variables.find(record=>record.value==='userscript-second').id;
    await other.evaluate(`document.querySelector('[data-pair-action=remove][data-id="${deletedUserscriptId}"]').click(); window.dispatchEvent(new Event("pagehide"));`);
    assert.equal((await userscriptValues()).includes('userscript-second'),false);
    await jsonSource.evaluate('document.getElementById("optimus-json-button").click()');
    await until(async()=> (await userscriptValues()).includes('userscript-second'),'userscript resend restores a deleted value');
    assert.equal((await userscriptValues()).filter(value=>value==='203.0.113.77').length,1,'Values still present are not duplicated');
    await until(async()=> (await queue()).captures.length===0,'userscript sends acknowledged');
    // A stale inactive view must respect a new investigation saved by another
    // view, including its latest notes, before accepting background JSON.
    await focus(other.tabId);
    await other.evaluate('document.getElementById("new-button").click(); const notes=document.getElementById("analysis-input"); notes.value="Latest new investigation notes"; notes.dispatchEvent(new InputEvent("input",{bubbles:true})); window.dispatchEvent(new Event("pagehide"));');
    const newCreatedAt=await other.evaluate('SOCNote.storage.load().document.createdAt');
    await focus(builder.tabId);
    await focus(jsonSource.tabId);await jsonSource.command('Page.bringToFront');
    assert.equal((await sendJSON({'fresh.field':'Fresh background JSON'},'siem-new-investigation')).ok,true);
    await until(async()=> (await queue()).captures.length===0,'stale view adopts new investigation before JSON import');
    const freshDraft=await builder.evaluate('SOCNote.storage.load().document');
    assert.equal(freshDraft.createdAt,newCreatedAt);
    assert.equal(freshDraft.analysis,'Latest new investigation notes');
    assert.equal(freshDraft.variables.length,1);
    assert.equal(freshDraft.variables[0].key,'fresh.field');
    await builder.evaluate('document.getElementById("undo-button").click();');
    const undoJSON=await builder.evaluate('SOCNote.storage.load().document');
    assert.equal(undoJSON.createdAt,newCreatedAt);
    assert.equal(undoJSON.analysis,'Latest new investigation notes');
    assert.equal(undoJSON.variables.length,0,'Undo JSON preserves the latest notes rather than an old tab snapshot');
    const commands = await worker.evaluate('chrome.commands.getAll()');
    assert.equal(commands.find(command=>command.name==='capture-selection').shortcut,'Ctrl+Shift+X');
    assert.deepEqual(commands.filter(command=>command.name!=='_execute_action').map(command=>command.name),['capture-selection']);
    assert.equal(await worker.evaluate('chrome.runtime.getManifest().permissions.includes("contextMenus")'),false);
    console.log('MV3 browser checks passed: real activeTab injection, Tampermonkey userscript copy and direct send, several tabs/windows, safe import and acknowledgement recovery, selection capture/copy, trusted Ctrl+Alt+X, JSON clipboard import, local JSON delivery between windows, background import without taking focus, replay protection, visual confirmation, failed-save recovery, multiline JSON and preservation of the latest investigation/notes. Only one registered command, no external requests.');
    const errors = events.filter(event=>event.method==='Runtime.exceptionThrown' || (event.method==='Log.entryAdded' && event.params.entry.level==='error'));
    assert.deepEqual(errors,[]);
    const remote = events.filter(event=>event.method==='Network.requestWillBeSent' && /^https?:/.test(event.params.request.url) && !event.params.request.url.startsWith(base));
    assert.deepEqual(remote,[],'No external requests');
  } finally {
    if (socket) socket.close();
    chrome.kill('SIGTERM');
    await new Promise(resolve=>{if(chrome.exitCode!==null)resolve();else{chrome.once('exit',resolve);setTimeout(resolve,2000);}});
    await new Promise(resolve=>server.close(resolve));
    await fs.rm(profile,{recursive:true,force:true,maxRetries:8,retryDelay:100});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});

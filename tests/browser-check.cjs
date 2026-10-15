// Optional browser checks. Requires an already installed Chrome, no npm packages.
const { spawn } = require('node:child_process');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');

(async () => {
  const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'soc-browser-'));
  const chrome = spawn(process.env.SOC_BROWSER || '/usr/bin/google-chrome', ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-background-networking', '--disable-sync', '--disable-default-apps', '--no-first-run', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], {stdio: ['ignore', 'ignore', 'pipe']});
  let socket;
  try {
    const endpoint = await new Promise((resolve, reject) => {
      let output = '';
      const timer = setTimeout(() => reject(Error('Chrome launch timed out')), 15000);
      chrome.on('error', error => { clearTimeout(timer); reject(error); });
      chrome.on('exit', code => { clearTimeout(timer); reject(Error('Chrome exited: ' + code)); });
      chrome.stderr.on('data', chunk => {
        output += chunk.toString();
        const match = /DevTools listening on (ws:\/\/\S+)/.exec(output);
        if (match) { clearTimeout(timer); resolve(match[1]); }
      });
    });
    socket = new WebSocket(endpoint);
    await new Promise((resolve, reject) => { socket.addEventListener('open', resolve, {once: true}); socket.addEventListener('error', reject, {once: true}); });
    let nextId = 0;
    const pending = new Map();
    const events = [];
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (!message.id) { events.push(message); return; }
      const promise = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) promise.reject(Error(JSON.stringify(message.error)));
      else promise.resolve(message.result);
    });
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, {resolve, reject});
      socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
    });
    const {targetId} = await send('Target.createTarget', {url: 'about:blank'});
    const {sessionId} = await send('Target.attachToTarget', {targetId, flatten: true});
    const command = (method, params = {}) => send(method, params, sessionId);
    const evaluate = async expression => {
      const result = await command('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true, userGesture: true});
      if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
      return result.result.value;
    };
    const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
    const ready = async () => {
      for (let i = 0; i < 100; i++) {
        try { if (await evaluate('document.readyState === "complete" && !!SOCNote.formatter')) return; } catch {}
        await wait(30);
      }
      throw Error('Application did not initialize');
    };
    const click = selector => evaluate(`(() => { const node = document.querySelector(${JSON.stringify(selector)}); node.focus(); node.click(); })()`);
    const fill = (selector, value) => evaluate(`(() => { const node = document.querySelector(${JSON.stringify(selector)}); node.focus(); if (node.isContentEditable) node.textContent = ${JSON.stringify(value)}; else node.value = ${JSON.stringify(value)}; node.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText'})); })()`);
    const text = () => evaluate('SOCNote.summary.getText()');
    const report = () => evaluate('SOCNote.report.getText()');
    const keypress = async (key, code, modifiers, virtualKey) => {
      await command('Input.dispatchKeyEvent', {type: 'keyDown', key, code, modifiers, windowsVirtualKeyCode: virtualKey});
      await command('Input.dispatchKeyEvent', {type: 'keyUp', key, code, modifiers: 0, windowsVirtualKeyCode: virtualKey});
    };
    for (const method of ['Page.enable', 'Runtime.enable', 'Log.enable', 'Network.enable']) await command(method);
    await command('Network.emulateNetworkConditions', {offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0});
    await command('Network.setBlockedURLs', {urls: ['http://*', 'https://*', 'ws://*', 'wss://*']});
    await command('Emulation.setDeviceMetricsOverride', {width: 1440, height: 900, deviceScaleFactor: 1, mobile: false});
    await command('Page.navigate', {url: pathToFileURL(path.resolve(__dirname, '../index.html')).href});
    await ready();
    assert.equal(await evaluate('document.querySelectorAll("main > section").length'), 5);
    assert.equal(await evaluate('getComputedStyle(document.documentElement).colorScheme'), 'light');
    assert.equal(await evaluate('document.querySelector(".investigation-pane")'), null);
    assert.equal(await evaluate('localStorage.length'), 0);
    await fill('#rule-input', 'Suspicious PowerShell Execution');
    await fill('#raw-input', 'user: a.martin\nhost: WS-0042\ndestination_ip: 192.0.2.17\ndestination_ip: 192.0.2.18\nprocess: powershell.exe\ncommand_line: powershell.exe -NoProfile -File inventory.ps1');
    await click('#process-source-button');
    assert.equal(await evaluate('document.querySelectorAll("#report-input [data-variable-id]").length'), 6);
    const example = await text();
    const exampleReport = await report();
    await click('#new-button');
    assert.equal(await text(), '');
    await click('#undo-button');
    assert.equal(await text(), example);

    await send('Browser.grantPermissions', {permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite']});
    await evaluate('window.nativeClipboard = navigator.clipboard');
    await click('#copy-report-button');
    await wait(60);
    assert.equal(await evaluate('nativeClipboard.readText()'), exampleReport);
    await click('[data-copy-variable]');
    await wait(60);
    assert.equal(await evaluate('nativeClipboard.readText()'), 'a.martin');
    await evaluate("Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:()=>Promise.reject(Error('Forced refusal'))}})");
    await click('#copy-report-button');
    await wait(60);
    assert.equal(await evaluate('nativeClipboard.readText()'), exampleReport);
    await evaluate('window.savedExec = document.execCommand; document.execCommand = () => false');
    await click('#copy-report-button');
    await wait(30);
    assert.equal(await evaluate('document.getElementById("copy-dialog").open'), false);
    assert.equal(await evaluate('document.getElementById("final-report-input").textContent'), exampleReport);
    await keypress('Escape', 'Escape', 0, 27);
    await wait(30);
    assert.equal(await evaluate('document.getElementById("copy-dialog").open'), false);
    assert.equal(await evaluate('document.getElementById("manual-copy-input").value'), '');
    await evaluate('document.execCommand = savedExec; delete navigator.clipboard');

    await click('#new-button');
    // A pasted block is cleaned on arrival: no pictographs, outer spaces or outer
    // blank lines. Inner CRLF line endings stay exactly as copied.
    const raw = 'user: alice\r\nhost = ONE';
    await evaluate(`nativeClipboard.writeText(${JSON.stringify('\r\n\r\n  ⚠️ ' + 'user: alice ✅\r\nhost = ONE' + '  \r\n\r\n')})`);
    await evaluate('document.getElementById("raw-input").focus()');
    await keypress('v', 'KeyV', 2, 86);
    await wait(60);
    assert.equal(await evaluate('document.querySelectorAll("#report-input [data-variable-id]").length'), 2);
    assert.equal(await text(), 'user : alice\nhost : ONE');
    await evaluate('window.dispatchEvent(new Event("pagehide"))');
    assert.equal(await evaluate('SOCNote.storage.load().document.raw'), raw);
    await evaluate('document.getElementById("raw-input").focus(); document.getElementById("raw-input").select()');
    await keypress('c','KeyC',2,67);
    await wait(60);
    assert.equal(await evaluate('nativeClipboard.readText()'), raw);

    await fill('[data-variable-value]', 'bob');
    assert((await text()).includes('user : bob'));
    await fill('#raw-input', 'user: charlie\nhost: TWO');
    await wait(300);
    assert((await text()).includes('user : bob'));
    assert((await text()).includes('user : charlie'));
    await click('#process-source-button');
    assert.equal(await evaluate('document.getElementById("raw-input").value'), '');
    await click('#undo-button');
    assert.equal(await evaluate('document.getElementById("raw-input").value'), 'user: charlie\nhost: TWO');
    await click('#new-button');
    const attack = '<img src="https://example.invalid/exfil" onerror="window.compromised=1">';
    await fill('#raw-input', 'payload: ' + attack + '\nurl: javascript:alert(1)');
    await wait(300);
    assert((await text()).includes(attack));
    assert.equal(await evaluate('document.querySelectorAll("img:not(.app-logo)").length'), 0);
    assert.equal(await evaluate('window.compromised || null'), null);
    const persistedPairs = await text();
    await evaluate('window.dispatchEvent(new Event("pagehide"))');
    await command('Page.reload');
    await ready();
    assert.equal(await text(), persistedPairs);
    await click('#new-button');
    assert.equal(await evaluate('localStorage.getItem("soc-note-builder.current-analysis.v1")'), null);
    await command('Page.reload');
    await ready();
    assert.equal(await text(), '');

    await require('./summary-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    // remediation-browser-scenarios.cjs is kept for the return of the withdrawn Remediation sections.
    await require('./workflow-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    await require('./url-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    await require('./timezone-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    await require('./report-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    await require('./entity-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    await require('./report-update-browser-scenarios.cjs')({ evaluate, command, click, fill, wait, ready, keypress });
    await require('./clipboard-browser-scenarios.cjs')({ evaluate, click, fill, wait, keypress });
    const downloadPath=path.join(profile,"downloads");
    await fs.mkdir(downloadPath);
    await send("Browser.setDownloadBehavior",{behavior:"allow",downloadPath,eventsEnabled:true});
    await require("./current-analysis-browser-scenarios.cjs")({evaluate,command,click,fill,wait,ready,keypress,fs,path,downloadPath,profile,events});
    await require('./json-browser-scenarios.cjs')({evaluate,command,click,fill,wait,ready,keypress,fs,path,profile});
    await require('./interface-browser-scenarios.cjs')({evaluate,command,click,fill,wait,keypress});
    await fill('#rule-input', 'Unusual sign-in activity');
    await fill('#raw-input', 'User: DOMAIN\\jdupont\nHost: PC-0042\nIP: 192.0.2.17');
    await click('#process-source-button');
    await evaluate('SOCNote.remediation.setActiveTactics(["credential-access"]); document.querySelector("[data-choose=credential-access-1]").click()');
    await fill('#analysis-input', 'Sign-ins reviewed.\n\nNo unusual process activity observed.\nAccount sessions checked.');
    await evaluate('document.getElementById("toast").hidden = true; document.activeElement.blur(); window.scrollTo(0, 0)');
    await wait(180);
    if (process.env.SOC_SCREENSHOT) {
      const {cssContentSize} = await command('Page.getLayoutMetrics');
      const screenshot = await command('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true, clip: {x:0, y:0, width:1440, height:Math.ceil(cssContentSize.height), scale:1}});
      await fs.writeFile(process.env.SOC_SCREENSHOT, Buffer.from(screenshot.data, 'base64'));
    }
    for (const [width, height] of [[1440, 900], [1280, 720], [900, 768], [375, 812]]) {
      await command('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: false});
      assert((await evaluate('document.documentElement.scrollWidth')) <= width, 'Horizontal overflow at ' + width);
      const rows=await evaluate('Array.from(document.querySelectorAll("#report-input .summary-pair"), row => {const key=row.querySelector("[data-variable-key]").getBoundingClientRect(),value=row.querySelector("[data-variable-value]").getBoundingClientRect(),grip=row.querySelector(".summary-pair-grip").getBoundingClientRect(),service=row.querySelector("[data-service-now]").getBoundingClientRect(),copy=row.querySelector("[data-copy-variable]").getBoundingClientRect(),add=row.querySelector("[data-pair-action=add-child]")?.getBoundingClientRect();return {keyWidth:key.width,valueWidth:value.width,serviceNowPlaced:service.right<=copy.left && row.querySelector("[data-service-now]").nextElementSibling.dataset.pairAction==="copy",addPlaced:!add || (add.left>=grip.right && add.right<key.left),aligned:Math.abs((key.top+key.height/2)-(value.top+value.height/2))<1 && key.right<value.left};})');
      assert(rows.every(row=>row.aligned && row.valueWidth>row.keyWidth*2),'Summary keeps titles and values side by side, with most space for the value at '+width);
      assert(rows.every(row=>row.serviceNowPlaced),'ServiceNow sits immediately to the left of Copy at '+width);
      assert(rows.every(row=>row.addPlaced),'The subcategory + sits to the right of the drag grip at '+width);
      if (width === 375 && process.env.SOC_MOBILE_SCREENSHOT) {
        await evaluate('window.scrollTo(0,0)');
        const screenshot = await command('Page.captureScreenshot', {format: 'png'});
        await fs.writeFile(process.env.SOC_MOBILE_SCREENSHOT, Buffer.from(screenshot.data, 'base64'));
      }
      const positions=await evaluate('(() => {const rect=selector=>{const r=document.querySelector(selector).getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,height:r.height,width:r.width};};return {logs:rect(".source-pane"),remediation:rect(".remediation-panel"),rule:rect(".rule-field"),mitre:rect(".mitre-field"),summary:rect(".synthesis-pane"),analysis:rect(".analysis-pane"),report:rect(".report-pane")};})()');
      assert.equal(positions.remediation.height,0,'Remediation and Recommendations are withdrawn');
      if(width>1100){
        // Two equal columns; the MITRE selector sits beside the Rule, above Analysis.
        assert(Math.abs(positions.logs.width-positions.analysis.width)<1);
        assert(Math.abs(positions.rule.left-positions.logs.left)<1 && Math.abs(positions.mitre.left-positions.analysis.left)<1 && Math.abs(positions.mitre.right-positions.analysis.right)<1);
        assert(Math.abs(positions.rule.top-positions.mitre.top)<1);
        assert(positions.summary.height>=540,'Summary has additional vertical space');
        assert(positions.logs.bottom <= positions.summary.top);
        assert(Math.abs(positions.logs.left-positions.summary.left)<1);
        assert(positions.summary.right <= positions.analysis.left);
        assert(Math.abs(positions.analysis.height-(positions.logs.height+positions.summary.height+12))<2);
        assert(Math.abs(positions.report.top-positions.analysis.bottom-12)<1,'Report follows the two columns directly');
        assert(positions.report.left <= positions.logs.left && positions.report.right >= positions.analysis.right);
      } else {
        // Below 1100 px every card sits above the next, full width.
        const order=[positions.rule,positions.mitre,positions.logs,positions.summary,positions.analysis,positions.report];
        assert(order.every((card,index)=>!index || card.top>=order[index-1].bottom),'Cards stack one above the other at '+width);
        assert(order.every(card=>Math.abs(card.left-positions.logs.left)<1 && Math.abs(card.width-positions.logs.width)<1),'Stacked cards share one full-width column at '+width);
      }
      const logo=await evaluate('(() => {const image=document.querySelector("h1 .app-logo"),title=document.querySelector("h1");const range=document.createRange();range.selectNodeContents(title.lastChild);const logo=image.getBoundingClientRect(),text=range.getBoundingClientRect();return {loaded:image.complete && image.naturalWidth>0,left:logo.right<=text.left,height:logo.height,centered:Math.abs((logo.top+logo.height/2)-(text.top+text.height/2))<2};})()');
      assert.deepEqual(logo,{loaded:true,left:true,height:28,centered:true},'Logo sits to the left of the title at '+width);

    }
    const errors = events.filter(event => event.method === 'Runtime.exceptionThrown' || (event.method === 'Log.entryAdded' && event.params.entry.level === 'error') || (event.method === 'Runtime.consoleAPICalled' && event.params.type === 'error'));
    const remote = events.filter(event => event.method === 'Network.requestWillBeSent' && /^(https?|wss?):/.test(event.params.request.url));
    assert.deepEqual(errors, []);
    assert.deepEqual(remote, []);
    console.log('Browser checks passed: five visible cards, inline editable synthesis with linked variables, analysis and complete report, capture without data loss, Rule, automatic Current Analysis recovery, raw CRLF, Undo, clipboard fallbacks, safe text, persistence and responsive layout. No JS/CSP errors or remote requests.');
  } finally {
    if (socket) socket.close();
    chrome.kill('SIGTERM');
    await new Promise(resolve => { if (chrome.exitCode !== null) resolve(); else { chrome.once('exit', resolve); setTimeout(resolve, 2000); } });
    await fs.rm(profile, {recursive: true, force: true, maxRetries: 8, retryDelay: 100});
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

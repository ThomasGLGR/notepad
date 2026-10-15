const assert = require('node:assert/strict');
module.exports = async function entityChecks({evaluate, command, click, fill, wait, ready}) {
  const report = () => evaluate('SOCNote.report.getText()');
  const saved = () => evaluate('SOCNote.storage.load().document.variables');
  const idFor = value => evaluate(`SOCNote.storage.load().document.variables.find(record=>record.value===${JSON.stringify(value)}).id`);
  const inRow = (id, selector) => `document.querySelector('[data-variable-id="${id}"] ${selector}')`;
  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const url = 'https://auth-office365-update.com/login';
  const urlLink = 'https://www.virustotal.com/gui/url/' + Buffer.from(url).toString('base64url');
  await click('#new-button');
  const data = [{'source.ip': '98.56.54.185', 'source.geo.country_iso_code': 'NL', 'host.ip': '10.0.0.5', 'url.full': url,
    'file.name': 'mail.txt', 'file.path': 'C:\\Users\\j.dupont\\Downloads\\mail.txt', 'file.hash.sha256': sha256}];
  assert.equal((await evaluate(`importJSON(${JSON.stringify(data)},{requestId:'entity-json'})`)).ok, true);
  await wait(250);
  // Country and file details join their entity instead of becoming separate pairs.
  assert.deepEqual((await saved()).map(record => record.key), ['source.ip', 'host.ip', 'url.full', 'file.name']);
  assert.equal(await report(), [
    '==================================================', '                     SUMMARY', '==================================================', '',
    'source.ip: 98.56.54.185 → VirusTotal',
    '└── Country     : NL 🇳🇱', '',
    'host.ip: 10.0.0.5', '',
    'url.full: ' + url + ' → VirusTotal', '',
    'file.name: mail.txt → VirusTotal',
    '├── Path        : C:\\Users\\j.dupont\\Downloads\\mail.txt',
    '└── Hash SHA256 : ' + sha256
  ].join('\n'));
  assert.equal(await evaluate('document.getElementById("final-report-input").textContent'), await report());
  const ipId = await idFor('98.56.54.185'), privateId = await idFor('10.0.0.5'), urlId = await idFor(url), fileId = await idFor('mail.txt');
  assert.equal(await evaluate('document.querySelectorAll("[data-entity-field], [data-entity-domain], .summary-entity").length'), 0, 'Summary has no predefined detail controls');
  assert.equal(await evaluate('Array.from(document.querySelectorAll(".entity-flag-controls")).every(node => node.hidden)'), true, 'Values that are not country codes have no flag');
  assert.equal(await evaluate('document.querySelectorAll(".summary-pair-child").length'), 0, 'Imported metadata does not create predefined subcategories');
  assert.equal(await evaluate(inRow(privateId, '[data-entity-vt]') + '.hidden'), true, 'Private addresses have no associated public report');
  const links = await evaluate('Array.from(document.querySelectorAll("a.entity-vt[href], #final-report-input a[href]"), node => ({href: node.href, text: node.textContent, target: node.target, rel: node.rel, report: !!node.closest("#final-report-input")}))');
  assert.equal(links.filter(link => !link.report).length, 3);
  assert.equal(links.filter(link => link.report).length, 3);
  assert(links.every(link => link.href.startsWith('https://www.virustotal.com/gui/') && link.target === '_blank' && link.rel === 'noopener noreferrer'));
  assert(links.filter(link => link.report).every(link => link.text === 'VirusTotal'));
  assert(links.filter(link => !link.report).every(link => link.text === ''));
  const serviceNow=await evaluate('Array.from(document.querySelectorAll("[data-service-now]"),link=>({host:new URL(link.href).hostname,value:new URL(link.href).searchParams.get("value"),target:link.target,rel:link.rel}))');
  assert.equal(serviceNow.length,4);
  assert.deepEqual(serviceNow.map(link=>link.value),['98.56.54.185','10.0.0.5',url,'mail.txt']);
  assert(serviceNow.every(link=>link.host==='changeme' && link.target==='_blank' && link.rel==='noopener noreferrer'));
  assert.equal(await evaluate(inRow(urlId, '[data-entity-vt]') + '.href'), urlLink);
  assert.equal(await evaluate('document.querySelectorAll(".summary-vt-arrow, [data-pair-action=detach]").length'), 0);
  assert((await evaluate('getComputedStyle(document.querySelector("[data-entity-vt]")).backgroundImage')).includes('virus-total.png'));
  assert.equal(await evaluate(inRow(ipId, '[data-entity-vt]') + '.closest(".summary-pair-actions") !== null'), true, 'Editor uses the PNG action link');
  const eye='[data-entity-vt-visibility="'+ipId+'"]';
  assert.equal(await evaluate(`document.querySelector('${eye}').getAttribute('aria-pressed')`),'true');
  assert.equal(await evaluate(`(() => {const eye=document.querySelector('${eye}').getBoundingClientRect(),logo=document.querySelector('[data-variable-id="${ipId}"] [data-entity-vt]').getBoundingClientRect();return eye.top>=logo.bottom && Math.abs((eye.left+eye.width/2)-(logo.left+logo.width/2))<1;})()`),true,'Eye sits under the VirusTotal logo');
  const withLinks=await report();
  await click(eye);
  assert.equal(await evaluate(`document.querySelector('${eye}').getAttribute('aria-pressed')`),'false');
  assert((await report()).includes('source.ip: 98.56.54.185\n└── Country'));
  assert.equal(await evaluate('document.querySelectorAll("#final-report-input a").length'),2,'Hiding one category leaves the other links');
  assert.equal(await evaluate(inRow(ipId,'[data-entity-vt]')+'.hidden'),false);
  assert.equal(await evaluate(inRow(ipId,'[data-entity-vt]')+'.href'),'https://www.virustotal.com/gui/ip-address/98.56.54.185');
  await click('#copy-report-button');await wait(60);
  assert.equal(await evaluate('navigator.clipboard.readText()'),await report());
  assert(!(await evaluate('SOCNote.report.getHTML()')).includes('https://www.virustotal.com/gui/ip-address/98.56.54.185'),'Hidden links are omitted from rich copies');
  await click('#undo-button');
  assert.equal(await report(),withLinks);
  await click(eye);
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  const withoutLink=await report();
  await command('Page.reload');await ready();
  assert.equal(await report(),withoutLink);
  assert.equal(await evaluate(`document.querySelector('${eye}').getAttribute('aria-pressed')`),'false');
  await click(eye);
  assert.equal(await report(),withLinks);
  // Existing metadata remains in reports and saved drafts, while the new editor
  // only exposes manual hierarchy controls and the URL presentation option.
  assert.equal((await saved()).find(record => record.id === ipId).country, 'NL');
  assert.equal((await saved()).find(record => record.id === fileId).fileHash, sha256);
  await click(`[data-defang-url="${urlId}"]`);
  assert((await report()).includes('url.full: hxxps://auth-office365-update[.]com/login'));
  assert.equal(await evaluate(inRow(urlId, '[data-entity-vt]') + '.href'), urlLink);
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  const before = await report();
  await command('Page.reload'); await ready();
  assert.equal(await report(), before);
  assert.equal((await evaluate(`importJSON(${JSON.stringify(data)},{requestId:'entity-json'})`)).count, 0);
  assert.equal(await report(), before);
  assert.equal(await evaluate('document.querySelectorAll("[data-entity-field]").length'), 0);

  // A file dropped on the page is listed and hashed inside the browser.
  await evaluate(`(() => { const transfer = new DataTransfer(); transfer.items.add(new File(['abc'], 'sample.bin'));
    document.querySelector('.analysis-pane').dispatchEvent(new DragEvent('drop', {dataTransfer: transfer, bubbles: true, cancelable: true})); })()`);
  await wait(60);
  const digest = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  for (let attempt = 0; attempt < 60 && !(await report()).includes(digest); attempt++) await wait(30);
  assert((await report()).endsWith('File: sample.bin → VirusTotal\n└── Hash SHA256 : ' + digest));
  // Dropped text and dropped JSON use the existing capture and JSON imports.
  const drop = text => evaluate(`(() => { const transfer = new DataTransfer(); transfer.setData('text/plain', ${JSON.stringify(text)});
    document.querySelector('.analysis-pane h2').dispatchEvent(new DragEvent('drop', {dataTransfer: transfer, bubbles: true, cancelable: true})); })()`);
  await drop('185.220.101.1');
  assert((await report()).endsWith('IP: 185.220.101.1 → VirusTotal'));
  await drop(JSON.stringify({'client.ip': '203.0.113.9', 'client.geo.country_name': 'Germany'}));
  assert((await report()).endsWith('client.ip: 203.0.113.9 → VirusTotal\n└── Country     : DE 🇩🇪'));
  assert.equal(await evaluate('document.querySelectorAll("img:not(.app-logo)").length'), 0);
  // A country code value shows its flag; the eye under it keeps or drops the flag in the report.
  await click('#new-button');
  assert.equal((await evaluate('importJSON({"geo.country":"FR","direction":"IN?"},{requestId:"flag-json"})')).ok, true);
  await wait(250);
  const countryId = await idFor('FR'), flagEye = '[data-entity-flag-visibility="' + countryId + '"]';
  assert.equal(await evaluate(inRow(countryId, '.entity-flag-controls') + '.hidden'), false);
  assert.equal(await evaluate(inRow(countryId, '[data-entity-flag]') + '.textContent'), '🇫🇷');
  assert.equal(await evaluate(inRow(countryId, '[data-entity-flag]') + '.getAttribute("aria-label")'), 'France flag');
  assert.equal(await evaluate(inRow(await idFor('IN?'), '.entity-flag-controls') + '.hidden'), true);
  assert.equal(await evaluate(`(() => {const eye=document.querySelector('${flagEye}').getBoundingClientRect(),flag=document.querySelector('[data-variable-id="${countryId}"] [data-entity-flag]').getBoundingClientRect();return eye.top>=flag.bottom && Math.abs((eye.left+eye.width/2)-(flag.left+flag.width/2))<1;})()`), true, 'Eye sits under the flag');
  assert((await report()).includes('geo.country: FR 🇫🇷'));
  await click(flagEye);
  assert.equal(await evaluate(`document.querySelector('${flagEye}').getAttribute('aria-pressed')`), 'false');
  assert((await report()).includes('geo.country: FR\n'));
  assert.equal(await evaluate(inRow(countryId, '[data-entity-flag]') + '.textContent'), '🇫🇷', 'The editor keeps the flag');
  await click('#copy-report-button'); await wait(60);
  assert.equal(await evaluate('navigator.clipboard.readText()'), await report());
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await command('Page.reload'); await ready();
  assert.equal(await evaluate(`document.querySelector('${flagEye}').getAttribute('aria-pressed')`), 'false');
  await click('#undo-button');
  await click(flagEye);
  assert((await report()).includes('geo.country: FR 🇫🇷'));
  await click('#new-button');
  console.log('Entity checks passed: country flags with report visibility eye, PNG VirusTotal controls in the editor, inline arrow and named report links, removed predefined controls and detach buttons, retained metadata, defanged URLs, local hashing, dropped text/JSON and draft recovery.');
};

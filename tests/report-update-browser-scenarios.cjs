const assert = require('node:assert/strict');
module.exports = async function reportUpdateChecks({evaluate, command, click, fill, wait, ready, keypress}) {
  const report = () => evaluate('SOCNote.report.getText()');
  const saved = () => evaluate('SOCNote.storage.load().document');
  const chips = () => evaluate('Array.from(document.querySelectorAll("#mitre-selected [data-technique]"), node => node.dataset.technique + "|" + node.querySelector(".mitre-chip-name").textContent)');
  const options = () => evaluate('document.getElementById("mitre-options").hidden ? null : Array.from(document.querySelectorAll("#mitre-options [role=option]"), node => node.textContent)');
  const type = async text => { await evaluate('document.getElementById("mitre-input").focus()'); await fill('#mitre-input', text); };
  const enter = () => keypress('Enter', 'Enter', 0, 13);
  await click('#new-button');
  await evaluate('window.nativeClipboard = navigator.clipboard');

  // MITRE ATT&CK selector beside the Rule: search by name or ID, several at once, custom IDs.
  assert.equal(await evaluate('document.querySelector("label[for=mitre-input]").textContent'), 'MITRE ATT&CK');
  assert.equal(await evaluate('document.querySelector(".rule-bar").contains(document.getElementById("mitre-input"))'), true);
  await type('powersh');
  assert.deepEqual(await options(), ['T1059.001 Command and Scripting Interpreter: PowerShell', 'T1546.013 Event Triggered Execution: PowerShell Profile']);
  assert.equal(await evaluate('document.getElementById("mitre-input").getAttribute("aria-expanded")'), 'true');
  await keypress('ArrowDown', 'ArrowDown', 0, 40);
  assert.equal(await evaluate('document.querySelector("#mitre-options [aria-selected=true]").id === document.getElementById("mitre-input").getAttribute("aria-activedescendant")'), true);
  await enter();
  assert.deepEqual(await chips(), ['T1059.001|Command and Scripting Interpreter: PowerShell']);
  assert.equal(await evaluate('document.getElementById("mitre-input").value'), '');
  assert.equal(await options(), null);
  await type('t1078, T1053.005');
  await enter();
  await type('valid accounts');
  assert(!(await options()).some(option => option.startsWith('T1078 ')), 'A selected technique is not offered again');
  await evaluate('document.querySelector("#mitre-options [role=option]").click()');
  await type('T9999 - Internal technique');
  await enter();
  assert.deepEqual((await chips()).map(chip => chip.split('|')[0]), ['T1059.001', 'T1078', 'T1053.005', 'T1078.001', 'T9999']);
  await type('not a technique');
  await enter();
  assert.equal((await chips()).length, 5);
  assert((await evaluate('document.getElementById("toast").textContent')).includes('T1059'));
  await fill('#mitre-input', '');
  // Removal: the chip button, or Backspace in the empty field. Undo brings a technique back.
  await click('[data-remove-technique="T1078.001"]');
  await keypress('Backspace', 'Backspace', 0, 8);
  assert.deepEqual((await chips()).map(chip => chip.split('|')[0]), ['T1059.001', 'T1078', 'T1053.005']);
  await click('#undo-button');
  assert.equal((await chips()).at(-1), 'T9999|Internal technique');
  await click('[data-remove-technique="T9999"]');
  // Tactics panel: the base tactics, one click to select or clear, listed before techniques.
  const pressed = () => evaluate('Array.from(document.querySelectorAll("#mitre-tactics [aria-pressed=true]"), node => node.dataset.tactic)');
  assert.equal(await evaluate('document.getElementById("mitre-tactics").hidden'), true);
  await click('#mitre-tactics-button');
  assert.equal(await evaluate('document.getElementById("mitre-tactics").hidden'), false);
  assert.equal(await evaluate('document.getElementById("mitre-tactics-button").getAttribute("aria-expanded")'), 'true');
  assert.equal(await evaluate('document.querySelectorAll("#mitre-tactics [data-tactic]").length'), 15);
  assert.equal(await evaluate('document.querySelector("#mitre-tactics [data-tactic=TA0006]").textContent'), 'TA0006 Credential Access');
  await click('#mitre-tactics [data-tactic=TA0006]');
  await click('#mitre-tactics [data-tactic=TA0002]');
  assert.deepEqual(await pressed(), ['TA0002', 'TA0006']);
  assert.deepEqual((await chips()).slice(0, 2), ['TA0006|Credential Access', 'TA0002|Execution']);
  await click('#mitre-tactics [data-tactic=TA0006]');
  assert.deepEqual(await pressed(), ['TA0002']);
  assert.equal(await evaluate('document.getElementById("mitre-tactics").hidden'), false, 'The panel stays open for several choices');
  await keypress('Escape', 'Escape', 0, 27);
  assert.equal(await evaluate('document.getElementById("mitre-tactics").hidden'), true);
  await fill('#rule-input', 'Suspicious scheduled task');
  assert.equal(await report(), 'Suspicious scheduled task\n\n==================================================\n                     SUMMARY\n==================================================\n\nMITRE ATT&CK: Execution (TA0002), Command and Scripting Interpreter: PowerShell (T1059.001), Valid Accounts (T1078), Scheduled Task/Job: Scheduled Task (T1053.005)');

  // Logs are cleaned when submitted; Summary points are one blank line apart in the report only.
  await fill('#raw-input', '\n\n  🚨 EDR Action: Not mitigated ✅\nuser: alice 🙂\ncommand_line: cmd.exe  /c   "whoami  /all"\n\n  \n');
  await click('#process-source-button');
  assert.equal(await evaluate('(() => {window.dispatchEvent(new Event("pagehide"));return SOCNote.storage.load().document.capturedRaw;})()'), 'EDR Action: Not mitigated\nuser: alice\ncommand_line: cmd.exe  /c   "whoami  /all"');
  assert.equal(await evaluate('SOCNote.summary.getText()'), 'EDR Action : Unmitigated\nuser : alice\ncommand_line : cmd.exe  /c   "whoami  /all"');
  assert.equal(await evaluate('document.querySelector("[data-variable-value]").value'), 'Unmitigated');
  assert((await report()).endsWith('Scheduled Task/Job: Scheduled Task (T1053.005)\n\nEDR Action: Unmitigated\n\nuser: alice\n\ncommand_line: cmd.exe  /c   "whoami  /all"'));
  assert.equal((await evaluate('SOCNote.summary.getValues()')).split('\n').length, 3, 'No blank lines are added to the editor or to value copies');
  // A paste into Logs arrives cleaned, in the field and in the stored text.
  await evaluate('nativeClipboard.writeText("\\n\\n  ⚠️ host: PC-0042 ✅  \\n\\n").then(() => document.getElementById("raw-input").focus())');
  await keypress('v', 'KeyV', 2, 86);
  await wait(80);
  assert.equal(await evaluate('document.getElementById("raw-input").value'), 'host: PC-0042');
  await click('#process-source-button');

  // "Unknown" is red in the report, on that word only, until it is replaced.
  const drop = text => evaluate(`(() => { const transfer = new DataTransfer(); transfer.setData('text/plain', ${JSON.stringify(text)});
    document.querySelector('.analysis-pane h2').dispatchEvent(new DragEvent('drop', {dataTransfer: transfer, bubbles: true, cancelable: true})); })()`);
  await drop('some unclassified text 🙂');
  const unknown = () => evaluate('Array.from(document.querySelectorAll("#final-report-input .report-unknown"), node => ({text: node.textContent, color: getComputedStyle(node).color, row: node.closest(".report-field").textContent}))');
  assert.deepEqual(await unknown(), [{text: 'Unknown', color: 'rgb(192, 57, 43)', row: 'Unknown: some unclassified text'}]);
  assert.notEqual(await evaluate('getComputedStyle(document.querySelector("#final-report-input .report-field strong")).color'), 'rgb(192, 57, 43)');
  const unknownId = await evaluate('Array.from(document.querySelectorAll("[data-variable-value]")).find(node => node.value === "some unclassified text").dataset.variableValue');
  await click('#add-variable-button');
  await fill('#summary-new-key', 'Verdict');
  await fill('#summary-new-value', 'Unknown');
  await evaluate('document.getElementById("summary-add-variable-form").requestSubmit()');
  assert.deepEqual((await unknown()).map(item => item.row), ['Unknown: some unclassified text', 'Verdict: Unknown']);
  await click('#copy-report-button');
  await wait(60);
  const html = () => evaluate('(async()=>{const items=await nativeClipboard.read();for(const item of items)if(item.types.includes("text/html"))return await(await item.getType("text/html")).text();return null;})()');
  assert.equal(await evaluate('nativeClipboard.readText()'), await report());
  assert((await html()).includes('<strong><font color="#c0392b">Unknown</font></strong>: some unclassified text'));
  await fill(`[data-variable-key="${unknownId}"]`, 'Comment');
  await click('#copy-summary-button');
  assert.deepEqual((await unknown()).map(item => item.row), ['Verdict: Unknown']);

  // Report links: VirusTotal analyses and the event's own console link open in a new tab.
  // Suspicious URLs stay text. VirusTotal is a named link on the indicator's own line.
  const suspicious = 'https://auth-office365-update.com/login', console_ = 'https://siem.example.invalid/app/alerts/45821';
  assert.equal((await evaluate(`importJSON(${JSON.stringify({'url.full': suspicious + ' 🎣', 'event.url': console_, 'source.ip': '98.56.54.185'})},{requestId:'report-links'})`)).ok, true);
  const vtUrl = 'https://www.virustotal.com/gui/url/' + Buffer.from(suspicious).toString('base64url');
  const reportLinks = selector => evaluate(`Array.from(document.querySelectorAll(${JSON.stringify(selector)}), node => ({href: node.getAttribute("href"), text: node.textContent, target: node.target, rel: node.rel}))`);
  const mitreLinks = await reportLinks('#final-report-input .report-mitre a');
  assert.deepEqual(mitreLinks.map(link => link.text + ' ' + link.href), ['TA0002 https://attack.mitre.org/tactics/TA0002/', 'T1059.001 https://attack.mitre.org/techniques/T1059/001/', 'T1078 https://attack.mitre.org/techniques/T1078/', 'T1053.005 https://attack.mitre.org/techniques/T1053/005/']);
  assert(mitreLinks.every(link => link.target === '_blank' && link.rel === 'noopener noreferrer'));
  const links = await reportLinks('#final-report-input .report-field:not(.report-mitre) a');
  assert.deepEqual(links.map(link => link.href), [vtUrl, console_, 'https://www.virustotal.com/gui/ip-address/98.56.54.185']);
  assert.deepEqual(links.map(link => link.text), ['VirusTotal',console_,'VirusTotal']);
  assert(links.every(link => link.target === '_blank' && link.rel === 'noopener noreferrer'));
  assert((await report()).includes('url.full: ' + suspicious + ' → VirusTotal\n\nevent.url: ' + console_ + '\n\nsource.ip: 98.56.54.185 → VirusTotal'));
  assert(!(await report()).includes('Domain      :'));
  assert.equal(await evaluate('document.getElementById("final-report-input").textContent'), await report());
  await click('#copy-report-button');
  await wait(60);
  assert.equal(await evaluate('nativeClipboard.readText()'), await report());
  const rich = await html();
  assert(rich.includes('→ <a href="' + vtUrl + '">VirusTotal</a>') && rich.includes('<a href="' + console_ + '">' + console_ + '</a>'));
  assert(!rich.includes('href="' + suspicious), 'The suspicious URL is not a link in the rich copy either');
  const consoleId = (await saved()).variables.find(record => record.value === console_).id;
  await click(`[data-defang-url="${consoleId}"]`);
  assert.equal(await evaluate('document.querySelectorAll("#final-report-input .report-field:not(.report-mitre) a").length'), 2, 'A defanged reference is text');
  await click(`[data-defang-url="${consoleId}"]`);

  // Everything survives a reload; New clears the techniques with the rest.
  await wait(250);
  const before = await report();
  await command('Page.reload'); await ready();
  assert.equal(await report(), before);
  assert.equal((await chips()).length, 4);
  assert.equal((await saved()).mitreTechniques.length, 4);
  // Buttons sit in their card heading, and the withdrawn file picker is gone.
  assert.equal(await evaluate('document.querySelector(".source-pane .pane-heading").contains(document.getElementById("process-source-button")) && document.querySelector(".synthesis-pane .pane-heading").contains(document.getElementById("add-variable-button"))'), true);

  // A draft saved before these changes keeps its data: the wording shown is updated, the
  // remediation choices stay stored, and their tactic rows leave Summary with the section.
  await evaluate(`(() => { const draft = SOCNote.templates.emptyDocument(); delete draft.mitreTechniques; draft.rule = 'Older draft';
    draft.variables = [{id: 'a', key: 'EDR Action', keys: ['EDR Action'], value: 'Not mitigated', origin: 'captured'}, {id: 'mitre:credential-access', key: 'MITRE', keys: ['MITRE'], value: 'Credential Access (TA0006)', origin: 'mitre', tacticId: 'credential-access'}];
    draft.remediation = {activeTactics: ['credential-access'], includeTactics: false, selected: [{id: 'credential-access-1', tacticId: 'credential-access', tacticName: 'Credential Access', template: 'Reset the password for the account {USER}.', generic: '', text: 'Reset this account today.'}]};
    localStorage.setItem('soc-note-builder.current-analysis.v1', JSON.stringify(draft));
    Storage.prototype.setItem = function () {}; })()`); // The closing page must not save over the older draft.
  await command('Page.reload'); await ready();
  assert.equal(await report(), 'Older draft\n\n==================================================\n                     SUMMARY\n==================================================\n\nEDR Action: Unmitigated');
  assert.equal(await evaluate('document.querySelectorAll("#report-input [data-variable-id]").length'), 1);
  assert.equal((await chips()).length, 0);
  await fill('#analysis-input', 'Checked.');
  await wait(300);
  const kept = await saved();
  assert.equal(kept.remediation.selected[0].text, 'Reset this account today.');
  assert.deepEqual(kept.remediation.activeTactics, ['credential-access']);
  assert.equal(kept.variables[0].value, 'Not mitigated', 'The stored value is not rewritten');
  await click('#new-button');
  assert.equal(await report(), '');
  assert.equal((await chips()).length, 0);
  console.log('Report update checks passed: MITRE selector and report block, cleaned imports, Unmitigated wording, red Unknown, spaced points, inline named VirusTotal links retained in rich copy, reference addresses and older drafts.');
};

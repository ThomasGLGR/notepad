const assert=require('node:assert/strict');
module.exports=async function remediationChecks({evaluate,command,click,fill,wait,ready,keypress}) {
  const choose=id=>click('[data-tactic-group] [data-choose="'+id+'"]');
  const mitre=()=>evaluate('Array.from(document.querySelectorAll("#report-input [data-variable-value][readonly]"),node=>node.value)');
  const selectedText=()=>evaluate('Array.from(document.querySelectorAll("[data-selected-text]")).map(node=>"- "+node.value).join("\\n")');
  const copy=async()=>{await click('#copy-remediations-button');await wait(50);return evaluate('nativeClipboard.readText()');};
  const reload=async()=>{await command('Page.reload');await ready();await evaluate('window.nativeClipboard=navigator.clipboard');};
  await click('#new-button');
  await evaluate('window.nativeClipboard=navigator.clipboard');
  assert.equal(await evaluate('document.querySelectorAll("#manage-remediations-button, #remediation-persist, #remediation-include-tactics, #remediation-category-tools").length'),0);
  await fill('#raw-input','USER: DOMAIN\\jdupont\nHOST: PC-0042\nIP: 185.42.21.8');
  await wait(300);
  assert.deepEqual(await mitre(),[],'Logs do not choose MITRE tactics');
  assert.equal(await evaluate('document.querySelectorAll("[data-selected-text]").length'),0);
  await evaluate('SOCNote.remediation.setActiveTactics(["credential-access","command-and-control","unknown","credential-access"])');
  assert.deepEqual(await mitre(),['Credential Access (TA0006)','Command and Control (TA0011)']);
  assert.equal(await evaluate('document.querySelectorAll("[data-tactic-group]").length'),2);
  for(const id of ['credential-access-1','credential-access-2','command-and-control-1','command-and-control-4']) await choose(id);
  const expected='- Reset the password for the account DOMAIN\\jdupont.\n- Revoke active sessions for the account DOMAIN\\jdupont.\n- Block the IP address 185[.]42[.]21[.]8.\n- Isolate the host PC-0042.';
  assert.equal(await copy(),expected);
  await click('#copy-report-button');await wait(50);
  const report=await evaluate('nativeClipboard.readText()');
  assert(report.includes('MITRE: Credential Access (TA0006)'));
  assert(report.includes('MITRE: Command and Control (TA0011)'));
  assert(report.endsWith('==================================================\n                   REMEDIATION\n==================================================\n\n'+expected));

  // Inline edits stay investigation-specific and missing fields use generic wording.
  await fill('[data-selected-text=credential-access-1]','Reset the verified account password within 30 minutes.');
  await fill('#raw-input','HOST: PC-0043');await wait(300);
  assert.equal(await evaluate('document.querySelector("[data-selected-text=credential-access-1]").value'),'Reset the verified account password within 30 minutes.');
  assert.equal(await evaluate('document.querySelector("[data-selected-text=credential-access-2]").value'),'Revoke active sessions for the account under investigation.');
  await click('[data-action=reset-selected][data-id=credential-access-1]');
  assert.equal(await evaluate('document.querySelector("[data-selected-text=credential-access-1]").value'),'Reset the password for the account under investigation.');
  await fill('[data-selected-text=credential-access-1]','Temporary action.');
  await click('#undo-button');
  assert.equal(await evaluate('document.querySelector("[data-selected-text=credential-access-1]").value'),'Reset the password for the account under investigation.');
  assert.equal(await evaluate('localStorage.getItem("soc-note-builder.remediation-catalog.v1")'),null);

  // Favorites and search remain quick; searching alone does not add MITRE context.
  await click('[data-action=favorite][data-id=command-and-control-5]');
  assert.equal(await evaluate('document.querySelector("#remediation-recommendations summary").textContent'),'Favorites (1)');
  await click('#remediation-recommendations > details:first-child [data-choose=command-and-control-5]');
  assert.equal(await evaluate('Array.from(document.querySelectorAll("[data-choose=command-and-control-5]")).every(node=>node.checked)'),true);
  await choose('command-and-control-5');
  await fill('#remediation-search','PASSWORD');
  assert.equal(await evaluate('document.querySelectorAll("[data-tactic-group]").length'),3);
  assert.equal((await mitre()).length,2);
  await click('[data-tactic-group=initial-access] [data-choose=initial-access-6]');
  assert((await mitre()).includes('Initial Access (TA0001)'));
  await click('[data-tactic-group=initial-access] [data-choose=initial-access-6]');
  assert(!(await mitre()).includes('Initial Access (TA0001)'));
  await fill('#remediation-search','');
  await click('[data-action=remove-tactic][data-id=credential-access]');
  assert((await mitre()).includes('Credential Access (TA0006)'),'Checked actions retain their tactic context');
  await click('[data-action=remove-selected][data-id=credential-access-1]');
  await click('[data-action=remove-selected][data-id=credential-access-2]');
  assert(!(await mitre()).includes('Credential Access (TA0006)'));
  await click('#remediation-search');
  assert.equal(await evaluate('document.activeElement.id'),'remediation-search');
  await click('#copy-remediations-button');await wait(50);
  assert.equal(await evaluate('nativeClipboard.readText()'),await selectedText());

  // Every configured tactic contributes an automatic Summary pair and supports selection.
  await click('#new-button');
  const ids=await evaluate('SOCNote.remediationData.defaults().map(tactic=>tactic.id)');
  for(const id of ids){
    await evaluate(`SOCNote.remediation.setActiveTactics([${JSON.stringify(id)}])`);
    assert.equal(await evaluate('document.querySelector("[data-tactic-group]").open'),true);
    await choose(id+'-1');
  }
  assert.equal(await evaluate('document.querySelectorAll("[data-selected-text]").length'),14);
  assert.equal((await mitre()).length,14);
  assert(!/undefined|null|\{[A-Z_]+\}/.test(await copy()));

  // Existing add/save-as-template flows remain inline without catalogue settings.
  await click('#new-button');
  await evaluate('SOCNote.remediation.setActiveTactics(["credential-access"])');
  await click('#add-remediation-button');
  await fill('#remediation-edit-template','Review access for the account {USER}.');
  await evaluate('document.getElementById("remediation-edit-form").requestSubmit()');
  const customId=await evaluate('Array.from(document.querySelectorAll("[data-tactic-group=credential-access] [data-choose]")).at(-1).dataset.choose');
  assert(customId.startsWith('custom-'));
  assert.equal(await evaluate('document.querySelectorAll("[data-selected-text]").length'),0);
  await choose(customId);
  await fill('[data-selected-text="'+customId+'"]','Review access within one hour.');
  await click('[data-action=save-selected][data-id="'+customId+'"]');
  await fill('#remediation-edit-template','Review access for the account {USER} today.');
  await evaluate('document.getElementById("remediation-edit-form").requestSubmit()');
  assert.equal(await evaluate(`document.querySelector('[data-selected-text="${customId}"]').value`),'Review access within one hour.');
  assert.equal(await evaluate('localStorage.getItem("soc-note-builder.remediation-catalog.v1")'),null);

  // Investigation saving restores tactic context without enabling catalogue saving.
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await reload();
  assert.deepEqual(await mitre(),['Credential Access (TA0006)']);
  assert.equal(await evaluate(`document.querySelector('[data-selected-text="${customId}"]').value`),'Review access within one hour.');
  assert.equal(await evaluate('localStorage.getItem("soc-note-builder.remediation-catalog.v1")'),null);

  // Clipboard fallbacks remain available for the selected-action list.
  await evaluate('Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:()=>Promise.reject(Error("Forced refusal"))}})');
  assert.equal(await copy(),await selectedText());
  await evaluate('window.savedExec=document.execCommand;document.execCommand=()=>false');
  await click('#copy-remediations-button');await wait(30);
  assert.equal(await evaluate('document.getElementById("copy-dialog").open'),true);
  assert.equal(await evaluate('document.getElementById("manual-copy-input").value'),await selectedText());
  await keypress('Escape','Escape',0,27);
  await evaluate('document.execCommand=savedExec;delete navigator.clipboard');
  await click('#new-button');
  assert.deepEqual(await mitre(),[]);
  assert.equal(await evaluate('document.getElementById("copy-remediations-button").disabled'),true);
  console.log('Remediation checks passed: removed settings, automatic MITRE Summary context from tactics/actions, all 14 tactics, search, favorites, inline edits, templates, explicit investigation persistence and clipboard fallbacks.');
};

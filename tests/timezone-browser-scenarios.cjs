const assert = require('node:assert/strict');
module.exports = async function timeZoneChecks({evaluate,command,click,fill,wait,ready,keypress}) {
  await click('#new-button');
  await evaluate('window.nativeClipboard=navigator.clipboard');
  await fill('#raw-input','timestamp: 2026-10-14T23:12:00Z\nDate: 14/10/2026\nunix_timestamp: 1791885600\nIP: 192.0.2.1\nInvalid date: 2026-02-29\nEvent: network');
  await click('#process-source-button');
  const idFor = value => evaluate(`Array.from(document.querySelectorAll('#report-input .summary-pair')).find(node=>node.querySelector('[data-variable-value]').value===${JSON.stringify(value)}).dataset.variableId`);
  const id = await idFor('2026-10-14T23:12:00Z');
  const zone = '[data-time-zone="'+id+'"]';
  const value = '[data-variable-value="'+id+'"]';
  const report = () => evaluate('SOCNote.report.getText()');
  async function selectZone(id,timeZone) {
    await evaluate(`(() => {const select=document.querySelector('[data-time-zone="${id}"]');select.focus();select.value=${JSON.stringify(timeZone)};select.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  }
  assert.equal(await evaluate('Array.from(document.querySelectorAll(".summary-timezone-controls")).filter(node=>!node.hidden).length'),3);
  assert.equal(await evaluate(`document.querySelector('${zone}').value`),'UTC');
  assert.equal(await evaluate('document.querySelectorAll("[data-time-zone-visibility], [data-pair-action=timezone-visibility], .summary-timezone-controls svg").length'),0,'The time zone eye has been removed');
  assert((await report()).includes('timestamp: 2026-10-14T23:12:00Z (UTC)'));
  assert((await report()).includes('Date: 14/10/2026 (UTC)'));
  assert((await report()).includes('unix_timestamp: 1791885600 (UTC)'));
  assert.equal(await evaluate('document.getElementById("final-report-input").textContent'),await report());
  assert.equal(await evaluate(`document.querySelector('${zone}').options[0].value`),'');

  // Native keyboard selection reaches the blank option immediately above UTC.
  await evaluate(`document.querySelector('${zone}').focus()`);
  await keypress('ArrowUp','ArrowUp',0,38);
  await keypress('Tab','Tab',0,9);
  assert.equal(await evaluate(`document.querySelector('${zone}').value`),'');
  assert(!(await report()).includes('timestamp: 2026-10-14T23:12:00Z ('));
  await click('#undo-button');
  assert.equal(await evaluate(`document.querySelector('${zone}').value`),'UTC');
  await selectZone(id,'UTC+2');
  assert((await report()).includes('timestamp: 2026-10-14T23:12:00Z (UTC+2)'));
  await click('[data-copy-variable="'+id+'"]');await wait(40);
  assert.equal(await evaluate('nativeClipboard.readText()'),'2026-10-14T23:12:00Z');
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await command('Page.reload');await ready();
  await evaluate('window.nativeClipboard=navigator.clipboard');
  assert.equal(await evaluate(`document.querySelector('${zone}').value`),'UTC+2');
  assert((await report()).includes('timestamp: 2026-10-14T23:12:00Z (UTC+2)'));
  await click('#copy-report-button');await wait(60);
  assert.equal(await evaluate('nativeClipboard.readText()'),await report());
  assert((await evaluate('SOCNote.report.getHTML()')).replace(/&nbsp;|\u00a0/g,' ').includes('2026-10-14T23:12:00Z (UTC+2)'));

  const localId = await idFor('14/10/2026');
  await selectZone(localId,'');
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await command('Page.reload');await ready();
  assert.equal(await evaluate(`document.querySelector('[data-time-zone="${localId}"]').value`),'','The blank option survives reload');
  assert(!(await report()).includes('Date: 14/10/2026 ('));
  await fill(value,'not a date');
  assert.equal(await evaluate(`document.querySelector('${zone}').parentNode.hidden`),true);
  assert((await report()).includes('timestamp: not a date'));
  assert(!(await report()).includes('timestamp: not a date ('));
  await fill(value,'2026-10-14T23:12:00Z');
  assert.equal(await evaluate(`document.querySelector('${zone}').parentNode.hidden`),false);
  assert.equal(await evaluate(`document.querySelector('${zone}').value`),'UTC+2');

  // Children receive independent date controls and report annotations.
  const parentId = await idFor('network');
  await click('[data-pair-action=add-child][data-id="'+parentId+'"]');
  await fill('#summary-new-key','Observed');
  await fill('#summary-new-value','2026-10-15');
  await evaluate('document.getElementById("summary-add-variable-form").requestSubmit()');
  const childId = await idFor('2026-10-15');
  await selectZone(childId,'UTC+5:45');
  assert((await report()).includes('Event: network\n└── Observed: 2026-10-15 (UTC+5:45)'));
  await selectZone(childId,'');
  assert((await report()).includes('Event: network\n└── Observed: 2026-10-15'));
  assert(!(await report()).includes('2026-10-15 ('));
  await click('#undo-button');
  assert((await report()).includes('2026-10-15 (UTC+5:45)'));

  // Older drafts with the removed eye set to hidden expose the blank option.
  const legacy = await evaluate('(() => {window.dispatchEvent(new Event("pagehide"));return SOCNote.storage.load().document;})()');
  legacy.variables.find(record=>record.id===id).hideTimeZone=true;
  const {identifier} = await command('Page.addScriptToEvaluateOnNewDocument',{source:`localStorage.setItem('soc-note-builder.current-analysis.v1',${JSON.stringify(JSON.stringify(legacy))});`});
  await command('Page.reload');await ready();
  await command('Page.removeScriptToEvaluateOnNewDocument',{identifier});
  assert.equal(await evaluate(`document.querySelector('${zone}').value`),'');
  assert(!(await report()).includes('timestamp: 2026-10-14T23:12:00Z ('));
  await selectZone(id,'UTC+2');
  assert((await report()).includes('timestamp: 2026-10-14T23:12:00Z (UTC+2)'),'Selecting a zone restores an annotation hidden in an older draft');

  for (const width of [1440,768,375]) {
    await command('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false});
    await wait(40);
    const layout = await evaluate(`(() => {
      const row=document.querySelector('[data-variable-id="${id}"]');
      const card=row.getBoundingClientRect(),select=row.querySelector('[data-time-zone]').getBoundingClientRect(),value=row.querySelector('[data-variable-value]').getBoundingClientRect(),key=row.querySelector('[data-variable-key]').getBoundingClientRect();
      return {fits:row.scrollWidth<=row.clientWidth && select.right<=card.right,space:value.width>key.width*2};
    })()`);
    assert.equal(layout.fits,true,'Date controls fit the card at '+width);
    assert.equal(layout.space,true,'Most of the key/value space remains dedicated to the value at '+width);
  }
  await command('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await click('#new-button');
  console.log('Time zone checks passed: date/timestamp detection, UTC default and blank selection, native keyboard selection, matching report preview and copies, removed time zone eye, legacy hidden annotations, original value copying, reload, inline edits, subcategories, Undo and responsive layout.');
};

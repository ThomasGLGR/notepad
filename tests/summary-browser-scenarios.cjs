const assert = require('node:assert/strict');
module.exports = async function summaryChecks({ evaluate, command, click, fill, wait, ready, keypress }) {
  const text = () => evaluate('SOCNote.summary.getText()');
  const values = () => evaluate('SOCNote.summary.getValues()');
  const count = () => evaluate('document.querySelectorAll("#report-input [data-variable-id]").length');
  await click('#new-button');
  await evaluate('window.nativeClipboard = navigator.clipboard');
  assert.equal(await evaluate('document.getElementById("report-input").isContentEditable'), false);
  assert.equal(await evaluate('document.querySelectorAll("#template-tab, #template-input, #variables-details, #variables-list").length'), 0);
  await fill('#raw-input', 'destination_ip: 192.0.2.1\ndestination_ip: 192.0.2.2\ndestination_ip: 192.0.2.1\nsource_ip: 192.0.2.1\nuser: alice');
  await click('#process-source-button');
  assert.equal(await count(), 3);
  assert.equal(await text(), 'destination_ip / source_ip : 192.0.2.1\ndestination_ip : 192.0.2.2\nuser : alice');
  assert.equal(await values(), '192.0.2.1\n192.0.2.2\nalice');
  const ids = await evaluate('Array.from(document.querySelectorAll("#report-input [data-variable-id]"), node => node.dataset.variableId)');
  await click('[data-copy-variable="' + ids[0] + '"]');
  await wait(40);
  assert.equal(await evaluate('nativeClipboard.readText()'), '192.0.2.1');
  await click('#copy-summary-button');
  await wait(40);
  assert.equal(await evaluate('nativeClipboard.readText()'), await values());
  assert(!(await evaluate('nativeClipboard.readText()')).includes('destination_ip'));

  async function wheelInSummary(deltaY) {
    const point=await evaluate('(() => {const rect=document.getElementById("report-input").getBoundingClientRect();return {x:rect.left+rect.width*.6,y:rect.top+rect.height/2};})()');
    await command('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await command('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY});
    await wait(200);
  }
  async function showSummary(width) {
    await command('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false});
    await evaluate('document.activeElement.blur();document.querySelector(".synthesis-pane").scrollIntoView({block:"start"});document.getElementById("report-input").scrollTop=0');
  }
  // A short list must allow scrolling the surrounding page from inside Summary.
  for(const width of [1440,768,375,320]) {
    await showSummary(width);
    await evaluate('window.scrollTo(0,0)');
    assert.equal(await evaluate('document.getElementById("report-input").scrollHeight-document.getElementById("report-input").clientHeight'),0);
    const page=await evaluate('scrollY');
    await wheelInSummary(150);
    assert(await evaluate('scrollY')>page,'Wheel in a short Summary scrolls the page at '+width);
  }
  await showSummary(1440);

  // Native keyboard editing is on the row fields; pair identity is distinct from the key.
  await evaluate(`(() => { const input = document.querySelector('[data-variable-value="${ids[2]}"]'); input.focus(); input.setSelectionRange(0,input.value.length); })()`);
  await command('Input.insertText', {text:'DOMAIN\\jdupont'});
  assert((await text()).includes('user : DOMAIN\\jdupont'));
  // The withdrawn Remediation section still resolves its templates, without adding tactic rows to Summary.
  await evaluate('SOCNote.remediation.setActiveTactics(["credential-access", "exfiltration"])');
  await click('[data-tactic-group=credential-access] [data-choose=credential-access-1]');
  await click('[data-tactic-group=exfiltration] [data-choose=exfiltration-1]');
  assert.equal(await evaluate('document.querySelector("[data-selected-text=credential-access-1]").value'), 'Reset the password for the account DOMAIN\\jdupont.');
  assert.equal(await evaluate('document.querySelector("[data-selected-text=exfiltration-1]").value'), 'Block the destination 192[.]0[.]2[.]1 / 192[.]0[.]2[.]2.');

  async function dragBeforeFirst(id, ctrl = false) {
    const drag = await evaluate(`(() => { document.querySelector('.synthesis-pane').scrollIntoView({block:'start'}); const token = document.querySelector('[data-variable-id="${id}"]'); const dt = new DataTransfer(); token.dispatchEvent(new DragEvent('dragstart', {bubbles:true, dataTransfer:dt})); const target = document.querySelector('#report-input [data-variable-id]').getBoundingClientRect(); return {id:${JSON.stringify(id)}, value:dt.getData('text/plain'), x:target.left+12, y:target.top+3}; })()`);
    const data = {items:[{mimeType:'application/x-soc-pair',data:drag.id},{mimeType:'text/plain',data:drag.value}],dragOperationsMask:17};
    for (const type of ['dragEnter','dragOver','drop']) await command('Input.dispatchDragEvent',{type,x:drag.x,y:drag.y,data,modifiers:ctrl?2:0});
  }
  await dragBeforeFirst(ids[1]);
  assert.equal(await count(), 3);
  assert((await text()).startsWith('destination_ip : 192.0.2.2\n'));
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${ids[1]}"] [data-variable-key]').value`), 'destination_ip');
  await dragBeforeFirst(ids[2], true);
  assert.equal(await count(), 3, 'Ctrl+drag cannot duplicate unique values');
  assert((await text()).startsWith('user : DOMAIN\\jdupont\n'));
  await evaluate(`document.querySelector('[data-variable-id="${ids[2]}"]').focus()`);
  const orderBeforeKey=await text();
  await keypress('ArrowDown','ArrowDown',1,40);
  assert.equal(await text(),orderBeforeKey,'Removed Alt+Arrow shortcut does not reorder');
  await click('[data-copy-variable="'+ids[2]+'"]');
  await wait(40);
  assert.equal(await evaluate('nativeClipboard.readText()'), 'DOMAIN\\jdupont');
  assert.equal(await evaluate('document.querySelectorAll("[data-pair-action=up], [data-pair-action=down]").length'),0);
  await dragBeforeFirst(ids[1]);
  assert(!(await text()).startsWith('user :'));
  await click('#undo-button');
  assert((await text()).startsWith('user :'));

  // Adding another value under the same key retains independent rows; duplicates merge keys.
  await click('#add-variable-button');
  await fill('#summary-new-key','destination_ip');
  await fill('#summary-new-value','192.0.2.3');
  await evaluate('document.getElementById("summary-add-variable-form").requestSubmit()');
  assert.equal(await count(),4);
  await click('#add-variable-button');
  await fill('#summary-new-key','dst_ip');
  await fill('#summary-new-value','192.0.2.3');
  await evaluate('document.getElementById("summary-add-variable-form").requestSubmit()');
  assert.equal(await count(),4);
  assert((await text()).includes('destination_ip / dst_ip : 192.0.2.3'));
  const newId = await evaluate('Array.from(document.querySelectorAll("#report-input [data-variable-id]")).find(node=>node.querySelector("[data-variable-value]").value==="192.0.2.3").dataset.variableId');
  await fill('[data-variable-key="'+newId+'"]','destination_ip / network');
  await click('#copy-summary-button');
  assert((await text()).includes('destination_ip / network : 192.0.2.3'));
  await fill('[data-variable-value="'+newId+'"]','192.0.2.2');
  assert.equal(await count(),3);
  assert((await text()).includes('destination_ip / network : 192.0.2.2'));
  await click('#undo-button');
  assert.equal(await count(),4);
  await click('[data-pair-action=remove][data-id="'+newId+'"]');
  assert.equal(await count(),3);
  await click('#undo-button');
  assert.equal(await count(),4);

  // Empty values cannot be committed; HTML is inert even when edited on a pair.
  await fill('[data-variable-value="'+newId+'"]','');
  await click('#copy-summary-button');
  assert((await values()).includes('192.0.2.3'));
  const attack = '<img src="https://example.invalid/exfil" onerror="window.compromised=1">';
  await fill('[data-variable-value="'+newId+'"]',attack);
  assert.equal(await evaluate(`new URL(document.querySelector('[data-service-now="${newId}"]').href).searchParams.get('value')`),attack,'ServiceNow safely encodes special characters in the value');
  await click('[data-copy-variable="'+newId+'"]');
  await wait(40);
  assert.equal(await evaluate('nativeClipboard.readText()'),attack);
  assert.equal(await evaluate('document.querySelectorAll("img:not(.app-logo)").length'),0);
  assert.equal(await evaluate('window.compromised || null'),null);
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  const before = await text();
  await command('Page.reload');
  await ready();
  await evaluate('window.nativeClipboard = navigator.clipboard');
  assert.equal(await text(),before);
  assert.equal(await count(),4);
  assert.equal(await evaluate('SOCNote.storage.load().document.schemaVersion'),4);
  await click('#new-button');

  // Key fields are plain text fields: no suggestion list opens on them.
  assert.equal(await evaluate('document.querySelectorAll("datalist").length'),0);
  assert.equal(await evaluate('document.getElementById("summary-new-key").list'),null);
  await fill('#raw-input','First: A\nSecond: B\nThird: C\nFourth: D');
  await click('#process-source-button');
  assert.equal(await evaluate('document.querySelector("[data-variable-key]").list'),null);
  const orderedValues=()=>evaluate('Array.from(document.querySelectorAll("#report-input [data-variable-value]"),input=>input.value)');
  const idFor=value=>evaluate(`Array.from(document.querySelectorAll("#report-input .summary-pair")).find(node=>node.querySelector("[data-variable-value]").value===${JSON.stringify(value)}).dataset.variableId`);
  await command('Input.setInterceptDrags',{enabled:true});
  async function beginNativeDrag(value) {
    const id=await idFor(value);
    const start=await evaluate(`(() => {
      const root=document.getElementById('report-input');
      document.querySelector('.synthesis-pane').scrollIntoView({block:'start'});
      const grip=document.querySelector('[data-variable-id="${id}"] .summary-pair-grip');
      grip.scrollIntoView({block:'nearest'});
      window.testNativeDrag=null;
      root.addEventListener('dragstart',event=>{
        window.testNativeDrag={id:event.dataTransfer.getData('application/x-soc-pair'),value:event.dataTransfer.getData('text/plain'),trusted:event.isTrusted};
      },{once:true});
      const rect=grip.getBoundingClientRect();return {x:rect.left+rect.width/2,y:rect.top+rect.height/2};
    })()`);
    await command('Input.dispatchMouseEvent',{type:'mouseMoved',x:start.x,y:start.y});
    await command('Input.dispatchMouseEvent',{type:'mousePressed',x:start.x,y:start.y,button:'left',buttons:1,clickCount:1});
    await command('Input.dispatchMouseEvent',{type:'mouseMoved',x:start.x+3,y:start.y+20,button:'left',buttons:1});
    await wait(40);
    const drag=await evaluate('window.testNativeDrag');
    assert.equal(drag?.trusted,true,'Drag starts from a real mouse gesture on the grip');
    assert.equal(drag.id,id);
    assert.equal(drag.value,value,'Dragging transfers only the value');
    return {items:[{mimeType:'application/x-soc-pair',data:drag.id},{mimeType:'text/plain',data:drag.value}],dragOperationsMask:17};
  }
  async function dragTo(value, position) {
    const data=await beginNativeDrag(value);
    // The left padding is outside every row: gaps must not append by default.
    const point=await evaluate(`(() => {
      const root=document.getElementById('report-input'),rect=root.getBoundingClientRect();
      const position=${JSON.stringify(position)};
      if(position.edge==='bottom')root.scrollTop=root.scrollHeight;
      const rows=Array.from(root.querySelectorAll('.summary-pair'));
      const target=rows.find(node=>node.querySelector('[data-variable-value]').value===position.before);
      return {x:rect.left+2,y:target?target.getBoundingClientRect().top:position.edge==='top'?rect.top+2:rows.at(-1).getBoundingClientRect().bottom+3};
    })()`);
    for(const type of ['dragEnter','dragOver']) await command('Input.dispatchDragEvent',{type,...point,data});
    const marker=await evaluate(`(() => {
      const line=document.querySelector('.summary-drop-indicator');if(!line)return null;
      const rect=line.getBoundingClientRect();return {y:rect.top+rect.height/2,height:rect.height,pointerEvents:getComputedStyle(line).pointerEvents};
    })()`);
    assert(marker,'An insertion line is visible before dropping');
    assert.equal(marker.height,2);
    assert.equal(marker.pointerEvents,'none');
    if(position.before) assert(Math.abs(marker.y-point.y)<2,'Marker is between the two rows');
    await command('Input.dispatchDragEvent',{type:'drop',...point,data});
    await command('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',buttons:0,clickCount:1});
    assert.equal(await evaluate('document.querySelectorAll(".summary-drop-indicator, .summary-pair-dragging").length'),0);
  }
  await dragTo('A',{before:'C'});
  assert.deepEqual(await orderedValues(),['B','A','C','D'],'Move down into the gap between B and C');
  await dragTo('D',{before:'A'});
  assert.deepEqual(await orderedValues(),['B','D','A','C'],'Move up into the gap between B and A');
  await click('#undo-button');
  assert.deepEqual(await orderedValues(),['B','A','C','D'],'Undo restores the exact previous order');
  await dragTo('D',{edge:'top'});
  assert.deepEqual(await orderedValues(),['D','B','A','C'],'Top padding inserts first');
  await dragTo('D',{edge:'bottom'});
  assert.deepEqual(await orderedValues(),['B','A','C','D'],'Bottom padding inserts last');
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await command('Page.reload');
  await ready();
  assert.deepEqual(await orderedValues(),['B','A','C','D'],'Drag order survives reload');
  await click('#new-button');
  await fill('#raw-input',Array.from({length:35},(_,index)=>'Item: Value-'+index).join('\n'));
  await click('#process-source-button');
  for(const width of [1440,768,375,320]) {
    await showSummary(width);
    const page=await evaluate('scrollY');
    await wheelInSummary(180);
    assert(await evaluate('document.getElementById("report-input").scrollTop')>100,'Wheel scrolls long Summary lists at '+width);
    assert.equal(await evaluate('scrollY'),page,'The page stays still while Summary can scroll');
    await wheelInSummary(-90);
    assert(await evaluate('document.getElementById("report-input").scrollTop')<150,'Summary also scrolls upwards');
    await evaluate('document.getElementById("report-input").scrollTop=document.getElementById("report-input").scrollHeight');
    await wheelInSummary(150);
    assert(await evaluate('scrollY')>page,'Scrolling continues into the page at the bottom of Summary');
    await showSummary(width);
    await wheelInSummary(-150);
    assert(await evaluate('scrollY')<page,'Scrolling continues into the page at the top of Summary');
  }
  await showSummary(1440);
  const scrollData=await beginNativeDrag('Value-0');
  const bottom=await evaluate('(() => {const root=document.getElementById("report-input");root.scrollTop=0;const rect=root.getBoundingClientRect();return {x:rect.left+2,y:rect.bottom-5};})()');
  for(const type of ['dragEnter','dragOver']) await command('Input.dispatchDragEvent',{type,...bottom,data:scrollData});
  await wait(180);
  assert(await evaluate('document.getElementById("report-input").scrollTop>30'),'Long lists scroll while dragging near an edge');
  // Leave the scroll target and cancel the intercepted drag. This delivers
  // dragleave and dragend, and clears Chrome's native scrolling as well.
  const outside=await evaluate('({x:innerWidth-5,y:document.getElementById("report-input").getBoundingClientRect().top+20})');
  await command('Input.dispatchDragEvent',{type:'dragOver',...outside,data:scrollData});
  await command('Input.cancelDragging');
  await command('Input.dispatchDragEvent',{type:'dragCancel',...outside,data:scrollData});
  await command('Input.dispatchMouseEvent',{type:'mouseReleased',...outside,button:'left',buttons:0,clickCount:1});
  await wait(40);
  assert.equal(await evaluate('document.querySelectorAll(".summary-drop-indicator, .summary-pair-dragging").length'),0,'Cancellation clears the marker and source styling');
  const stopped=await evaluate('document.getElementById("report-input").scrollTop');
  await wait(100);
  assert.equal(await evaluate('document.getElementById("report-input").scrollTop'),stopped,'Auto-scroll stops after cancellation');
  assert.deepEqual(await orderedValues(),Array.from({length:35},(_,index)=>'Value-'+index),'Cancellation preserves the order');
  await click('#new-button');
  await fill('#raw-input','Network: A\nHost: B\nSource: C\nDestination: D');
  await click('#process-source-button');
  const parentId=await idFor('A');
  // The left-hand + opens a form directly below its parent.
  await click('[data-pair-action=add-child][data-id="'+parentId+'"]');
  assert.equal(await evaluate('document.activeElement.id'),'summary-new-key');
  assert.equal(await evaluate('document.getElementById("summary-add-variable-form").previousElementSibling.dataset.variableId'),parentId);
  await fill('#summary-new-key','Protocol');
  await fill('#summary-new-value','TCP');
  await evaluate('document.getElementById("summary-add-variable-form").requestSubmit()');
  const manualId=await idFor('TCP');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId`),parentId);
  assert.equal(await evaluate(`document.querySelectorAll('[data-variable-id="${manualId}"] [data-pair-action="add-child"]').length`),0,'Subcategories cannot receive a second child level');
  assert.deepEqual(await orderedValues(),['A','TCP','B','C','D']);

  async function dragOnCard(value,targetValue,{fraction=.75,vertical=.5,nest=true,fallback=false,gap=false}={}) {
    const data=await beginNativeDrag(value);
    const targetId=await idFor(targetValue);
    const point=await evaluate(`(() => {
      const node=document.querySelector('[data-variable-id="${targetId}"]');node.scrollIntoView({block:'nearest'});
      const rect=node.getBoundingClientRect(),summary=document.getElementById('report-input').getBoundingClientRect();
      return {x:summary.left+summary.width*${fraction},y:${gap ? 'rect.bottom+4' : 'rect.top+rect.height*'+vertical}};
    })()`);
    for(const type of ['dragEnter','dragOver']) await command('Input.dispatchDragEvent',{type,...point,data});
    if(fallback) {
      assert.equal(await evaluate(`document.querySelector('[data-variable-id="${targetId}"]').classList.contains('summary-drop-invalid')`),false,'Invalid drops keep the card free of orange highlighting');
      assert.equal(await evaluate('document.querySelectorAll(".summary-drop-indicator").length'),1,'An impossible drop shows its top-level fallback position');
      assert.equal(await evaluate('document.querySelectorAll(".summary-nest-target").length'),0);
      const marker=await evaluate(`(() => {
        const root=document.getElementById('report-input'),summary=root.getBoundingClientRect();
        const target=document.querySelector('[data-variable-id="${targetId}"]');
        const parent=target.dataset.parentId || target.dataset.variableId;
        const group=Array.from(root.querySelectorAll('.summary-pair')).filter(node=>node.dataset.variableId===parent || node.dataset.parentId===parent);
        const bottom=group.at(-1).getBoundingClientRect().bottom;
        const line=document.querySelector('.summary-drop-indicator').getBoundingClientRect();
        return {fullWidth:Math.abs(line.left-summary.left-10)<2 && line.width>summary.width-40,belowGroup:line.top+line.height/2>=bottom-2 && line.top+line.height/2<=bottom+10};
      })()`);
      assert.equal(marker.fullWidth,true,'The fallback marker indicates a parent category');
      assert.equal(marker.belowGroup,true,'The fallback stays at the first gap below the complete target block');
      assert((await evaluate('document.getElementById("summary-drop-status").textContent')).includes('top-level'));
    } else if(nest) {
      const targetParent=await evaluate(`document.querySelector('[data-variable-id="${targetId}"]').dataset.parentId || null`);
      assert.equal(await evaluate(`document.querySelector('[data-variable-id="${targetParent || targetId}"]').classList.contains('summary-nest-target')`),true,'Nesting highlights the actual parent');
      assert.equal(await evaluate('document.querySelectorAll(".summary-drop-indicator").length'),targetParent ? 1 : 0);
      if(targetParent) {
        const aligned=await evaluate(`(() => {
          const target=document.querySelector('[data-variable-id="${targetId}"]').getBoundingClientRect();
          const line=document.querySelector('.summary-drop-indicator').getBoundingClientRect();
          return Math.abs(line.top+line.height/2-target.bottom)<2 && Math.abs(line.left-target.left)<2;
        })()`);
        assert.equal(aligned,true,'The indented marker sits directly below the hovered child');
      }
    } else {
      assert.equal(await evaluate('document.querySelectorAll(".summary-drop-indicator").length'),1);
      assert.equal(await evaluate('document.querySelectorAll(".summary-nest-target").length'),0);
    }
    await command('Input.dispatchDragEvent',{type:'drop',...point,data});
    await command('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',buttons:0,clickCount:1});
    assert.equal(await evaluate('document.querySelectorAll(".summary-nest-target, .summary-drop-invalid, .summary-drop-indicator, .summary-pair-dragging").length'),0);
  }
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId`),parentId);
  assert.equal(await evaluate(`new URL(document.querySelector('[data-service-now="${manualId}"]').href).searchParams.get('value')`),'TCP','ServiceNow is available on a subcategory');
  assert.deepEqual(await orderedValues(),['A','TCP','B','C','D']);
  await dragOnCard('C','A',{fraction:.07});
  assert.deepEqual(await orderedValues(),['A','C','TCP','B','D'],'The right fourteen fifteenths of Summary insert directly below the parent');
  const childId=await idFor('C');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId`),parentId);
  assert((await evaluate('SOCNote.report.getText()')).includes('Network: A\n├── Source: C\n└── Protocol: TCP'));
  assert.equal(await evaluate('document.getElementById("final-report-input").textContent'),await evaluate('SOCNote.report.getText()'));
  await command('Emulation.setDeviceMetricsOverride',{width:375,height:900,deviceScaleFactor:1,mobile:false});
  await wait(40);
  await dragOnCard('TCP','C',{fraction:.06,vertical:.2,nest:false});
  assert.deepEqual(await orderedValues(),['A','TCP','C','B','D'],'On a narrow Summary, the left zone reorders children through their margin');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId`),parentId);
  await click('#undo-button');
  await dragOnCard('D','C',{fraction:.07});
  assert.deepEqual(await orderedValues(),['A','C','D','TCP','B'],'The same global boundary nests after the hovered child even inside its indentation');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${await idFor('D')}"]').dataset.parentId`),parentId);
  await click('#undo-button');
  await dragOnCard('A','B',{fallback:true});
  assert.deepEqual(await orderedValues(),['B','A','C','TCP','D'],'On a narrow Summary, an impossible parent nesting falls back below the target');
  await click('#undo-button');
  await command('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await wait(40);
  await click('#undo-button');
  assert.deepEqual(await orderedValues(),['A','TCP','B','C','D']);
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId || null`),null);
  await dragOnCard('C','A');
  await dragOnCard('C','TCP');
  assert.deepEqual(await orderedValues(),['A','TCP','C','B','D'],'Dropping on a sibling places the child just below it');
  await dragOnCard('D','C',{fraction:.07,vertical:.2});
  const destinationId=await idFor('D');
  assert.deepEqual(await orderedValues(),['A','TCP','C','D','B'],'Dropping on a child inserts a sibling, even in its upper half');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${destinationId}"]').dataset.parentId`),parentId);
  await click('#undo-button');
  assert.deepEqual(await orderedValues(),['A','TCP','C','B','D']);
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${destinationId}"]').dataset.parentId || null`),null);
  await dragOnCard('D','TCP',{gap:true});
  assert.deepEqual(await orderedValues(),['A','TCP','D','C','B'],'The right-side gap uses the row immediately above the pointer');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${destinationId}"]').dataset.parentId`),parentId);
  await click('#undo-button');
  await dragOnCard('D','C',{fraction:.06,nest:false,fallback:true});
  assert.deepEqual(await orderedValues(),['A','TCP','C','D','B'],'A root dropped in the left zone of a child falls back after its parent block');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${destinationId}"]').dataset.parentId || null`),null);
  await click('#undo-button');
  await dragOnCard('A','B',{fallback:true});
  assert.deepEqual(await orderedValues(),['B','A','TCP','C','D'],'A parent with children falls back after the target at the top level');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId`),parentId);
  await click('#undo-button');
  await dragOnCard('A','C',{fallback:true});
  assert.deepEqual(await orderedValues(),['A','TCP','C','B','D'],'A drop on the source subtree uses the gap after that block without moving it');
  await dragOnCard('A','D',{fallback:true});
  assert.deepEqual(await orderedValues(),['B','D','A','TCP','C'],'An impossible drop on the last parent falls back to the end');
  await click('#undo-button');
  await dragOnCard('C','C',{fallback:true});
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId || null`),null,'An impossible drop on the same child promotes it below its parent');
  assert.deepEqual(await orderedValues(),['A','TCP','C','B','D']);
  await click('#undo-button');
  await dragOnCard('C','TCP',{fraction:.06,vertical:.2,nest:false});
  assert.deepEqual(await orderedValues(),['A','C','TCP','B','D'],'The left fifteenth of Summary reorders siblings');
  await dragOnCard('D','B',{fraction:.06,vertical:.8,nest:false});
  assert.deepEqual(await orderedValues(),['A','C','TCP','B','D'],'The lower half of the left fifteenth of Summary inserts after');
  await dragOnCard('B','A',{fraction:.06,vertical:.8,nest:false});
  assert.deepEqual(await orderedValues(),['A','C','TCP','B','D'],'After a parent inserts after its complete subtree');
  await dragOnCard('A','D',{fraction:.06,vertical:.8,nest:false});
  assert.deepEqual(await orderedValues(),['B','D','A','C','TCP'],'Reordering a parent carries its children');
  await dragOnCard('C','B');
  assert.deepEqual(await orderedValues(),['B','C','D','A','TCP'],'A child can change parents');
  await dragOnCard('A','C',{fallback:true});
  assert.deepEqual(await orderedValues(),['B','C','A','TCP','D'],'A parent dropped on another child falls back after that entire group');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId`),parentId);
  await click('#undo-button');
  await dragOnCard('TCP','C');
  assert.deepEqual(await orderedValues(),['B','C','TCP','D','A'],'A child can join another parent directly below its existing child');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId`),await idFor('B'));
  await click('#undo-button');
  assert.deepEqual(await orderedValues(),['B','C','D','A','TCP']);
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await command('Page.reload'); await ready();
  assert.deepEqual(await orderedValues(),['B','C','D','A','TCP']);
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId`),await idFor('B'));
  if(process.env.SOC_TREE_SCREENSHOT) {
    await evaluate('document.querySelector(".synthesis-pane").scrollIntoView({block:"start"}); document.activeElement.blur(); document.getElementById("toast").hidden=true');
    const image=await command('Page.captureScreenshot',{format:'png'});
    await require('node:fs/promises').writeFile(process.env.SOC_TREE_SCREENSHOT,Buffer.from(image.data,'base64'));
  }
  assert.equal(await evaluate('document.querySelectorAll("[data-pair-action=detach]").length'),0);
  await dragOnCard('C','B',{fraction:.06,vertical:.8,nest:false});
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId || null`),null);
  await click('#undo-button');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${childId}"]').dataset.parentId`),await idFor('B'));
  await click('[data-pair-action=remove][data-id="'+parentId+'"]');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId || null`),null,'Removing a parent keeps its child as a root');
  await click('#undo-button');
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"]').dataset.parentId`),parentId);
  await fill('[data-variable-value="'+manualId+'"]','https://example.invalid/custom');
  assert.equal(await evaluate(`new URL(document.querySelector('[data-service-now="${manualId}"]').href).searchParams.get('value')`),'https://example.invalid/custom','ServiceNow follows edited subcategory values');
  await click('#copy-report-button');await wait(60);
  assert.equal(await evaluate('navigator.clipboard.readText()'),await evaluate('SOCNote.report.getText()'),'Report copying retains the hierarchy and child details');
  assert.equal(await evaluate('document.getElementById("final-report-input").textContent'),await evaluate('SOCNote.report.getText()'));
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"] [data-entity-vt]').textContent`),'');
  assert((await evaluate(`getComputedStyle(document.querySelector('[data-variable-id="${manualId}"] [data-entity-vt]')).backgroundImage`)).includes('virus-total.png'));
  assert.equal(await evaluate(`document.querySelector('[data-variable-id="${manualId}"] [data-entity-vt]').href`),'https://www.virustotal.com/gui/url/'+Buffer.from('https://example.invalid/custom').toString('base64url'));
  await command('Input.setInterceptDrags',{enabled:false});
  // Removing a value frees it for a new import, including after recovery and Undo.
  await click('#new-button');
  await fill('#raw-input','Host: Reimport-ONE');
  await click('#process-source-button');
  const removedId=await idFor('Reimport-ONE');
  await click('[data-pair-action=remove][data-id="'+removedId+'"]');
  assert.equal(await count(),0);
  await click('#undo-button');
  assert.equal(await idFor('Reimport-ONE'),removedId);
  await click('[data-pair-action=remove][data-id="'+removedId+'"]');
  await evaluate('window.dispatchEvent(new Event("pagehide"))');
  await command('Page.reload');await ready();
  assert.equal(await count(),0);
  await fill('#raw-input','Host: Reimport-ONE\nHost: Reimport-ONE');
  await click('#process-source-button');
  assert.equal(await count(),1,'A deleted value is accepted again, once');
  assert.notEqual(await idFor('Reimport-ONE'),removedId);
  const importedId=await idFor('Reimport-ONE');
  await click('[data-pair-action=remove][data-id="'+importedId+'"]');
  assert.equal((await evaluate('SOCNote.importJSON({Host:"Reimport-ONE"})')).ok,true);
  assert.equal(await count(),1,'JSON can also reintroduce a deleted value');
  await evaluate('SOCNote.importJSON({Host:"Reimport-ONE"})');
  assert.equal(await count(),1,'A value currently in Summary still appears only once');
  await click('#new-button');
  await command('Page.reload');
  await ready();
  console.log('Summary checks passed: native wheel scrolling and page handoff at 320–1440 px, native mouse drag in both card zones, insertion lines and nesting highlights, manual category creation, ServiceNow links and edited values, depth limits, parent block moves, child ordering and reparenting, detaching, deletion, hierarchy copy and reload, auto-scroll, cancellation, unique values and Undo.');
};

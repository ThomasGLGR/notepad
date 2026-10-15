const assert = require('node:assert/strict');
const luminance = rgb => rgb.map(value => value / 255).reduce((sum,value,index) => sum + [.2126,.7152,.0722][index] * (value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4),0);
const contrast = (first,second) => (Math.max(luminance(first),luminance(second)) + .05) / (Math.min(luminance(first),luminance(second)) + .05);

module.exports = async function interfaceChecks({evaluate,command,click,fill,wait,keypress}) {
  await click('#new-button');
  const style = selector => evaluate(`(() => {
    const node=document.querySelector(${JSON.stringify(selector)}),style=getComputedStyle(node);
    return {background:style.backgroundColor,color:style.color,border:style.borderTopColor,borderStyle:style.borderTopStyle,cursor:style.cursor,opacity:style.opacity,shadow:style.boxShadow};
  })()`);
  assert.equal(await evaluate('document.getElementById("copy-report-button").disabled'),true);
  const disabledButton = await style('#copy-report-button');
  assert.equal(disabledButton.cursor,'not-allowed');
  assert.equal(disabledButton.opacity,'1','Disabled text stays legible');
  assert.equal(disabledButton.borderStyle,'dashed');
  let lowest = await audit();

  await fill('#rule-input','Interface verification');
  await fill('#raw-input','URL: https://example.invalid/path\nIP: 192.0.2.1\ntimestamp: 2026-10-14T23:12:00Z');
  await click('#process-source-button');
  await fill('#analysis-input','Notes kept exactly.\n\nSecond paragraph.');
  const urlId = await evaluate('Array.from(document.querySelectorAll(".summary-pair")).find(node=>node.querySelector("[data-variable-value]").value.startsWith("https://")).dataset.variableId');
  const ipId = await evaluate('Array.from(document.querySelectorAll(".summary-pair")).find(node=>node.querySelector("[data-variable-value]").value==="192.0.2.1").dataset.variableId');
  const defang = '[data-defang-url="'+urlId+'"]';
  const idleToggle = await style(defang);
  await click(defang);
  await wait(180);
  const activeToggle = await style(defang);
  assert.equal(await evaluate(`document.querySelector('${defang}').getAttribute('aria-pressed')`),'true');
  assert.notEqual(activeToggle.background,idleToggle.background);
  assert(activeToggle.shadow.includes('inset'),'The active DFN toggle looks pressed');
  lowest=Math.min(lowest,await audit());
  await click(defang);
  await click('[data-pair-action=add-child][data-id="'+ipId+'"]');
  await fill('#summary-new-key','Observed');
  await fill('#summary-new-value','2026-10-15');
  await evaluate('document.getElementById("summary-add-variable-form").requestSubmit()');
  assert.equal(await evaluate('document.querySelectorAll(".source-archive, #archived-raw-input, #copy-raw-button").length'),0);
  await click('#add-variable-button');
  await wait(180);

  const report = await evaluate('SOCNote.report.getText()');
  const reportStyle = await style('#final-report-input');
  assert.equal(reportStyle.color,'rgb(48, 54, 64)');
  assert.equal(reportStyle.background,'rgb(255, 255, 255)');
  assert.equal(await evaluate('getComputedStyle(document.getElementById("final-report-input")).fontSize'),'14px');
  assert.equal(await evaluate('getComputedStyle(document.querySelector("#final-report-input strong")).color'),'rgb(37, 43, 51)');

  const editable = await style('#raw-input');
  await evaluate('document.getElementById("manual-copy-input").value="Read-only selection";document.getElementById("copy-dialog").showModal()');
  const readonly = await style('#manual-copy-input');
  assert.equal(editable.background,'rgb(243, 244, 246)','Editable backgrounds stay neutral gray');
  assert.equal(readonly.background,'rgb(220, 231, 245)','Read-only backgrounds use a light blue tint');
  assert.equal(editable.border,'rgba(0, 0, 0, 0)','Editable fields have no dark resting border');
  assert.equal(editable.shadow,'none','Fields have no focus halo');
  assert.equal(editable.cursor,'text');
  assert.notEqual(readonly.background,editable.background);
  assert.equal(readonly.borderStyle,'dashed');
  assert.equal(readonly.cursor,'default');
  await evaluate('document.getElementById("manual-copy-input").setSelectionRange(0,7)');
  assert.equal(await evaluate('document.getElementById("manual-copy-input").selectionEnd'),7,'Read-only text can still be selected and copied');
  await evaluate('document.getElementById("copy-dialog").close()');

  // Measure computed text and field colors, including placeholders and translucent ancestors.
  async function audit() {
    const samples = await evaluate(`(() => {
      const parse=color=>{const numbers=color.match(/[0-9.]+/g).map(Number);return [...numbers.slice(0,3),numbers[3] ?? 1];};
      const blend=(color,background)=>color.slice(0,3).map((value,index)=>value*color[3]+background[index]*(1-color[3]));
      function background(node) {return node ? blend(parse(getComputedStyle(node).backgroundColor),background(node.parentElement)) : [255,255,255];}
      const visible=node=>!node.closest('.sr-only, #final-report-input') && Array.from(node.getClientRects()).some(rect=>rect.width>1 && rect.height>1) && getComputedStyle(node).visibility==='visible';
      const text=[];
      function note(node,label,color) {
        const bg=background(node);let opacity=1;
        for(let parent=node;parent;parent=parent.parentElement) opacity*=Number(getComputedStyle(parent).opacity);
        const fg=parse(color || getComputedStyle(node).color);fg[3]*=opacity;
        text.push({label,foreground:blend(fg,bg),background:bg});
      }
      const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
      while(walker.nextNode()) {
        const node=walker.currentNode,parent=node.parentElement;
        if(node.textContent.trim() && parent.tagName!=='OPTION' && visible(parent)) note(parent,node.textContent.trim().slice(0,60));
      }
      for(const node of document.querySelectorAll('input:not([type=file]):not([type=checkbox]), textarea, select')) {
        if(!visible(node)) continue;
        note(node,node.id || node.getAttribute('aria-label'),!node.value && node.placeholder ? getComputedStyle(node,'::placeholder').color : null);
      }
      return {text};
    })()`);
    assert(samples.text.length>=15,'Audit covers the visible interface, values, placeholders and controls');
    let lowest=Infinity;
    for(const sample of samples.text) {
      const ratio=contrast(sample.foreground,sample.background);
      lowest=Math.min(lowest,ratio);
      assert(ratio>=7,`${sample.label}: text contrast ${ratio.toFixed(2)} is below 7:1`);
    }
    return lowest;
  }
  lowest=Math.min(lowest,await audit());
  await evaluate('document.getElementById("raw-input").disabled=true');
  await wait(180);
  const disabledField = await style('#raw-input');
  assert.equal(disabledField.cursor,'not-allowed');
  assert.equal(disabledField.borderStyle,'dashed');
  assert.notEqual(disabledField.background,editable.background);
  lowest=Math.min(lowest,await audit());
  await evaluate('document.getElementById("raw-input").disabled=false;document.getElementById("new-button").focus()');
  await keypress('Tab','Tab',0,9);
  const focus = await evaluate(`(() => {
    const node=document.activeElement,style=getComputedStyle(node);
    return {visible:node.matches(':focus-visible'),width:parseFloat(style.outlineWidth),style:style.outlineStyle,color:style.outlineColor,background:style.backgroundColor,shadow:style.boxShadow};
  })()`);
  assert.equal(focus.visible,true);
  assert.equal(focus.width,2,'Focus has a thin ring');
  assert.equal(focus.style,'solid');
  assert.equal(focus.shadow,'none','Keyboard focus adds no large overlay');
  assert(contrast(focus.color.match(/[0-9.]+/g).slice(0,3).map(Number),[255,255,255])>=3,'Focus ring has at least 3:1 contrast');
  assert.equal(await evaluate('SOCNote.report.getText()'),report,'Field states and keyboard focus do not change report text');
  assert.equal(await evaluate('document.getElementById("final-report-input").textContent'),report);

  const secondary=await style('#open-log-button'), quiet=await style('#copy-analysis-button'), primary=await style('#process-source-button'), icon=await style('[data-copy-variable="'+urlId+'"]');
  assert.equal(quiet.background,secondary.background,'Standard and quiet buttons share the secondary style');
  assert.equal(quiet.border,secondary.border);
  assert.notEqual(primary.background,secondary.background,'Primary actions have their own style');
  assert.equal((await style('#new-button')).background,(await style('#copy-report-button')).background,'New uses the same primary style as Copy report');
  assert.equal(icon.background,'rgba(0, 0, 0, 0)','Icon actions use the third, transparent style');

  for(const width of [1440,900,768,375,320]) {
    await command('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false});
    await wait(40);
    assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),'No page overflow at '+width);
    const fonts = await evaluate(`Array.from(document.querySelectorAll('input:not([type=file]):not([readonly]):not([disabled]),textarea:not([readonly]):not([disabled]),select:not([disabled])')).filter(node=>node.getClientRects().length).map(node=>getComputedStyle(node).fontSize)`);
    assert(fonts.length>5 && fonts.every(size=>size==='13px'),'All editable fields use 13 px text at '+width);
    assert(await evaluate(`(() => {
      const headings=Array.from(document.querySelectorAll('.rule-field label, .mitre-field label, .pane-heading h2'),node=>{
        const style=getComputedStyle(node);return [style.fontSize,style.fontWeight,style.color,style.lineHeight].join('|');
      });return new Set(headings).size===1;
    })()`),'Rule and MITRE titles match section headings at '+width);
    if(width>1100) {
      const inline=await evaluate(`(() => {
        const nodes=['.rule-field label','#rule-input','.mitre-field label','.mitre-picker','#mitre-tactics-button'].map(selector=>document.querySelector(selector).getBoundingClientRect());
        const centers=nodes.map(rect=>rect.top+rect.height/2);
        return Math.max(...centers)-Math.min(...centers)<2 && nodes.every((rect,index)=>!index || rect.left>=nodes[index-1].right);
      })()`);
      assert.equal(inline,true,'Rule, MITRE, their fields and Tactics share one row at '+width);
    }
    const rows = await evaluate(`Array.from(document.querySelectorAll('.summary-pair'),node=>({
      key:node.querySelector('[data-variable-key]').value,width:node.clientWidth,content:node.scrollWidth,
      fields:node.querySelector('[data-variable-value]').getBoundingClientRect().right-node.getBoundingClientRect().left,
      actions:node.querySelector('.summary-pair-actions').getBoundingClientRect().right-node.getBoundingClientRect().left
    }))`);
    assert(rows.every(node=>node.content<=node.width),'Summary controls fit at '+width+': '+JSON.stringify(rows));
    assert(await evaluate('(() => {const heading=document.querySelector(".analysis-pane h2").getBoundingClientRect(),input=document.getElementById("analysis-input").getBoundingClientRect();return input.top-heading.bottom>=12;})()'),'Headings have breathing room at '+width);
  }
  await command('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  assert.equal(await evaluate('getComputedStyle(document.getElementById("new-button")).transitionDuration'),'0s');
  await command('Emulation.setEmulatedMedia',{features:[]});
  await command('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
  await click('#new-button');
  console.log(`Interface checks passed: minimum measured UI text contrast ${lowest.toFixed(2)}:1, neutral gray editable fields, blue read-only backgrounds, thin focus without halos, three button styles, matching Rule/MITRE titles, disabled/active states, readable placeholders, reduced motion, 320–1440 px layouts and unchanged report text/style.`);
};

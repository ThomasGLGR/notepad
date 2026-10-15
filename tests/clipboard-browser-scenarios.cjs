const assert = require('node:assert/strict');

module.exports = async function clipboardChecks({evaluate, click, fill, wait, keypress}) {
  await click('#new-button');
  await evaluate(`(() => {
    window.nativeClipboard = navigator.clipboard;
    const host = document.createElement('div');
    host.id = 'clipboard-test-host';
    const shadow = host.attachShadow({mode: 'open'});
    const plain = document.createElement('textarea');
    const rich = document.createElement('div');
    rich.contentEditable = 'true';
    shadow.append(plain, rich);
    document.body.append(host);
    window.clipboardTestEditors = {plain, rich};
  })()`);
  const paste = async kind => {
    await evaluate(`(() => {
      const editor = clipboardTestEditors.${kind};
      if (editor instanceof HTMLTextAreaElement) editor.value = '';
      else editor.replaceChildren();
      editor.focus();
    })()`);
    await keypress('v', 'KeyV', 2, 86);
    await wait(40);
    // Rich editors represent preserved indentation with nonbreaking spaces.
    return evaluate(`clipboardTestEditors.${kind}.${kind === 'plain' ? 'value' : 'innerText.replace(/\\u00a0/g, " ")'}`);
  };
  const readHTML = () => evaluate(`(async () => {
    for (const item of await nativeClipboard.read()) {
      if (item.types.includes('text/html')) return (await item.getType('text/html')).text();
    }
    return null;
  })()`);
  const assertPastes = async (expected, label) => {
    assert.equal(await paste('plain'), expected, label + ': plain-text editor');
    assert.equal(await paste('rich'), expected, label + ': rich-text editor without app CSS');
  };

  try {
    await fill('#rule-input', 'Multiple lines');
    await fill('#raw-input', 'User: alice\nHost: ONE');
    await click('#process-source-button');
    await evaluate('SOCNote.remediation.setActiveTactics(["credential-access"])');
    await click('[data-tactic-group=credential-access] [data-choose=credential-access-1]');
    await fill('[data-selected-text=credential-access-1]', 'First action\n  Continuation\n\nSecond action');
    const analysis = 'First observation\n\nSecond observation\nThird observation';
    await fill('#analysis-input', analysis);
    const report = await evaluate('SOCNote.report.getText()');

    await click('#copy-report-button');
    await wait(40);
    assert.equal(await evaluate('nativeClipboard.readText()'), report);
    assert(await readHTML(), 'Report includes rich HTML');
    await assertPastes(report, 'Copy Report');
    await evaluate('window.dispatchEvent(new Event("pagehide"))');
    const summary = await evaluate('SOCNote.formatter.summaryValues(SOCNote.storage.load().document)');
    const remediation = await evaluate('SOCNote.remediationEngine.format(SOCNote.storage.load().document)');
    for (const [button, expected] of [['#copy-analysis-button', analysis], ['#copy-summary-button', summary], ['#copy-remediations-button', remediation]]) {
      await click(button);
      await wait(40);
      assert.equal(await evaluate('nativeClipboard.readText()'), expected);
      await assertPastes(expected, 'Modern ' + button);
    }

    // Native Ctrl+C must also preserve complete and partial report selections.
    await evaluate('SOCNote.report.select()');
    await keypress('c', 'KeyC', 2, 67);
    await wait(40);
    await assertPastes(report, 'Ctrl+C on full report');
    const selected = await evaluate(`(() => {
      const root = document.getElementById('final-report-input');
      const range = document.createRange();
      range.setStart(root.querySelector('strong').firstChild, 1);
      range.setEnd(root.querySelector('[data-report-section="analysis"] .report-section-text').firstChild, ${analysis.indexOf('\nThird')});
      root.focus();
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      // The copy carries the report's own text, centered headings and separators included.
      return range.toString();
    })()`);
    assert(report.includes(selected), 'A partial selection is a slice of the plain-text report');
    await keypress('c', 'KeyC', 2, 67);
    await wait(40);
    await assertPastes(selected, 'Ctrl+C on partial report');

    // Denied modern clipboard APIs must retain the same report through execCommand.
    await evaluate(`Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {write: () => Promise.reject(Error('Forced refusal')), writeText: () => Promise.reject(Error('Forced refusal'))}
    })`);
    await click('#copy-report-button');
    await wait(40);
    assert(await readHTML(), 'Fallback report copy includes rich HTML');
    await assertPastes(report, 'Fallback report copy');

    await click('#copy-analysis-button');
    await wait(40);
    await assertPastes(analysis, 'Fallback Analysis copy');
    await click('#copy-summary-button');
    await wait(40);
    await assertPastes(summary, 'Fallback Summary copy');
    await click('#copy-remediations-button');
    await wait(40);
    await assertPastes(remediation, 'Fallback Remediation copy');

    // Native copying in Logs preserves original CRLF/CR, including when clipboard APIs fail.
    const raw = 'User: bob\r\nHost: TWO\rComment: literal <tag>';
    await evaluate(`document.getElementById('raw-input').focus(); nativeClipboard.writeText(${JSON.stringify(raw + '\n\n')})`);
    await keypress('v', 'KeyV', 2, 86);
    await wait(40);
    await evaluate('document.getElementById("raw-input").focus();document.getElementById("raw-input").select()');
    await keypress('c','KeyC',2,67);
    await wait(40);
    await evaluate('window.dispatchEvent(new Event("pagehide"))');
    const original = await evaluate('SOCNote.storage.load().document.raw');
    assert(original.endsWith(raw), 'Pasting preserves original source line endings');
    assert.equal(await evaluate('nativeClipboard.readText()'), original, 'Fallback preserves CRLF and CR');
    await assertPastes(original.replace(/\r\n?/g, '\n'), 'Fallback raw text copy');

    // With automatic methods blocked, native copying of the selected report
    // and the manual dialog must still supply the same portable HTML.
    await evaluate('window.clipboardTestExecCommand = document.execCommand; document.execCommand = () => false');
    await click('#copy-report-button');
    const currentReport = await evaluate('SOCNote.report.getText()');
    assert.equal(await evaluate('document.getElementById("copy-dialog").open'), false);
    await keypress('c', 'KeyC', 2, 67);
    await wait(40);
    await assertPastes(currentReport, 'Manual Report copy');

    await click('#copy-analysis-button');
    assert.equal(await evaluate('document.getElementById("copy-dialog").open'), true);
    await keypress('c', 'KeyC', 2, 67);
    await wait(40);
    await click('#close-copy-button');
    await assertPastes(analysis, 'Manual Analysis copy');
    await evaluate('document.getElementById("raw-input").focus();document.getElementById("raw-input").select()');
    await keypress('c', 'KeyC', 2, 67);
    await wait(40);
    assert.equal(await evaluate('nativeClipboard.readText()'), original, 'Manual copy preserves original CRLF/CR');
    await evaluate(`(() => {
      const input = document.getElementById('raw-input');
      const start = input.value.indexOf('User: bob');
      input.setSelectionRange(start, start + 'User: bob\\nHost: TWO\\n'.length);
    })()`);
    await keypress('c', 'KeyC', 2, 67);
    await wait(40);
    assert.equal(await evaluate('nativeClipboard.readText()'), 'User: bob\r\nHost: TWO\r', 'Manual partial copy maps normalized selection offsets to original line endings');
    await assertPastes('User: bob\nHost: TWO\n', 'Manual partial raw copy');
  } finally {
    await evaluate(`
      delete navigator.clipboard;
      if (window.clipboardTestExecCommand) document.execCommand = window.clipboardTestExecCommand;
      delete window.clipboardTestExecCommand;
      if (document.getElementById('copy-dialog').open) document.getElementById('copy-dialog').close();
      document.getElementById('clipboard-test-host')?.remove();
      delete window.clipboardTestEditors;
    `);
    await click('#new-button');
  }
  console.log('Clipboard checks passed: real plain/rich pastes, multiline text, blank lines, full/partial Ctrl+C, denied clipboard APIs, manual copying and original CRLF/CR.');
};

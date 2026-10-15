const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {randomUUID} = require('node:crypto');
function modules() {
  const saved = new Map();
  const window = {crypto:{randomUUID},localStorage:{getItem:key=>saved.get(key)??null,setItem:(key,value)=>saved.set(key,value),removeItem:key=>saved.delete(key)}};
  const context = vm.createContext({window,URL});
  for (const file of ['templates','summary-data','extractors','parser','defang','remediation-data','remediation-engine','remediation-storage','formatter','storage']) vm.runInContext(fs.readFileSync(path.join(__dirname,'../js',file+'.js'),'utf8'),context);
  return {...window.SOCNote,saved};
}

test('report uses English sections, plain-text keys and blank lines after headings and between Summary points',()=>{
  const {templates,parser,formatter,remediationData:data,features}=modules();
  const document=templates.emptyDocument();
  document.raw='USER: DOMAIN\\jdupont\nHOST: PC-0042\nIP: 185.42.21.8';
  parser.capture(document);
  const tactic=data.defaults().find(tactic=>tactic.id==='credential-access');
  const item=tactic.remediations[0];
  document.remediation.selected.push({id:item.id,tacticId:tactic.id,tacticName:tactic.name,template:item.template,generic:'',text:null});
  document.analysis='Sign-ins reviewed.';
  // Remediation is withdrawn from the report; its selection stays in the investigation.
  assert.equal(formatter.format(document),'==================================================\n                     SUMMARY\n==================================================\n\nUSER: DOMAIN\\jdupont\n\nHOST: PC-0042\n\nIP: 185.42.21.8\n\n==================================================\n                     ANALYSIS\n==================================================\n\nSign-ins reviewed.');
  assert.equal(document.remediation.selected.length,1);
  features.remediation=true;
  assert.equal(formatter.format(document),'==================================================\n                     SUMMARY\n==================================================\n\nUSER: DOMAIN\\jdupont\n\nHOST: PC-0042\n\nIP: 185.42.21.8\n\n==================================================\n                   REMEDIATION\n==================================================\n\n- Reset the password for the account DOMAIN\\jdupont.\n\n==================================================\n                     ANALYSIS\n==================================================\n\nSign-ins reviewed.');
  assert.equal(formatter.summaryValues(document),'DOMAIN\\jdupont\nPC-0042\n185.42.21.8');
});

test('report leaves one blank line after its title and Summary banner without adding empty sections',()=>{
  const {templates,pairs,formatter}=modules();
  const document=templates.emptyDocument();
  document.rule='Investigation';
  assert.equal(formatter.format(document),'Investigation');
  pairs.add(document,['Host'],'ONE');
  assert.equal(formatter.format(document),'Investigation\n\n==================================================\n                     SUMMARY\n==================================================\n\nHost: ONE');
  document.variables=[];
  document.analysis='Reviewed.';
  assert.equal(formatter.format(document),'Investigation\n\n==================================================\n                     ANALYSIS\n==================================================\n\nReviewed.');
});

test('empty sections are omitted and keys and values remain plain text',()=>{
  const {templates,pairs,formatter}=modules();
  const document=templates.emptyDocument();
  assert.equal(formatter.format(document),'');
  pairs.add(document,['key**name'],'literal <img src=x>');
  assert.equal(formatter.format(document),'==================================================\n                     SUMMARY\n==================================================\n\nkey**name: literal <img src=x>');
  document.analysis='Notes.';
  assert.equal(formatter.format(document),'==================================================\n                     SUMMARY\n==================================================\n\nkey**name: literal <img src=x>\n\n==================================================\n                     ANALYSIS\n==================================================\n\nNotes.');
  assert(formatter.format(document).includes('=================================================='),'Literal separators are retained in the copied report');
});

test('all default action templates and generic fallback wording are English',()=>{
  const {remediationData:data,remediationEngine:engine,templates}=modules();
  const items=data.defaults().flatMap(tactic=>tactic.remediations);
  assert.equal(items.length,116);
  for(const item of items){
    assert(/^(Identify|Block|Review|Limit|Monitor|Add|Check|Remove|Reset|Revoke|Stop|Isolate|Look|Restore|Verify|Temporarily|Preserve|Disable|Follow)\b/.test(item.template),item.template);
    const generic=engine.resolve(item.template,templates.emptyDocument()).text;
    assert(!/undefined|null|\{[^{}]+\}|[éèàç]/.test(generic),generic);
  }
});

test('saved French defaults upgrade to English while retaining favorites, order, disabled states and custom edits',()=>{
  const {remediationData:data,remediationStorage:storage}=modules();
  const catalog=data.defaults();
  const tactic=catalog.find(tactic=>tactic.id==='credential-access');
  tactic.remediations[0].template='Réinitialiser le mot de passe du compte {USER}.';
  tactic.remediations[0].favorite=true;
  tactic.remediations[0].enabled=false;
  tactic.remediations[1].template='User-authored text to preserve.';
  catalog.reverse();
  assert.equal(storage.save(catalog).ok,true);
  const loaded=storage.load().catalog;
  const restored=loaded.find(tactic=>tactic.id==='credential-access');
  assert.equal(loaded[0].id,'impact');
  assert.equal(restored.remediations[0].template,'Reset the password for the account {USER}.');
  assert.equal(restored.remediations[0].favorite,true);
  assert.equal(restored.remediations[0].enabled,false);
  assert.equal(restored.remediations[1].template,'User-authored text to preserve.');
});

test('saved default selections translate their template without overwriting investigation edits',()=>{
  const {templates,storage}=modules();
  const document=templates.emptyDocument();
  document.remediation.selected.push({id:'credential-access-1',tacticId:'credential-access',tacticName:'Credential Access',template:'Réinitialiser le mot de passe du compte {USER}.',generic:'',text:'Preserve my incident-specific action.'});
  const clean=storage.validate(document);
  assert.equal(clean.remediation.selected[0].template,'Reset the password for the account {USER}.');
  assert.equal(clean.remediation.selected[0].text,'Preserve my incident-specific action.');
});

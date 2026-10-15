const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const run = promisify(execFile);

(async () => {
  const root = path.resolve(__dirname, '..');
  const output = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(root, '../Notepad++++-SOC-Capture.zip');
  try {await fs.access(output); throw Error('Archive already exists: ' + output);}
  catch (error) {if (error.code !== 'ENOENT') throw error;}
  const staging = await fs.mkdtemp(path.join(os.tmpdir(), 'soc-extension-package-'));
  try {
    for (const item of ['manifest.json','index.html','favicon.ico','virus-total.png','servicenow.png','css','js','extension','tampermonkey','README.md','EXTENSION.md','JSON-IMPORT.md']) await fs.cp(path.join(root,item),path.join(staging,item),{recursive:true});
    await run('zip',['-q','-r',output,'.'],{cwd:staging});
    console.log(output);
  } finally {await fs.rm(staging,{recursive:true,force:true});}
})().catch(error=>{console.error(error.message);process.exitCode=1;});

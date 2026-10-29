// Run only in an isolated browser container. Never changes the host trust store.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import puppeteer from 'puppeteer-core';
import {browserOrigin} from '../../scripts/lib/browser-lab-origin.mjs';
import {startCapture} from '../scripts/browser-profile-capture.mjs';
assert.equal(process.platform,'linux');assert.equal(process.env.CVPN_DISPOSABLE_BROWSER_LAB,'1');
assert.deepEqual(Object.keys(os.networkInterfaces()).sort(),['lo']);
const output=process.argv[2];assert(path.isAbsolute(output));
const dir=await fs.mkdtemp('/tmp/meshpn-capture-'),origin=await browserOrigin(dir);
const db='sql:/home/node/.pki/nssdb';execFileSync('certutil',['-N','--empty-password','-d',db],{stdio:'pipe'});
let browser,server;const store=path.join(dir,'catalog');
const launch=async n=>puppeteer.launch({executablePath:'/usr/bin/chromium',headless:true,pipe:true,userDataDir:path.join(dir,'browser'+n),args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-first-run','--no-default-browser-check','--no-proxy-server']});
try{
 server=await startCapture({...origin.originTls,store,port:0});browser=await launch('untrusted');
 let page=await browser.newPage();await assert.rejects(page.goto(server.url),/CERT_AUTHORITY_INVALID/);assert.equal(server.catalog().length,0);await browser.close();browser=null;
 execFileSync('certutil',['-A','-d',db,'-n','meshpn-test','-t','C,,','-i',origin.caPath],{stdio:'pipe'});
 const profiles=[];let version;
 for(let i=0;i<3;i++){
  browser=await launch(i);version=await browser.version();page=await browser.newPage();
  const r=await page.goto(server.url);assert.equal(r.status(),200);assert.match(await page.content(),/Профиль браузера сохранён/);
  const rows=server.catalog();assert.equal(rows.length,i+1);assert.equal(rows.at(-1).status,'candidate',JSON.stringify(rows.at(-1)));
  await page.reload();assert.equal(server.catalog().length,i+1);
  const download=await page.evaluate(async u=>JSON.parse(await(await fetch(u)).text()),server.url+'/download/'+rows.at(-1).id);
  assert.deepEqual(download,rows.at(-1).profile);profiles.push(download);
  assert.equal(await page.evaluate(async u=>(await fetch(u.replace(/capture\/[a-f0-9]+/,'capture/bad'))).status,server.url),404);
  await browser.close();browser=null;
 }
 await server.close();server=await startCapture({...origin.originTls,store,port:0});assert.equal(server.catalog().length,3);
 await fs.mkdir(path.dirname(output),{recursive:true});await fs.writeFile(output,JSON.stringify({version,platform:process.platform,architecture:process.arch,conditions:'Headless Chromium, fresh process per sample, disposable private CA, no proxy, container loopback only. TLS fingerprint snapshot; not full browser equivalence.',certificateValidation:true,hostTrustStoreChanged:false,profiles},null,2));
 console.log(JSON.stringify({passed:true,version,captures:3,output}));
}finally{await browser?.close();await server?.close();}

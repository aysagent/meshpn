// UI from the firmware, real browser TLS. No TLS server/cert/trust store/Internet.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer-core';
import {parseFirstTlsClientHelloFromTcpBuf} from '../../scripts/lib/tls-clienthello-ja3.mjs';
import {deviceProfile} from '../scripts/browser-profile-capture.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_BROWSER_LAB,'1');assert.equal(process.platform,'linux');
assert.deepEqual(Object.keys(os.networkInterfaces()).sort(),['lo']);
const output=process.argv[2];assert(path.isAbsolute(output));await fs.mkdir(output,{recursive:true});
const source=await fs.readFile(new URL('../components/meshvpn_web/web_ui.h',import.meta.url),'utf8');
const lines=source.split('\n').filter(l=>l.startsWith('"')).map(l=>JSON.parse(l.endsWith(';')?l.slice(0,-1):l));
const captureJS=lines.find(l=>l.startsWith('let browserCaptureTicket='));assert(captureJS);
const load=lines.find(l=>l.startsWith('async function loadBrowserProfiles')).split("$('vpn-profile-import')")[0];
let state,listener,wire,profile;const sockets=new Set();let rawConnections=0,serverBytes=0,apiCalls=[];
const main=http.createServer(async(req,res)=>{
 res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store');
 if(req.url==='/api/vpn/profiles'){res.end(JSON.stringify({profiles:profile?[profile]:[]}));return;}
 if(req.url==='/api/vpn/capture'&&req.method==='POST'){
  let body='';for await(const b of req)body+=b;const q=JSON.parse(body);apiCalls.push(q.action);
  if(q.action==='start'){
   profile=null;state={ticket:1,state:'waiting',active:true};
   listener=net.createServer(s=>{
    rawConnections++;sockets.add(s);const write=s.write;s.write=function(data,...args){serverBytes+=Buffer.byteLength(data);return write.call(this,data,...args);};let prefix=Buffer.alloc(0);s.on('error',()=>{});s.on('close',()=>sockets.delete(s));
    s.on('data',b=>{prefix=Buffer.concat([prefix,b]);const parsed=parseFirstTlsClientHelloFromTcpBuf(prefix);
     if(parsed.ok){wire=prefix.subarray(0,parsed.bytesConsumed);profile=deviceProfile(wire,q.name).profile;assert(profile);state={ticket:1,state:'saved',active:false,saved:true,profile_id:profile.id,detail:'Profile saved'};s.destroy();listener.close();}
    });
   });await new Promise(r=>listener.listen(0,'127.0.0.1',r));state.url=`https://dongle.local:${listener.address().port}/capture`;
  }else assert.equal(q.ticket,1);
  res.end(JSON.stringify(state));return;
 }
 if(req.url!=='/'){res.statusCode=404;res.end('{}');return;}
 res.setHeader('content-type','text/html');
 res.end(`<!doctype html><title>Device admin capture test</title><input id="vpn-capture-name" value="Phone browser"><button id="vpn-capture-start">Capture</button><button id="vpn-capture-cancel">Cancel</button><p id="vpn-capture-status"></p><select id="vpn-profile"></select><p id="message"></p><script>
 const $=id=>document.getElementById(id);let vpnDirty=false,vpnRevision=0,browserProfileSelection=null;
 const message=m=>$('message').textContent=m;
 const run=fn=>async()=>{try{await fn();}catch(e){message('ERROR: '+e.message);}};
 const api=async(url,method='GET',body)=>{const r=await fetch(url,{method,headers:{'content-type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error(await r.text());return r.json();};
 ${load}${captureJS}</script>`);
});
let browser;
try{
 await new Promise(r=>main.listen(0,'127.0.0.1',r));
 browser=await puppeteer.launch({executablePath:'/usr/bin/chromium',headless:true,pipe:true,userDataDir:await fs.mkdtemp('/tmp/meshpn-local-browser-'),args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-first-run','--no-default-browser-check','--no-proxy-server','--host-resolver-rules=MAP dongle.local 127.0.0.1']});
 const page=await browser.newPage();let dialogs=0;page.on('dialog',d=>{dialogs++;void d.dismiss();});
 await page.goto(`http://dongle.local:${main.address().port}/`);
 assert.equal(await page.evaluate(()=>isSecureContext),false,'exercise ordinary HTTP device admin');
 await page.click('#vpn-capture-start');
 await page.waitForFunction(()=>document.getElementById('message').textContent.includes('Browser profile saved'),{timeout:15000});
 assert.equal(await page.$eval('#vpn-profile',el=>el.value),profile.id);assert.equal(dialogs,0);assert.equal(serverBytes,0);
 assert(apiCalls.includes('start')&&apiCalls.includes('poll'));
 // The foreground admin remains usable, no navigation to certificate error page.
 assert.equal(await page.title(),'Device admin capture test');
 await fs.writeFile(path.join(output,'hello.bin'),wire);await fs.writeFile(path.join(output,'profile.json'),JSON.stringify(profile,null,2));
 await fs.writeFile(path.join(output,'result.json'),JSON.stringify({version:await browser.version(),architecture:process.arch,ordinaryHttpAdmin:true,externalNetwork:false,certificateInstalled:false,dialogs,rawConnections,serverTlsBytes:serverBytes,selected:profile.id,apiCalls},null,2));
 console.log('On-device capture UI → hidden local TLS → saved selection: PASSED');
}finally{await browser?.close();for(const s of sockets)s.destroy();if(listener?.listening)await new Promise(r=>listener.close(r));main.closeAllConnections();await new Promise(r=>main.close(r));}

// UI acceptance only. RPC is a fixture: no systemctl, reboot or poweroff runs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {once} from 'node:events';
import net from 'node:net';
import puppeteer from 'puppeteer';
import {createAdmin} from '../server.mjs';
const state=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-device-browser-'));
const calls=[];let mode='combo-tls',jobs=[],power=null;
const capabilities={role:'client',nativeManaged:true,networkOwner:true,wifi:false,guardToggle:false,hostnameChange:false,observer:false,profileImport:false,vpnSettings:true,devicePower:true,transports:['boring-tls','combo-tls'],probes:[]};
const reservation=net.createServer();reservation.listen(0,'127.0.0.1');await once(reservation,'listening');const port=reservation.address().port;await new Promise(r=>reservation.close(r));
const app=await createAdmin({address:'127.0.0.1',subnet:'127.0.0.0/8',port,state,lab:true},{rpc:async(route,p)=>{
 if(route==='/settings')return{hostname:'mpn',adminUrl:'/',vpn:{role:'client',transport:mode,nativeManaged:true,address:'192.0.2.1',port:443,sni:'relay.example',serverName:'personal-cert.internal'},dns:{mode:'tunnel',upstreams:'fixture'},profiles:[],wifi:[],capabilities};
 if(route==='/status')return{metrics:{time:Date.now(),timezone:'UTC',temperatures:[],memory:{},uptimeSeconds:1,cpu:[],network:[]},device:{power},vpn:{ActiveState:'active',StatusText:'ready'},network:{ActiveState:'active'},guard:{active:true},wifi:{},jobs,capabilities,vpnSettingsRecovery:{pending:false}};
 if(route==='/operations')return{jobs};
 if(route==='/vpn/settings'){calls.push([route,p]);mode=p.transport;const job={id:'mode-'+calls.length,kind:'vpn-settings',status:'passed'};jobs=[job];return job;}
 if(route==='/device/power'){assert.equal(p.confirm,true);assert(['reboot','poweroff'].includes(p.action));calls.push([route,p]);power={action:p.action,delaySeconds:3};return{id:'power',kind:'device-'+p.action,status:'running'};}
 throw Error('unexpected_route');
}});
await app.auth.change('admin','browser fixture password');app.server.listen(port,'127.0.0.1');await once(app.server,'listening');
const origin='http://127.0.0.1:'+port;let browser;
try{
 const localChrome='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
 browser=await puppeteer.launch({headless:true,protocolTimeout:10000,...(fs.existsSync(localChrome)?{executablePath:localChrome}:{}),args:['--disable-background-networking','--disable-gpu','--no-proxy-server']});
 const page=await browser.newPage();page.setDefaultTimeout(10000);const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.setRequestInterception(true);page.on('request',r=>r.url().startsWith(origin+'/')?r.continue():r.abort());
 await page.goto(origin);await page.type('#login-password','browser fixture password');await page.$eval('#login-form',f=>f.requestSubmit());
 await page.waitForFunction(()=>!document.querySelector('#dashboard').hidden&&!document.querySelector('#vpn-transport').disabled);
 assert.deepEqual(await page.$$eval('#vpn-transport option',a=>a.map(e=>e.value)),['boring-tls','combo-tls']);
 await page.select('#vpn-transport','boring-tls');await new Promise(r=>setTimeout(r,3300));
 assert.equal(await page.$eval('#vpn-transport',e=>e.value),'boring-tls');
 await page.$eval('#vpn-form',f=>f.requestSubmit());
 await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('завершено'));
 assert.equal(calls[0][1].transport,'boring-tls');
 await page.waitForFunction(()=>!document.querySelector('[data-power]').disabled);
 for(const action of ['reboot','poweroff']){
  const before=calls.length;let question='';page.once('dialog',async d=>{question=d.message();await d.dismiss();});
  await page.click(`[data-power=${action}]`);await new Promise(r=>setTimeout(r,150));
  assert.match(question,action==='reboot'?/Перезагрузить/:/Выключить/);assert.equal(calls.length,before,'cancel must send no RPC');
 }
 for(const action of ['reboot','poweroff']){
  power=null;jobs=[];await page.reload();await page.waitForFunction(()=>!document.querySelector('#dashboard').hidden);
  page.once('dialog',d=>d.accept());await page.click(`[data-power=${action}]`);
  await page.waitForFunction(()=>document.querySelector('#device-power-status').textContent.includes('Команда принята'));
  assert.deepEqual(calls.at(-1),['/device/power',{action,confirm:true}]);
 }
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({status:'passed',browser:await browser.version(),checks:['transport selector retains choice across polls','transport sent with settings','reboot confirmation cancel sends no request','poweroff confirmation cancel sends no request','reboot accept sends confirmed request','poweroff accept sends confirmed request'],realPowerActions:0,hostNetworkChanged:false}));
}finally{if(browser)await browser.close();await app.close();fs.rmSync(state,{recursive:true,force:true});}

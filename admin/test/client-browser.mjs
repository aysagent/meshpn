// Actual UI interactions against a bounded broker fixture; no host networking changes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import net from 'node:net';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer';
import {createAdmin} from '../server.mjs';
const state=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-client-browser-'));
let guard=true,job=null;const calls=[];
const capabilities={role:'client',nativeManaged:true,networkOwner:true,wifi:false,guardToggle:true,hostnameChange:false,observer:true,profileImport:true,vpnSettings:true,transports:['combo-tls']};
const reservation=net.createServer();reservation.listen(0,'127.0.0.1');await once(reservation,'listening');const port=reservation.address().port;await new Promise(r=>reservation.close(r));
const app=await createAdmin({address:'127.0.0.1',subnet:'127.0.0.0/8',port,state,lab:true},{rpc:async(route,p)=>{
 if(route==='/settings')return{hostname:'mpn',adminUrl:'/',vpn:{role:'client',transport:'combo-tls',nativeManaged:true,address:'192.0.2.1',port:443,sni:'relay.example',serverName:'personal-cert.internal'},dns:{mode:'tunnel',upstreams:'fixture'},profiles:[],wifi:[],capabilities};
 if(route==='/status')return{metrics:{time:Date.now(),timezone:'UTC',temperatures:[],memory:{},uptimeSeconds:1,cpu:[],network:[]},vpn:{ActiveState:'active'},network:{ActiveState:'active'},guard:{active:guard},wifi:{},jobs:job?[job]:[],capabilities,vpnSettingsRecovery:{pending:false}};
 if(route==='/guard'){calls.push(p);assert.deepEqual(p,{enabled:false,confirmDirect:true});job={id:'guard-fixture',kind:'guard',status:'running'};return job;}
 throw Error('unexpected_route');
}});
await app.auth.change('admin','browser fixture password');app.server.listen(port,'127.0.0.1');await once(app.server,'listening');
const url='http://127.0.0.1:'+app.server.address().port;let browser;
try{
 browser=await puppeteer.launch({headless:true,protocolTimeout:10000,args:['--disable-background-networking','--no-proxy-server']});
 const page=await browser.newPage(),errors=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));
 await page.setRequestInterception(true);page.on('request',r=>r.url().startsWith(url+'/')?r.continue():r.abort());
 await page.goto(url+'/');
 await page.type('#login-password','browser fixture password');await page.$eval('#login-form',f=>f.requestSubmit());
 try{await page.waitForFunction(()=>document.querySelector('#vpn-transport').textContent==='combo-tls',{polling:100});}catch(e){console.error(JSON.stringify({errors,dom:await page.evaluate(()=>({message:document.querySelector('#message').textContent,login:document.querySelector('#login').hidden,transport:document.querySelector('#vpn-transport').textContent}))}));throw e;}
 assert.equal(await page.evaluate(()=>!!document.querySelector('#vpn-form select:disabled')),false);
 await page.evaluate(()=>document.querySelector('#guard-enabled').click());
 // Previously a polling refresh could undo a selection before Apply.
 await new Promise(r=>setTimeout(r,3400));assert.equal(await page.$eval('#guard-enabled',e=>e.checked),false);
 page.once('dialog',d=>d.accept());await page.evaluate(()=>document.querySelector('#guard-save').click());
 await page.waitForFunction(()=>document.querySelector('#operation-status').textContent.includes('очистка'),{polling:100});
 assert.equal(await page.$eval('#guard-save',e=>e.disabled),true);
 assert.equal(await page.$eval('[data-vpn="start"]',e=>e.disabled),true);
 guard=false;job={...job,status:'passed'};
 await page.waitForFunction(()=>document.querySelector('#guard-status').textContent==='Выключен'&&!document.querySelector('#guard-save').disabled,{polling:100});
 assert.deepEqual(calls,[{enabled:false,confirmDirect:true}]);assert.deepEqual(errors,[]);
 console.log(JSON.stringify({status:'passed',browser:await browser.version(),checks:['actual combo label','no misleading fixed transport selector','guard selection survives poll','confirmed direct mode','progress and serialized controls','completed guard state'],hostNetworkChanged:false}));
}catch(e){console.error(e.message);throw e;}finally{if(browser)await browser.close();await app.close();fs.rmSync(state,{recursive:true,force:true});}

// Browser acceptance of saved hidden-network choices; loopback fixture only.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import net from 'node:net';
import puppeteer from 'puppeteer';
import {createAdmin} from '../server.mjs';
const state=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-wifi-browser-'));
const profile={id:'remembered-id',ssid:'Saved <hidden>',security:'wpa2',priority:7,enabled:true,hidden:false,hasPassword:true};
const capabilities={role:'client',wifi:true,guardToggle:false,networkOwner:false,profileImport:false,observer:false,vpnSettings:false,hostnameChange:false,probes:[]};
let job=null;const saves=[];
const reservation=net.createServer();reservation.listen(0,'127.0.0.1');await once(reservation,'listening');const port=reservation.address().port;await new Promise(r=>reservation.close(r));
const app=await createAdmin({state,address:'127.0.0.1',subnet:'127.0.0.0/8',port,lab:true},{rpc:async(route,p)=>{
 if(route==='/settings')return{hostname:'mpn',adminUrl:'/',vpn:{role:'client',transport:'combo-tls'},dns:{mode:'tunnel',upstreams:'fixture'},profiles:[],wifi:[profile],capabilities};
 if(route==='/status')return{metrics:{time:Date.now(),timezone:'UTC',temperatures:[],memory:{},cpu:[],network:[],uptimeSeconds:1},vpn:{ActiveState:'active'},network:null,guard:{active:true},wifi:{},jobs:job?[job]:[],capabilities};
 if(route==='/wifi/scan'){job={id:'scan',kind:'wifi-scan',status:'passed',result:[{ssid:profile.ssid,source:'saved',savedId:profile.id,observed:false,security:'wpa2',signal:null}]};return job;}
 if(route==='/wifi/save'){saves.push(p);job={id:'save',kind:'wifi-save',status:'passed',result:[profile]};return job;}
 throw Error('unexpected_route');
}});
let browser;
try{
 await app.auth.change('admin','wifi fixture password');app.server.listen(port,'127.0.0.1');await once(app.server,'listening');
 const url='http://127.0.0.1:'+port;
 browser=await puppeteer.launch({headless:true,args:['--disable-background-networking','--no-proxy-server']});
 const page=await browser.newPage(),errors=[];page.setDefaultTimeout(15000);page.on('pageerror',e=>errors.push(e.message));
 await page.setRequestInterception(true);page.on('request',r=>r.url().startsWith(url+'/')?r.continue():r.abort());
 await page.goto(url);await page.type('#login-password','wifi fixture password');await page.$eval('#login-form',f=>f.requestSubmit());
 await page.waitForFunction(()=>!document.querySelector('#dashboard').hidden);
 assert.equal(await page.$eval('#wifi-hidden',e=>e.hidden),true);
 await page.click('#wifi-scan');
 await page.waitForFunction(()=>document.querySelector('#wifi-nearby').options.length===2);
 const label=await page.$eval('#wifi-nearby',e=>e.options[1].textContent);
 assert.match(label,/Saved <hidden>.*сохранённая.*пока не найдена/);assert.doesNotMatch(label,/null dBm/);
 await page.select('#wifi-nearby',profile.ssid);
 assert.equal(await page.$eval('#wifi-ssid',e=>e.value),profile.ssid);
 assert.equal(await page.$eval('#wifi-security',e=>e.value),'wpa2');
 assert.equal(await page.$eval('#wifi-priority',e=>Number(e.value)),7);
 assert.equal(await page.$eval('#wifi-password',e=>e.value),'');
 await page.$eval('#wifi-form',f=>f.requestSubmit());
 for(let i=0;i<30&&!saves.length;i++)await new Promise(r=>setTimeout(r,100));
 assert.deepEqual(saves,[{id:profile.id,ssid:profile.ssid,security:'wpa2',password:'',priority:7,enabled:true,hidden:false}]);
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({status:'passed',checks:['unseen saved SSID in scan options','availability label is honest','SSID treated as text','selection edits existing profile','empty password reuses stored secret','automatic hidden discovery has no manual toggle'],hostNetworkChanged:false}));
}finally{if(browser)await browser.close();await app.close();fs.rmSync(state,{recursive:true,force:true});}

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {wifiSuitability,PortalDecision,portalDns,portalUrl,portalPeer,readPortalState} from '../lib/captive.mjs';
import {CaptiveNetwork,captiveRules} from '../lib/captive-network.mjs';
import {sampleWifi,responders,runPortal} from '../usb-captive.mjs';
import {captiveUnit} from '../lib/captive-unit.mjs';
import {createAdmin} from '../server.mjs';
const tmp=t=>{const d=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-captive-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));return d;};
const req=(port,{host='probe.example',url='/',method='GET'}={})=>new Promise((resolve,reject)=>{const r=http.request({hostname:'127.0.0.1',port,path:url,method,headers:{host}},s=>{let body='';s.on('data',b=>body+=b);s.on('end',()=>resolve({status:s.statusCode,headers:s.headers,body}));});r.on('error',reject);r.end();});
export function question(type=1){const h=Buffer.alloc(12);h.writeUInt16BE(123,0);h.writeUInt16BE(256,2);h.writeUInt16BE(1,4);return Buffer.concat([h,Buffer.from([5,...Buffer.from('probe'),7,...Buffer.from('example'),0,0,type,0,1])]);}
test('Wi-Fi qualification uses association, usable IPv4 and main default route; unknown disables',()=>{
 const links=[{ifname:'wlan0',flags:['UP','LOWER_UP']}],addresses=[{ifname:'wlan0',addr_info:[{family:'inet',scope:'global',local:'192.168.1.8'}]}],routes=[{dev:'wlan0',dst:'default'}],wpa={wpa_state:'COMPLETED'};
 assert.equal(wifiSuitability(links,addresses,routes,wpa).state,'ready');
 assert.equal(wifiSuitability([],addresses,routes,wpa).state,'offline');
 assert.equal(wifiSuitability(links,[],routes,wpa).reason,'wifi_ipv4_pending');
 assert.equal(wifiSuitability(links,addresses,[],wpa).reason,'wifi_route_pending');
 assert.equal(wifiSuitability(links,addresses,[{dev:'tun0',dst:'default'}],wpa).state,'offline');
 assert.equal(wifiSuitability(links,addresses,routes,{wpa_state:'SCANNING'}).state,'offline');
 assert.equal(wifiSuitability(links,addresses,routes,{}).state,'unknown');
 const d=new PortalDecision();assert(!d.sample({state:'offline'}));assert(d.sample({state:'offline'}));assert(!d.sample({state:'unknown'}));assert(!d.sample({state:'offline'}));assert(!d.sample({state:'ready'}));
});
test('metadata errors do not pretend no Wi-Fi; missing interface is ordinary offline',async()=>{
 assert.equal((await sampleWifi(async()=>{throw Error('timeout');})).state,'unknown');
 let calls=0;assert.equal((await sampleWifi(async()=>{calls++;return{out:'[]'};})).state,'offline');assert.equal(calls,3);
});
test('bounded synthetic DNS A TTL zero, NODATA AAAA/SVCB/HTTPS, no upstream or malformed amplification',()=>{
 const a=portalDns(question(),true);assert.equal(a.readUInt16BE(6),1);assert.deepEqual([...a.subarray(-4)],[192,168,7,1]);assert.equal(a.readUInt32BE(a.length-10),0);
 for(const type of[28,64,65]){const a=portalDns(question(type),true);assert.equal(a.readUInt16BE(6),0);assert.equal(a.readUInt16BE(2)&15,0);}
 assert.equal(portalDns(question(),false).readUInt16BE(2)&15,2);assert.equal(portalDns(question(16),true).readUInt16BE(2)&15,5);
 assert.equal(portalDns(Buffer.alloc(2048),true),null);assert.equal(portalDns(Buffer.alloc(1),true),null);
 const compressed=question();compressed[12]=0xc0;assert.equal(portalDns(compressed,true).readUInt16BE(2)&15,1);
 for(let i=0;i<question().length;i++){const a=portalDns(question().subarray(0,i),true);if(a)assert.equal(a.readUInt16BE(2)&15,1);}
 assert(portalPeer('192.168.7.2'));assert(!portalPeer('192.168.7.1'));assert(!portalPeer('192.168.1.2'));assert(!portalPeer('::1'));
});
test('stale, future, writable or symlink status never opens redirect exception',t=>{
 const file=tmp(t)+'/captive.json',state={kind:'meshpn-usb-captive',active:true,reason:'wifi_not_associated',updatedAt:100};
 fs.writeFileSync(file,JSON.stringify(state),{mode:0o644});assert(readPortalState(file,200).active);assert(!readPortalState(file,10100).active);assert(!readPortalState(file,99).active);
 fs.chmodSync(file,0o666);assert(!readPortalState(file,200).active);fs.renameSync(file,file+'.real');fs.symlinkSync(file+'.real',file);assert(!readPortalState(file,200).active);
});
test('admin only redirects foreign-host GET/HEAD while portal fresh; API/password boundary preserved',async t=>{
 const dir=tmp(t),file=dir+'/captive.json';const app=await createAdmin({state:dir+'/auth',brokerSocket:dir+'/broker.sock',address:'127.0.0.1',subnet:'127.0.0.0/8',port:80,lab:true},{rpc:async()=>({hostname:'mpn'})});app.server.listen(0,'127.0.0.1');await once(app.server,'listening');t.after(()=>app.close());const port=app.server.address().port;
 assert.equal((await req(port)).status,403);fs.writeFileSync(file,JSON.stringify({kind:'meshpn-usb-captive',active:true,updatedAt:Date.now()}),{mode:0o644});
 for(const method of['GET','HEAD']){const r=await req(port,{url:'/generate_204',method});assert.equal(r.status,302);assert.equal(r.headers.location,portalUrl);assert.equal(r.headers['set-cookie'],undefined);}
 assert.equal((await req(port,{url:'/api/status'})).status,403);assert.equal((await req(port,{url:'/api/login',method:'POST'})).status,403);
 assert.equal((await req(port,{host:'mpn.local',url:'/api/status'})).status,401);assert.equal((await req(port,{host:'mpn.local'})).status,200);
 fs.unlinkSync(file);assert.equal((await req(port)).status,403);
});
test('real bounded UDP/TCP responders and fixed redirect, inactive failure, no POST',async t=>{
 let active=true;const r=await responders(()=>active,{address:'127.0.0.1',dnsPort:0,httpPort:0,peer:a=>a==='127.0.0.1'});t.after(()=>r.close());
 const port=r.web.address().port;assert.equal((await req(port)).headers.location,portalUrl);assert.equal((await req(port,{method:'POST'})).status,405);
 const udp=dgram.createSocket('udp4');t.after(()=>udp.close());udp.send(question(),r.udp.address().port,'127.0.0.1');const [a]=await once(udp,'message');assert.equal(a.readUInt16BE(6),1);
 const s=net.connect(r.tcp.address().port,'127.0.0.1');const bytes=[];s.on('data',b=>bytes.push(b));const done=once(s,'end');const h=Buffer.alloc(2);h.writeUInt16BE(question().length);s.write(h);s.write(question().subarray(0,8));s.write(question().subarray(8));await done;assert.equal(Buffer.concat(bytes).readUInt16BE(8),1);
 active=false;assert.equal((await req(port)).status,503);
});
test('network plan never touches host DNS/routing/HTTPS; cleanup uses exact translations',async()=>{
 const calls=[],n=new CaptiveNetwork(async(f,a)=>{calls.push([f,a]);return{code:a.includes('-C')?1:0,out:''};});await n.down();
 assert(calls.every(([,a])=>!a.includes('-F')&&!a.includes('OUTPUT')&&!a.includes('FORWARD')));
 assert.equal(calls.filter(([f])=>f.endsWith('/conntrack')).length,3);
 assert(calls.filter(([f])=>f.endsWith('/conntrack')).every(([,a])=>a.includes('--reply-port-src')&&a.includes('192.168.7.0/24')));
 assert(captiveRules.nat.every(r=>r.includes('usb0')&&!r.includes('443')));
 const bad=new CaptiveNetwork(async()=>({code:1,out:'',err:'Permission denied'}));await assert.rejects(bad.purge(),/portal_conntrack_cleanup/);
 const empty=new CaptiveNetwork(async()=>({code:1,out:'',err:'conntrack: 0 flow entries have been deleted.'}));await empty.purge();
 const unit=captiveUnit();assert(unit.includes('ExecStopPost='));assert(unit.includes('BindsTo=meshpn-admin-broker.service'));assert(!unit.includes('CAP_SYS_ADMIN'));
});
test('bind failure or lost status directory cannot prevent rule/socket cleanup',async t=>{
 const c={usbAddress:'192.168.7.1',usbInterface:'usb0',wifiInterface:'wlan0',socket:'/run/meshpn-admin/broker.sock'},calls=[];
 const network=Object.fromEntries(['prepare','inactive','down'].map(k=>[k,async()=>calls.push(k)]));
 const dir=tmp(t),stateFile=dir+'/captive.json';
 await assert.rejects(runPortal(c,{network,stateFile,listen:async()=>{throw Error('bind_failed');}}),/bind_failed/);assert.deepEqual(calls,['prepare','inactive','down']);calls.length=0;
 const app=await runPortal(c,{network,stateFile,sample:async()=>({state:'ready',reason:'wifi_ready'}),listen:async()=>({close:async()=>calls.push('close')})});
 await new Promise(r=>setImmediate(r));fs.rmSync(dir,{recursive:true});await assert.rejects(app.stop(),/ENOENT/);assert.deepEqual(calls,['prepare','inactive','close','down']);
});

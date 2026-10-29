#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import dgram from 'node:dgram';
import {once} from 'node:events';
import {pathToFileURL} from 'node:url';
import {need,atomic,readJson,safeError} from './lib/common.mjs';
import {command} from './lib/command.mjs';
import {CaptiveNetwork} from './lib/captive-network.mjs';
import {portalAddress,portalPorts,portalUrl,portalPeer,portalDns,wifiSuitability,PortalDecision} from './lib/captive.mjs';

export async function sampleWifi(run=command){
 try{
  const opts={timeout:2000,limit:65536};
  const [links,addresses,routes]=await Promise.all([['-j','link','show'],['-j','address','show'],['-j','-4','route','show','table','main']].map(args=>run('/usr/sbin/ip',args,opts).then(r=>JSON.parse(r.out))));
  // A missing/down interface is normal during cold boot, not a command error.
  const link=links.find(l=>l.ifname==='wlan0');
  if(!link?.flags?.includes('LOWER_UP'))return wifiSuitability(links,addresses,routes,null);
  const wpa=await run('/usr/sbin/wpa_cli',['-i','wlan0','-s','/run/meshpn-admin-captive','status'],opts);
  return wifiSuitability(links,addresses,routes,Object.fromEntries(wpa.out.trim().split('\n').map(line=>{const i=line.indexOf('=');return[line.slice(0,i),line.slice(i+1)];})));
 }catch{return{state:'unknown',reason:'wifi_status_unavailable'};}
}

// Independent unprivileged-port responders. Firewall confines them to USB DNAT;
// address checks and bounded budgets provide a second layer.
export async function responders(isActive,{address=portalAddress,dnsPort=portalPorts.dns,httpPort=portalPorts.http,peer=portalPeer}={}){
 let budget=128,window=performance.now();const sockets=new Set();
 const admit=ip=>{if(performance.now()-window>=1000){budget=128;window=performance.now();}return peer(ip)&&budget-->0;};
 const udp=dgram.createSocket('udp4');
 udp.on('message',(b,r)=>{if(!admit(r.address))return;const answer=portalDns(b,isActive());if(answer)udp.send(answer,r.port,r.address,()=>{});});
 const tcp=net.createServer(s=>{if(!admit(s.remoteAddress)){s.destroy();return;}sockets.add(s);s.on('close',()=>sockets.delete(s));s.on('error',()=>{});s.setTimeout(3000,()=>s.destroy());let bytes=Buffer.alloc(0),done=false;
  s.on('data',b=>{if(done)return;if(bytes.length+b.length>1234){s.destroy();return;}bytes=Buffer.concat([bytes,b]);if(bytes.length<2)return;const n=bytes.readUInt16BE(0);if(n<12||n>1232){s.destroy();return;}if(bytes.length<n+2)return;done=true;const answer=portalDns(bytes.subarray(2,n+2),isActive());if(!answer){s.destroy();return;}const head=Buffer.alloc(2);head.writeUInt16BE(answer.length);s.end(Buffer.concat([head,answer]));});
 });tcp.maxConnections=16;
 const web=http.createServer((req,res)=>{req.resume();res.setHeader('cache-control','no-store');res.setHeader('connection','close');res.setHeader('referrer-policy','no-referrer');res.setHeader('content-security-policy',"default-src 'none'; frame-ancestors 'none'");
  if(!admit(req.socket.remoteAddress)){res.writeHead(403);res.end();return;}
  if(!['GET','HEAD'].includes(req.method)){res.writeHead(405);res.end();return;}
  if(!isActive()){res.writeHead(503);res.end();return;}
  res.writeHead(302,{location:portalUrl});res.end();
 });web.maxConnections=16;web.headersTimeout=2000;web.requestTimeout=3000;web.keepAliveTimeout=1000;web.setTimeout(3000,s=>s.destroy());web.on('clientError',(_,s)=>s.destroy());
 const close=async()=>{for(const s of sockets)s.destroy();web.closeAllConnections();await Promise.all([new Promise(r=>{try{udp.close(r);}catch{r();}}),...([tcp,web].map(s=>new Promise(r=>{if(s.listening)s.close(r);else r();})))]);};
 try{udp.bind(dnsPort,address);await once(udp,'listening');tcp.listen(dnsPort,address);await once(tcp,'listening');web.listen(httpPort,address);await once(web,'listening');}catch(e){await close();throw e;}
 // Unexpected socket failure must terminate the owner and invoke ExecStopPost.
 for(const s of[udp,tcp,web])s.on('error',()=>{process.exitCode=1;process.kill(process.pid,'SIGTERM');});
 return{close,udp,tcp,web};
}

export async function runPortal(c,{network=new CaptiveNetwork(),sample=sampleWifi,interval=2500,stateFile=path.dirname(c.socket)+'/captive.json',listen=responders}={}){
 need(c.usbAddress===portalAddress&&c.usbInterface==='usb0'&&c.wifiInterface==='wlan0'&&c.socket==='/run/meshpn-admin/broker.sock','portal_config_scope');
 const state=stateFile;let active=false,stopping=false,listener,timer,pending=Promise.resolve();const decision=new PortalDecision();
 const publish=reason=>{atomic(state,{kind:'meshpn-usb-captive',active,reason,updatedAt:Date.now()},0o644);fs.chmodSync(state,0o644);};
 const stop=async()=>{
  if(stopping)return;stopping=true;clearTimeout(timer);await pending.catch(()=>{});active=false;
  // Losing the status directory must never prevent network/socket cleanup.
  let error;for(const action of[()=>publish('stopped'),()=>network.inactive(),()=>listener?.close(),()=>network.down()])try{await action();}catch(e){error??=e;}
  if(error)throw error;
 };
 try{
  publish('starting');await network.prepare();listener=await listen(()=>active);
  const step=async()=>{const wifi=await sample();const next=decision.sample(wifi);if(next&&!active){await network.active();await network.resetUsbDns();active=true;}else if(!next&&active){active=false;publish(wifi.reason);await network.inactive();}if(active)await network.reconcile();publish(wifi.reason);};
  const tick=()=>{pending=step();pending.then(()=>{if(!stopping)timer=setTimeout(tick,interval);},e=>{console.error(safeError(e));process.exitCode=1;void stop().catch(()=>{process.exitCode=1;});});};tick();
  return{stop};
 }catch(e){await stop();throw e;}
}
async function main(){
 need(process.platform==='linux'&&process.getuid()===0,'linux_root_required');
 const action=process.argv[2];need(['run','down'].includes(action),'portal_action');
 if(action==='down'){const file='/run/meshpn-admin/captive.json';try{if(fs.existsSync(path.dirname(file))){atomic(file,{kind:'meshpn-usb-captive',active:false,reason:'stopped',updatedAt:Date.now()},0o644);fs.chmodSync(file,0o644);}}finally{await new CaptiveNetwork().down();}return;}
 need(process.argv.length===4,'portal_config_argument');const c=readJson(process.argv[3]);
 const app=await runPortal(c);for(const signal of['SIGTERM','SIGINT'])process.once(signal,()=>void app.stop().catch(e=>{console.error(safeError(e));process.exitCode=1;}));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(safeError(e));process.exitCode=1;});

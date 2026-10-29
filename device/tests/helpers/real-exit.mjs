// Execute production runExit/bridge/transport with an in-memory TUN only.
// No Linux addon, routes, NAT, sysctl or external listeners are allowed.
import fs from 'node:fs';
import path from 'node:path';
import {fork} from 'node:child_process';
const original=new URL('../../../scripts/clean-vpn.js',import.meta.url);

export async function startRealExit(options) {
 const base=new URL('../../perf-results/',import.meta.url);fs.mkdirSync(base,{recursive:true});
 const dir=fs.mkdtempSync(path.join(base.pathname,'offline-real-exit-'));
 let source=fs.readFileSync(original,'utf8');
 const main="main().catch((e) => {\n  invokeCleanVpnEmergencyShutdown('main', e, 1);\n});";
 if(source.split(main).length!==2)throw Error('Exit entry point changed; audit offline adapter');
 source=source.replace(main,'');
 source=source.replace(/from (['"])([^'"]+)\1/g,(all,q,name)=>{
  const url=name.startsWith('.')?new URL(name,original).href:name;
  return `from ${JSON.stringify(url)}`;
 });
 source=source.replaceAll('import.meta.url',JSON.stringify(original.href));
 source+=`\n// Test infrastructure only. Production runExit, framing and lifecycle remain intact.
const opts=JSON.parse(process.env.MESHPN_EXIT_FIXTURE);
execFileSync=()=>{throw Error('Host command forbidden by offline exit fixture');};
findFreeTunName=()=> 'fixture0';
setupTunIp=()=>{};setupExitNat=()=>({tunName:'fixture0',ext:'fixture',prevIpForward:0});
teardownExitNat=()=>{};restoreExitSysctl=()=>{};
let readTun=null, writes=0;
openTunNative=()=>({name:'fixture0',tun:{startRead(cb){readTun=cb;},close(){readTun=null;},write(p){
 writes++;process.send?.({packet:Buffer.from(p).toString('base64')});
}}});
loadTlsServerCredentials=()=>({cert:fs.readFileSync(opts.cert),key:fs.readFileSync(opts.key)});
const listen=net.Server.prototype.listen;
net.Server.prototype.listen=function(...args){
 if(args[1]!=='127.0.0.1')throw Error('Non-loopback listener forbidden');
 this.once('listening',()=>process.send?.({ready:this.address().port}));return listen.apply(this,args);
};
const createUdp=dgram.createSocket;
dgram.createSocket=function(...args){const s=createUdp.apply(this,args),bind=s.bind;
 s.bind=function(...args){if(args[1]!=='127.0.0.1')throw Error('Non-loopback UDP forbidden');
 this.once('listening',()=>process.send?.({ready:this.address().port}));return bind.apply(this,args);};return s;};
process.on('message',m=>{if(m.inject&&readTun)readTun([Buffer.from(m.inject,'base64')]);});
process.on('disconnect',()=>process.exit(0));
await runExit({...opts,server:'127.0.0.1:0',keepAliveSec:opts.keepAliveSec??0,tlsRaw:true});
`;
 const file=path.join(dir,'exit.mjs');fs.writeFileSync(file,source);
 const child=fork(file,[],{execArgv:[],env:{...process.env,MESHPN_EXIT_FIXTURE:JSON.stringify(options)},stdio:['ignore','pipe','pipe','ipc']});
 let log='';child.stdout.on('data',b=>log+=b);child.stderr.on('data',b=>log+=b);
 const packets=[];
 child.on('message',m=>{if(m.packet){const p=Buffer.from(m.packet,'base64');packets.push(p);options.onPacket?.(p,child);}});
 const close=async()=>{if(child.exitCode===null&&child.signalCode===null){const exited=new Promise(r=>child.once('exit',r));child.kill('SIGTERM');const t=setTimeout(()=>child.kill('SIGKILL'),2000);await exited;clearTimeout(t);}fs.writeFileSync(path.join(dir,'exit.log'),log);};
 try {
  const port=await new Promise((resolve,reject)=>{
   const t=setTimeout(()=>reject(Error('Exit startup timeout: '+log)),10000);
   child.once('exit',code=>{clearTimeout(t);reject(Error('Exit failed '+code+': '+log));});
   child.on('message',m=>{if(m.ready){clearTimeout(t);resolve(m.ready);}});
  });
  return {port,packets,dir,child,close,log:()=>log,inject:p=>child.send({inject:p.toString('base64')})};
 }catch(e){await close();throw e;}
}

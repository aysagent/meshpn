import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { NativeClientManager } from './lib/native-client-manager.mjs';
import { readPeerDnsRegistry } from './lib/native-peer-dns.mjs';
const put=(p,v)=>fs.writeFileSync(p,typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(v),{mode:0o600});
const wait=async fn=>{for(let i=0;i<300;i++){if(fn())return;await delay(10);}throw Error('test_gate_timeout');};
async function fixture(t,applyConfig){
 const root=fs.mkdtempSync(fs.realpathSync(os.tmpdir())+'/cvpn-peer-dns-txn-');t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 put(root+'/key',Buffer.alloc(32,4));put(root+'/ca','fixture');put(root+'/config.json',{version:1,role:'exit',address:'192.0.2.1',port:3443,tun:'cvpn0',peers:[{ipv4:'10.99.0.2',secret_path:root+'/key'}]});
 const manager=new NativeClientManager({directory:root+'/state',validateConfig:async()=>{},applyConfig});
 await manager.init({configPath:root+'/config.json',endpoint:'192.0.2.1',serverName:'vpn.test',caPath:root+'/ca'});return{root,manager};
}
for(const [commit,readOld] of [[false,false],[true,false],[true,true]])test('cross-process DNS reader sees only committed registry: '+(readOld?'old inode replaced by commit':commit?'commit':'rollback'),{timeout:15000},async t=>{
 let release,entered=false;const gate=new Promise(r=>release=r);
 const {root,manager}=await fixture(t,async args=>{if(args.rollback)return;entered=true;await gate;if(!commit)throw Error('activation_failed');});
 const code=`import fs from 'node:fs';import {readPeerDnsRegistry} from ${JSON.stringify(new URL('./lib/native-peer-dns.mjs',import.meta.url).href)};
 const filename=process.argv[1],root=process.argv[2],open=fs.openSync,read=fs.readSync;let target=-1,paused=false;
 const wait=name=>{const end=Date.now()+10000;while(!fs.existsSync(root+'/'+name)){if(Date.now()>end)throw Error('child_gate_timeout');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,10);}};
 fs.openSync=function(p,...args){if(p===filename){fs.writeFileSync(root+'/before-open','1');wait('allow-open');target=open.call(fs,p,...args);return target;}return open.call(fs,p,...args);};
 fs.readSync=function(fd,...args){const n=read.call(fs,fd,...args);if(fd===target&&n>0&&!paused){paused=true;fs.writeFileSync(root+'/after-read','1');wait('allow-finish');}return n;};
 try{const r=readPeerDnsRegistry(filename);console.log(JSON.stringify({status:'published',revision:r.revision}));}catch(e){console.log(JSON.stringify({status:'refused',reason:e.message}));}`;
 const reader=spawn(process.execPath,['--input-type=module','-e',code,manager.registryPath,root],{stdio:['ignore','pipe','pipe']});t.after(()=>reader.kill('SIGKILL'));let out='',err='';reader.stdout.on('data',b=>out+=b);reader.stderr.on('data',b=>err+=b);const done=once(reader,'close');
 await wait(()=>fs.existsSync(root+'/before-open'));
 if(readOld){put(root+'/allow-open','1');await wait(()=>fs.existsSync(root+'/after-read'));}
 const mutation=manager.rename('client-2','renamed');mutation.catch(()=>{});await wait(()=>entered);
 assert.throws(()=>readPeerDnsRegistry(manager.registryPath),/transaction_pending/);
 put(root+'/allow-open','1');await wait(()=>fs.existsSync(root+'/after-read'));
 release();if(commit)await mutation;else await assert.rejects(mutation,/activation_failed/);
 put(root+'/allow-finish','1');const [exit]=await done;assert.equal(exit,0,err);const result=JSON.parse(out);
 if(commit&&!readOld)assert.deepEqual(result,{status:'published',revision:1});
 else {assert.equal(result.status,'refused','uncommitted snapshot escaped after rollback: '+out);assert.match(result.reason,/peer_dns_registry_replaced/);}
 assert.equal(readPeerDnsRegistry(manager.registryPath).revision,commit?1:0);
});

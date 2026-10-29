// Exercise the two-process WAN fixture on loopback before physical use.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {randomBytes} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
for(const version of ['2','1.1'])test(`two-process WAN fixture over HTTP ${version}`,{timeout:30000},async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-wan-fixture-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',dir+'/key','-out',dir+'/cert','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
 fs.writeFileSync(dir+'/psk',randomBytes(32),{mode:0o600});
 const listener=net.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');const port=listener.address().port;await new Promise(r=>listener.close(r));
 const common={version:1,address:'127.0.0.1',port,tun:'cvtest0',secret_path:dir+'/psk',http_version:version};
 for(const [role,extra]of [['exit',{cert:dir+'/cert',key:dir+'/key'}],['client',{ca:dir+'/cert',server_name:'localhost'}]])fs.writeFileSync(dir+'/'+role+'.json',JSON.stringify({...common,role,...extra}));
 const run=role=>{const p=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',dir+'/'+role+'.json','wan-'+role]);let output='';for(const s of [p.stdout,p.stderr])s.on('data',b=>output+=b);const timer=setTimeout(()=>p.kill('SIGKILL'),25000);t.after(()=>{clearTimeout(timer);p.kill('SIGKILL');});const done=once(p,'close').then(([code])=>{clearTimeout(timer);assert.equal(code,0,output);assert.match(output,/"status":"passed"/);assert.match(output,/"packets_each_direction":32/);});done.catch(()=>{});return{done,output:()=>output};};
 const exit=run('exit');for(let n=0;!exit.output().includes('WAN_LISTENING');n++){assert(n<100,exit.output());await delay(50);}
 const client=run('client');await Promise.all([client.done,exit.done]);
});

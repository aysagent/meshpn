import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';

for(const http_version of ['2','1.1'])test(`Android embedded boring client HTTP ${http_version}`,{timeout:90000},async t=>{
  const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-android-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const cert=path.join(dir,'ca.pem'),key=path.join(dir,'key.pem'),psk=path.join(dir,'psk');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
  fs.writeFileSync(psk,randomBytes(32),{mode:0o600});
  const listener=net.createServer().listen(0,'127.0.0.1');await once(listener,'listening');
  const port=listener.address().port;await new Promise(r=>listener.close(r));
  const common={version:1,http_version,address:'127.0.0.1',port,tun:'android',secret_path:psk};
  const client=path.join(dir,'client.json'),exit=path.join(dir,'exit.json');
  const config={...common,role:'client',server_name:'localhost',ca:cert,peer_ipv4:'10.99.0.2',dns:false,connection_mode:'persistent'};
  fs.writeFileSync(exit,JSON.stringify({...common,role:'exit',cert,key}));
  function run(extra=[]){
    const r=spawnSync(path.join(build,'android-adapter-test'),[path.join(build,'clean-vpn-engine-fixture'),client,exit,...extra],{encoding:'utf8',timeout:30000});
    assert.equal(r.status,0,`${r.error??''} signal=${r.signal??'none'}\n${r.stdout}\n${r.stderr}`);console.log(r.stdout.trim().split('\n').at(-1));
  }
  fs.writeFileSync(client,JSON.stringify(config));run();
  fs.writeFileSync(client,JSON.stringify({...config,server_name:'wrong.invalid'}));run(['reject']);
  const other=path.join(dir,'wrong-psk');fs.writeFileSync(other,randomBytes(32),{mode:0o600});
  fs.writeFileSync(client,JSON.stringify({...config,secret_path:other}));run(['reject']);
});

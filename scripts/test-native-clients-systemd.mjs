// Explicit disposable Linux container only. Real systemd/journal SIGHUP ack.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {NativeClientManager} from './lib/native-client-manager.mjs';
import {nativeClientService} from './lib/native-client-service.mjs';
const run=(c,a)=>execFileSync(c,a,{encoding:'utf8',timeout:20000,stdio:['ignore','pipe','pipe']});
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(process.env.CVPN_DISPOSABLE_CLIENTS_LAB,'1');
assert.equal(fs.readFileSync('/run/systemd/container','utf8').trim(),'podman');assert.deepEqual(JSON.parse(run('ip',['-j','link'])).map(x=>x.ifname),['lo']);
const engine=process.env.CVPN_ENGINE;assert.ok(engine&&path.isAbsolute(engine));
const root=fs.mkdtempSync(os.tmpdir()+'/cvpn-clients-systemd-'),configPath=root+'/exit.json',unit='cvpn-client-manager-test.service';let checks=0;
const check=(ok,name)=>{assert.ok(ok,name);checks++;console.log('CLIENT_SYSTEMD_CHECK '+name);};
const put=(p,b)=>fs.writeFileSync(p,typeof b==='string'||Buffer.isBuffer(b)?b:JSON.stringify(b),{mode:0o600});
try{
 run('ip',['link','set','lo','up']);run('ip',['tuntap','add','dev','cvtest0','mode','tun']);run('ip',['address','add','10.99.0.1/24','dev','cvtest0']);run('ip',['link','set','cvtest0','up']);
 run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',root+'/key.pem','-out',root+'/cert.pem','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost']);put(root+'/psk',randomBytes(32));put(configPath,{version:1,role:'exit',address:'127.0.0.1',port:3443,tun:'cvtest0',cert:root+'/cert.pem',key:root+'/key.pem',peers:[{ipv4:'10.99.0.2',secret_path:root+'/psk'}]});
 run('systemd-run',['--unit='+unit,'--property=Type=notify','--property=RuntimeMaxSec=180','--property=Restart=no',engine,'--config',configPath,'--service']);
 const pid=()=>run('systemctl',['show',unit,'-p','MainPID','--value']).trim(),original=pid();check(+original>0,'native systemd exit ready');
 const service=nativeClientService({engine,unit,directory:root+'/state'});await service.preflight();const m=new NativeClientManager({directory:root+'/state',...service});
 await m.init({configPath,endpoint:'127.0.0.1',serverName:'localhost',caPath:root+'/cert.pem',management:{engine,unit}});
 const added=await m.add('laptop');check(added.applied&&added.clients.find(p=>p.name==='laptop').ipv4==='10.99.0.3','add acknowledged via real journal');check(pid()===original,'add preserves exit PID');
 const key=(await m.export('laptop')).files.psk;await m.rotate('laptop');check((await m.export('laptop')).files.psk!==key&&pid()===original,'rotate acknowledged without restart');
 await m.revoke('client-2');check(JSON.parse(fs.readFileSync(configPath)).peers.length===1,'revoke changes running peer table');
 let once=true;const failing=new NativeClientManager({directory:root+'/state',...service,applyConfig:async a=>{await service.applyConfig(a);if(once){once=false;throw Error('post_apply_failure');}}});const before=fs.readFileSync(configPath);
 await assert.rejects(failing.add('rollback'),/post_apply_failure/);check(fs.readFileSync(configPath).equals(before)&&pid()===original,'successful reload followed by failure rolls back and reloads previous config');
 const cli=new URL('./clean-vpn-native-clients.mjs',import.meta.url).pathname;
 const result=JSON.parse(run(process.execPath,[cli,'add','phone','--directory='+root+'/state']));check(result.applied&&result.clients.some(p=>p.name==='phone'),'CLI restores saved engine/unit without repeated flags');
 await m.revoke('laptop');await m.revoke('phone');check(JSON.parse(fs.readFileSync(configPath)).peers.length===0&&pid()===original,'deny all without stopping exit');
 const journal=run('journalctl',['-u',unit,'--no-pager','-o','cat']);check((journal.match(/"event":"peer_reload"/g)??[]).length>=8,'reload events present');
 console.log(JSON.stringify({kind:'native-client-manager-systemd',status:'passed',checks,scope:'disposable netns; real TUN/systemd/journal; no host change; peer packet load tested separately'}));
}finally{
 try{run('systemctl',['stop',unit]);}catch{}try{run('systemctl',['reset-failed',unit]);}catch{}try{run('ip',['link','delete','cvtest0']);}catch{}fs.rmSync(root,{recursive:true,force:true});
}

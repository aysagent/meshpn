// Fresh disposable container only: real root broker and unprivileged web.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {NativeClientManager} from '../../scripts/lib/native-client-manager.mjs';
import {nativeClientService} from '../../scripts/lib/native-client-service.mjs';
const run=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:30000,stdio:['ignore','pipe','pipe']});
assert.equal(process.env.CVPN_DISPOSABLE_EXIT_ADMIN,'1');assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(fs.readFileSync('/run/systemd/container','utf8').trim(),'podman');assert.deepEqual(JSON.parse(run('ip',['-j','link'])).map(l=>l.ifname),['lo']);
const dir='/opt/cvpn-exit-admin-fixture',state='/var/lib/cvpn-exit-clients-fixture',engine='/usr/local/bin/peer-reload-engine',unit='cvpn-admin-exit-test.service',configPath=dir+'/engine.json';const put=(p,b)=>fs.writeFileSync(p,typeof b==='string'||Buffer.isBuffer(b)?b:JSON.stringify(b),{mode:0o600});
const combo=process.env.CVPN_EXIT_ADMIN_TRANSPORT==='combo-tls';
const installer=new URL('../exit-install.mjs',import.meta.url).pathname;let installed=false,checks=0,cookie='',csrf='';
const check=(v,s)=>{assert.ok(v,s);checks++;console.log('EXIT_ADMIN_CHECK '+s);};
const url='http://127.0.0.1:18880';
async function api(route,data){const r=await fetch(url+route,{method:data?'POST':'GET',headers:{...(cookie?{cookie}:{}),...(data?{'content-type':'application/json',origin:url,'x-csrf-token':csrf}:{})},...(data?{body:JSON.stringify(data)}:{}),signal:AbortSignal.timeout(5000)});if(r.headers.get('set-cookie'))cookie=r.headers.get('set-cookie').split(';')[0];const body=await r.json();assert.equal(r.status,200,JSON.stringify(body));if(body.csrf)csrf=body.csrf;return body;}
async function job(route,body){const started=await api(route,body);for(let i=0;i<100;i++){const status=await api('/api/status'),j=status.jobs.find(x=>x.id===started.id);if(j?.status!=='running'){assert.equal(j?.status,'passed',JSON.stringify(j));return j;}await delay(100);}throw Error('job_timeout');}
try{
 fs.mkdirSync(dir,{mode:0o700});run('ip',['link','set','lo','up']);run('ip',['tuntap','add','dev','cvtest0','mode','tun']);run('ip',['address','add','10.99.0.1/24','dev','cvtest0']);run('ip',['link','set','cvtest0','up']);
 run('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',dir+'/key.pem','-out',dir+'/cert.pem','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost']);put(dir+'/psk',randomBytes(32));put(configPath,{version:1,role:'exit',address:'127.0.0.1',port:3443,tun:'cvtest0',cert:dir+'/cert.pem',key:dir+'/key.pem',peers:[{ipv4:'10.99.0.2',secret_path:dir+'/psk'}]});
 if(combo){const packet=JSON.parse(fs.readFileSync(configPath));fs.mkdirSync('/var/lib/cvpn-admin-replay',{mode:0o700});put(dir+'/relay.psk',randomBytes(32));put(configPath,{version:1,transport:'combo-tls',role:'exit',boring:packet,transparent:{version:1,transport:'transparent-tls',role:'exit',public_name:'relay.example',listen:{ipv4:'127.0.0.1',port:3443},peers:[{id:'initial',secret_path:dir+'/relay.psk'}],destinations:[{ipv4:'127.0.0.1',port:33445}],replay_directory:'/var/lib/cvpn-admin-replay'}});run(engine,['--init-transparent-replay',configPath]);}
 run('systemd-run',['--unit='+unit,'--property=Type=notify','--property=RuntimeMaxSec=300','--property=CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE',engine,'--config',configPath,'--service']);const pid=run('systemctl',['show',unit,'-p','MainPID','--value']).trim();
 const manager=new NativeClientManager({directory:state,...nativeClientService({engine,unit,directory:state})});await manager.init({configPath,endpoint:'127.0.0.1',serverName:'localhost',caPath:dir+'/cert.pem',management:{engine,unit},...(combo?{relayMap:{'10.99.0.2':'initial'}}:{})});
 run(process.execPath,[installer,'--apply','--name=lab','--directory='+state]);installed=true;
 let ready=false;for(let i=0;i<80;i++){try{ready=(await fetch(url,{signal:AbortSignal.timeout(1000)})).status===200;}catch{}if(ready)break;await delay(100);}check(ready,'localhost frontend responds');
 await api('/api/login',{password:'admin'});const password='night-'+randomBytes(16).toString('hex');await api('/api/password',{oldPassword:'admin',newPassword:password});await api('/api/login',{password});check((await api('/api/status')).capabilities.clients,'exit clients capability');
 await job('/api/clients/add',{name:'laptop'});check((await api('/api/clients')).clients.some(c=>c.name==='laptop'&&c.ipv4==='10.99.0.3'),'unprivileged UI to root broker to native reload');
 const first=await api('/api/clients/export',{name:'laptop'});check(Buffer.from(first.files.psk,'base64').length===32,'explicit credential export');
 await job('/api/clients/rotate',{name:'laptop',confirm:true});const rotated=await api('/api/clients/export',{name:'laptop'});check(first.files.psk!==rotated.files.psk,'rotation through real broker');
 await job('/api/clients/revoke',{name:'laptop',confirm:true});check((await api('/api/clients')).clients.find(c=>c.name==='laptop').revoked,'revocation through real broker');
 check(run('systemctl',['show',unit,'-p','MainPID','--value']).trim()===pid,'VPN PID unchanged by installer or administration');
 const webPid=run('systemctl',['show','meshpn-exit-lab-web.service','-p','MainPID','--value']).trim(),webStatus=fs.readFileSync('/proc/'+webPid+'/status','utf8');check(!/^Uid:\s+0\s/m.test(webStatus)&&/^CapEff:\s+0+$/m.test(webStatus),'frontend unprivileged and zero capabilities');
 run(process.execPath,[installer,'--remove','--name=lab']);installed=false;check(run('systemctl',['show',unit,'-p','MainPID','--value']).trim()===pid,'remove touches only admin services');
 console.log(JSON.stringify({kind:'exit-admin-systemd',status:'passed',checks,transport:combo?'combo-tls':'boring-tls',scope:'real systemd, broker, web, native exit; disposable container; no physical deployment'}));
}finally{if(installed)try{run(process.execPath,[installer,'--remove','--name=lab']);}catch{}try{run('systemctl',['stop',unit]);}catch{}try{run('ip',['link','delete','cvtest0']);}catch{}}

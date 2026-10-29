#!/usr/bin/env node
// Explicit rootful Linux container lab. No physical interfaces, host firewall,
// host DNS or public port publishing. Uses private uniquely named resources.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {createRuntimeConfig} from './clean-vpn-native-runtime-config.mjs';
const cli=JSON.parse(process.env.CVPN_CONTAINER_COMMAND??'["podman"]');
const compose=JSON.parse(process.env.CVPN_COMPOSE_COMMAND??'["podman-compose"]');
const image=process.env.CVPN_MANAGED_IMAGE,webImage=process.env.CVPN_ADMIN_IMAGE;
assert.ok(image&&webImage,'managed_and_admin_images_required');assert.ok(cli.every(v=>typeof v==='string')&&compose.every(v=>typeof v==='string'));
const reportFile=path.resolve(process.argv[2]??'');assert.ok(process.argv[2]&&!fs.existsSync(reportFile),'new_report_required');
const tag='cvpnmanaged-'+randomBytes(5).toString('hex'),net=tag+'-net',temp=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),tag)));
const p=(args,input)=>execFileSync(cli[0],[...cli.slice(1),...args],{encoding:'utf8',timeout:60000,maxBuffer:2*1024*1024,input});
const e=(name,...args)=>p(['exec',name,...args]);const projects=[],volumes=[],helpers=[];let netCreated=false;const checks=[];
const record=label=>{checks.push(label);console.log('MANAGED_COMPOSE='+label);};
const file=path.resolve('scripts/containers/native-managed.compose.yml');
const co=(env,args)=>execFileSync(compose[0],[...compose.slice(1),'-f',file,...args],{encoding:'utf8',timeout:120000,maxBuffer:2*1024*1024,env:{...process.env,...env}});
async function wait(fn){let last;for(let i=0;i<35;i++){try{return fn();}catch(e){last=e;}await delay(1000);}throw last;}
const report={schema:1,kind:'native-managed-compose-lab',status:'running',checks,scope:'internal bridge; real namespace runtime and HTTP admin; no physical hosts or reboot'};
try{
 const parent=p(['run','--rm','--network=host','--entrypoint=readlink',image,'/proc/self/ns/net']).trim();assert.match(parent,/^net:\[\d+\]$/);
 p(['network','create','--internal','--subnet=10.77.91.0/24',net]);netCreated=true;
 const bundle=temp+'/bundle';createRuntimeConfig({directory:bundle,mode:'container',endpoint:'10.77.91.2',exitAddress:'10.77.91.2',serverName:'runtime.test',clients:1,days:2,profile:fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json')});
 for(const [role,source,ip,port]of[['exit','exit','10.77.91.2',18181],['client','client-1','10.77.91.3',18182]]){
  const config=tag+'-'+role+'-config',web=tag+'-'+role+'-web';
  const prepare=['scripts/clean-vpn-native-managed-prepare.mjs','--engine='+path.basename(cli[0]),'--image='+image,'--source='+bundle+'/'+source,'--config-volume='+config,'--web-volume='+web,'--web-port='+port,'--capture-port='+(port+1000)];
  if(role==='exit')prepare.push('--ca='+bundle+'/authority/ca.pem','--profile='+path.resolve('fixtures/native-tls-profiles/chromium-156-bounded-cold.json'),'--clients-endpoint=10.77.91.2','--server-name=runtime.test');
  if(cli.length>1){assert.equal(cli.length,3);assert.equal(cli[1],'--connection');prepare.push('--connection='+cli[2]);}
  execFileSync(process.execPath,prepare,{encoding:'utf8',timeout:60000});volumes.push(config,web);
  const env={COMPOSE_PROJECT_NAME:tag+'-'+role,CVPN_MANAGED_IMAGE:image,CVPN_ADMIN_IMAGE:webImage,CVPN_PARENT_NETNS:parent,CVPN_CONFIG_VOLUME:config,CVPN_WEB_VOLUME:web,CVPN_CONTAINER_IP:ip,CVPN_UPLINK_NETWORK:net,MPN_ADMIN_GID:'1000',MPN_ADMIN_UID:'1000',CVPN_CLIENTS_DIRECTORY:role==='exit'?'/config/clients':''};
  projects.push(env);co(env,['up','-d']);
 }
 const names=projects.map(env=>Object.fromEntries([['vpn','vpn'],['web','admin']].map(([key,service])=>{const ids=p(['ps','-a','-q','--filter','label=com.docker.compose.project='+env.COMPOSE_PROJECT_NAME,'--filter','label=com.docker.compose.service='+service]).trim().split('\n');assert.equal(ids.length,1);assert.ok(ids[0]);return[key,ids[0]];})));
 const rpc=(index,route,data={})=>JSON.parse(e(names[index].vpn,'node','--input-type=module','-e',`import http from 'node:http';const q=http.request({socketPath:'/run/meshpn-admin/broker.sock',method:'POST',path:${JSON.stringify(route)},headers:{'content-type':'application/json'}},r=>{let s='';r.on('data',b=>s+=b);r.on('end',()=>{if(r.statusCode!==200)process.exitCode=1;console.log(s);});});q.on('error',()=>process.exit(1));q.end(${JSON.stringify(JSON.stringify(data))});`));
 for(let i=0;i<2;i++)await wait(()=>assert.equal(rpc(i,'/status').vpn.ActiveState,'active'));record('compose-pair-supervised-engines-active');
 // Local origin and DNS fixture, confined to exit's own namespace.
 const server=`const net=require('node:net'),dgram=require('node:dgram');net.createServer(s=>s.pipe(s)).listen(8080,'0.0.0.0');const d=dgram.createSocket('udp4');d.on('message',(q,r)=>{const b=Buffer.from(q);b.writeUInt16BE(0x8180,2);b.writeUInt16BE(1,6);d.send(Buffer.concat([b,Buffer.from('c00c000100010000000100040a630001','hex')]),r.port,r.address);});d.bind(5353,'0.0.0.0');`;
 const origin=tag+'-origin';p(['run','-d','--name',origin,'--network',net,'--ip=10.77.91.4','--cap-drop=ALL','--cap-add=NET_ADMIN','--no-healthcheck','--entrypoint=sh',image,'-ec','ip addr add 198.18.0.80/32 dev lo; exec node -e '+"'"+server.replaceAll("'","'\\''")+"'"]);helpers.push(origin);e(names[0].vpn,'ip','route','add','198.18.0.80/32','via','10.77.91.4','dev','eth0');
 for(const serverIp of['1.1.1.1','8.8.8.8'])e(names[0].vpn,'iptables-nft','-t','nat','-A','PREROUTING','-i','cvpn0','-d',serverIp,'-p','udp','--dport','53','-j','DNAT','--to-destination','10.77.91.4:5353');
 // Exit runtime INPUT accepts loopback/TUN according to its existing policy.
 const echo=()=>e(names[1].vpn,'timeout','6s','node','-e',"const s=require('node:net').connect(8080,'198.18.0.80',()=>s.write('managed-packet'));s.setTimeout(4000,()=>process.exit(2));s.on('error',()=>process.exit(3));s.on('data',b=>{if(b.toString()!=='managed-packet')process.exit(4);console.log('PACKET_OK');s.destroy();});");
 await wait(()=>assert.match(echo(),/PACKET_OK/));record('real-tun-authenticated-packet-roundtrip');
 const exitPid=rpc(0,'/status').vpn.MainPID;const job=rpc(0,'/clients/add',{name:'laptop'});await wait(()=>assert.equal(rpc(0,'/status').jobs.find(j=>j.id===job.id)?.status,'passed'));const clients=rpc(0,'/clients');assert.ok(clients.clients.some(c=>c.name==='laptop'&&c.ipv4==='10.99.0.3'));assert.equal(rpc(0,'/status').vpn.MainPID,exitPid);assert.match(echo(),/PACKET_OK/);const revoked=rpc(0,'/clients/revoke',{name:'laptop'});await wait(()=>assert.equal(rpc(0,'/status').jobs.find(j=>j.id===revoked.id)?.status,'passed'));assert.equal(rpc(0,'/status').vpn.MainPID,exitPid);assert.match(echo(),/PACKET_OK/);record('client-add-revoke-reload-without-existing-client-interruption');
 // HTTP API uses auth + password change + CSRF; requests stay on VM loopback.
 const httpCheck=String.raw`const http=require('node:http');let cookie='',csrf='';const port=Number(process.argv[1]);async function req(route,data){return new Promise((ok,no)=>{const headers={host:'127.0.0.1:'+port,origin:'http://127.0.0.1:'+port,cookie};if(data!==undefined){headers['content-type']='application/json';headers['x-csrf-token']=csrf;}const q=http.request({host:'127.0.0.1',port,path:'/api/'+route,method:data===undefined?'GET':'POST',headers},r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>{if(r.headers['set-cookie'])cookie=r.headers['set-cookie'][0].split(';')[0];const x=JSON.parse(b);if(r.statusCode!==200)return no(Error(x.error));if(x.csrf)csrf=x.csrf;ok(x);});});q.on('error',no);q.end(data===undefined?undefined:JSON.stringify(data));});}(async()=>{await req('login',{password:'admin'});await req('password',{oldPassword:'admin',newPassword:'managed-test-only-20261030'});await req('login',{password:'managed-test-only-20261030'});const s=await req('status');if(!s.capabilities.containerManaged)throw Error('wrong_broker');const capture=await req('capture/start',{browser:'Node.js',version:process.versions.node,platform:'Linux',architecture:process.arch,extensionOrder:'fixed',echMode:'disabled',padding:'exact'});const url=new URL(capture.url);if(url.hostname!=='localhost')throw Error('capture_authority');await new Promise((ok,no)=>{const h=require('node:http2').connect('https://127.0.0.1:'+url.port,{servername:'localhost',ca:require('node:fs').readFileSync('/var/lib/meshpn-admin-web/capture.pem')});h.on('error',no);const q=h.request({':path':url.pathname,':authority':url.host});let bytes=0;q.on('data',b=>bytes+=b.length);q.on('error',no);q.on('end',()=>{h.close();bytes>0?ok():no(Error('capture_body'));});q.end();});await req('capture/stop',{});console.log('AUTHENTICATED_ADMIN_OK');})().catch(e=>{console.error(e.message);process.exit(1);});`;
 for(let i=0;i<2;i++){await wait(()=>assert.match(e(names[i].web,'node','-e',httpCheck,String(18181+i)),/AUTHENTICATED_ADMIN_OK/));}record('both-roles-http-admin-auth-and-verified-TLS-browser-capture');
 const before=rpc(1,'/status').vpn.MainPID;rpc(1,'/vpn/action',{action:'stop'});await wait(()=>assert.equal(rpc(1,'/status').vpn.ActiveState,'inactive'));
 assert.throws(echo);assert.match(e(names[1].vpn,'iptables-nft-save'),/CVPN_R_/);record('stop-retains-guard-no-packet-forwarding');
 rpc(1,'/vpn/action',{action:'start'});await wait(()=>assert.match(echo(),/PACKET_OK/));assert.notEqual(rpc(1,'/status').vpn.MainPID,before);record('start-restores-packet-path');
 const crashed=rpc(1,'/status').vpn.MainPID;e(names[1].vpn,'kill','-KILL',String(crashed));await wait(()=>{assert.notEqual(rpc(1,'/status').vpn.MainPID,crashed);assert.match(echo(),/PACKET_OK/);});record('engine-sigkill-auto-recovery');
 report.status='passed';report.images=[image,webImage].map(name=>{const i=JSON.parse(p(['image','inspect',name]))[0];return{name,id:i.Id,architecture:i.Architecture,size:i.Size};});
}catch(error){report.status='failed';report.error=String(error.message).slice(0,2000);report.logs=[];for(const env of projects)try{for(const id of p(['ps','-a','-q','--filter','label=com.docker.compose.project='+env.COMPOSE_PROJECT_NAME]).trim().split('\n').filter(Boolean))report.logs.push({id,log:p(['logs','--tail','30',id]).replace(/^.*(?:secret|password|psk|bearer|authorization).*$/gim,'[sensitive line omitted]')});}catch{}throw error;}finally{
 const errors=[];for(const env of projects.reverse())try{co(env,['down','--volumes']);}catch(e){errors.push(e.message);}
 for(const name of helpers.reverse())try{p(['rm','-f',name]);}catch(e){errors.push(e.message);}
 for(const name of volumes.reverse())try{p(['volume','rm',name]);}catch(e){errors.push(e.message);}
 if(netCreated)try{p(['network','rm',net]);}catch(e){errors.push(e.message);}
 fs.rmSync(temp,{recursive:true,force:true});report.cleanupErrors=errors;fs.writeFileSync(reportFile,JSON.stringify(report,null,2)+'\n');if(errors.length)process.exitCode=1;
}

#!/usr/bin/env node
// Import ONE role bundle into new container volumes. No runtime start, network
// creation, host services, or arbitrary mounts. Existing volumes are refused.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {parseArgs} from 'node:util';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
const {values:v}=parseArgs({options:{'private-peer-dns':{type:'boolean'},...Object.fromEntries(['engine','connection','image','source','config-volume','web-volume','web-port','capture-port','uid','gid','ca','profile','clients-endpoint','server-name'].map(k=>[k,{type:'string'}]))}});
const engine=v.engine??'podman';assert.ok(['podman','docker'].includes(engine),'container_engine');
const cli=v.connection?[engine,'--connection',v.connection]:[engine];if(v.connection){assert.equal(engine,'podman');assert.match(v.connection,/^[a-zA-Z0-9_.-]+$/);}
assert.ok(v.image&&!v.image.startsWith('-')&&!/[\r\n\0]/.test(v.image),'image_required');
for(const k of ['config-volume','web-volume'])assert.match(v[k]??'',/^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,63}$/,'volume_name');assert.notEqual(v['config-volume'],v['web-volume']);
const source=path.resolve(v.source??'');assert.ok(v.source&&fs.lstatSync(source).isDirectory()&&!fs.lstatSync(source).isSymbolicLink(),'role_directory');
const number=(key,fallback,max)=>{const n=Number(v[key]??fallback);assert.ok(Number.isInteger(n)&&n>=1&&n<=max,key);return n;};
const uid=number('uid',1000,65535),gid=number('gid',1000,65535),port=number('web-port',8080,65535),capture=number('capture-port',18443,65535);assert.notEqual(port,capture);
const p=(args)=>execFileSync(cli[0],[...cli.slice(1),...args],{encoding:'utf8',timeout:60000,maxBuffer:2*1024*1024,stdio:['ignore','pipe','pipe']});
const existing=p(['volume','ls','--format','{{.Name}}']).trim().split('\n');for(const key of ['config-volume','web-volume'])assert.ok(!existing.includes(v[key]),'new_volume_required');
const read=name=>{assert.match(name,/^[a-zA-Z0-9_.-]{1,128}$/,'flat_bundle_files_required');const fd=fs.openSync(path.join(source,name),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=65536,'bounded_regular_file');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}};
const config=JSON.parse(read('engine.json')),role=config.role;assert.ok(['client','exit'].includes(role),'bundle_role');
if(v['private-peer-dns']){assert.equal(role,'exit','private_peer_dns_exit_only');assert.ok(v['clients-endpoint'],'private_dns_registry_required');const packet=config.transport==='combo-tls'?config.boring:config;packet.private_peer_dns=true;}
const files=new Set(['engine.json']);
function refs(value){if(!value||typeof value!=='object')return;for(const[k,x]of Object.entries(value)){if(['secret_path','key','cert','ca','tls_profile_path'].includes(k)){assert.equal(typeof x,'string');assert.match(x,/^\/config\/[a-zA-Z0-9_.-]{1,128}$/,'container_bundle_paths_required');files.add(x.slice(8));}else refs(x);}}
refs(config);const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-managed-import-')),helper='cvpnmanaged-import-'+randomBytes(6).toString('hex');let started=false;const created=[];
try{
 fs.mkdirSync(temp+'/role',{mode:0o700});for(const name of files)fs.writeFileSync(temp+'/role/'+name,name==='engine.json'?JSON.stringify(config):read(name),{mode:0o600});
 for(const [option,name]of [['ca','ca.pem'],['profile','profile.json']])if(v[option]){const fd=fs.openSync(v[option],fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=16384,'bounded_public_material');const data=fs.readFileSync(fd),dest=temp+'/role/'+name;if(fs.existsSync(dest))assert.ok(fs.readFileSync(dest).equals(data),'bundle_material_conflict');else fs.writeFileSync(dest,data,{mode:0o600});}finally{fs.closeSync(fd);}}
 const web={address:'127.0.0.1',subnet:'127.0.0.0/8',port,capturePort:capture,captureHostname:'localhost',container:true,loopbackProxy:true,state:'/var/lib/meshpn-admin-web',brokerSocket:'/run/meshpn-admin/broker.sock'};fs.writeFileSync(temp+'/web.json',JSON.stringify(web),{mode:0o600});
 for(const key of ['config-volume','web-volume']){p(['volume','create',v[key]]);created.push(v[key]);}
 p(['run','-d','--name',helper,'--network=none','--no-healthcheck','--cap-drop=ALL','--cap-add=CHOWN','--cap-add=FOWNER','-v',v['config-volume']+':/config','-v',v['web-volume']+':/web','--entrypoint=sleep',v.image,'180']);started=true;
 p(['cp',temp+'/role/.',helper+':/config/']);p(['cp',temp+'/web.json',helper+':/web/web.json']);
 p(['exec',helper,'sh','-ec','chmod 700 /config /web; chmod 600 /config/* /web/web.json; chown -R '+uid+':'+gid+' /web']);
 p(['exec',helper,'/usr/local/bin/clean-vpn-engine','--check-config','/config/engine.json']);
 if(v['clients-endpoint']){assert.equal(role,'exit','clients_exit_only');assert.ok(v.ca&&v['server-name'],'clients_ca_and_server_name_required');assert.ok(config.transport!=='combo-tls','combo_registry_requires_explicit_relay_map');p(['exec',helper,'node','/opt/clean-vpn/scripts/clean-vpn-native-clients.mjs','init','--directory=/config/clients','--config=/config/engine.json','--engine=/usr/local/bin/clean-vpn-engine','--endpoint='+v['clients-endpoint'],'--server-name='+v['server-name'],'--ca=/config/ca.pem',...(v.profile?['--profile=/config/profile.json']:[])]);}
 console.log(JSON.stringify({kind:'native-managed-prepared',role,configVolume:v['config-volume'],webVolume:v['web-volume'],uid,gid,webUrl:'http://127.0.0.1:'+port+'/',capturePort:capture,clientsRegistry:!!v['clients-endpoint'],started:false,hostNetworkChanged:false,comboReplayInitializationRequired:config.transport==='combo-tls'&&role==='exit'},null,2));
}catch(error){try{p(['rm','-f',helper]);started=false;}catch{}for(const name of created)try{p(['volume','rm',name]);}catch{}throw error;}finally{if(started)p(['rm','-f',helper]);fs.rmSync(temp,{recursive:true,force:true});}

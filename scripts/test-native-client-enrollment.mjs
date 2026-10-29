// Linux integration: provision -> add/rotate/export/import -> real native TLS.
// C++ WAN fixture owns packet generation/verification; no host TUN/routes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {once} from 'node:events';
import {spawn,execFileSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import {createRuntimeConfig,parseRuntimeConfig} from './clean-vpn-native-runtime-config.mjs';
import {NativeClientManager,importClientBundle} from './lib/native-client-manager.mjs';
import {nativeClientService} from './lib/native-client-service.mjs';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
for(const transport of ['boring-tls','combo-tls'])for(const httpVersion of ['2','1.1'])test(`enrollment ${transport} HTTP ${httpVersion} connects with allocated rotated identity`,{timeout:45000},async t=>{
 const root=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'cvpn-enroll-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const dir=root+'/bundle';
 const socket=net.createServer();socket.listen(0,'127.0.0.1');await once(socket,'listening');const port=socket.address().port;await new Promise(r=>socket.close(r));
 const args=['create','--directory='+dir,'--mode=standalone','--endpoint=192.0.2.1','--exit-address=192.0.2.1','--server-name=localhost.test','--port='+port,'--transport='+transport,...(transport==='combo-tls'?['--public-name=relay.example']:[])];
 createRuntimeConfig(parseRuntimeConfig(args));const configPath=dir+'/exit/engine.json';const config=JSON.parse(fs.readFileSync(configPath));(config.boring??config).http_version=httpVersion;(config.boring??config).address='127.0.0.1';if(config.transparent)config.transparent.listen.ipv4='127.0.0.1';fs.writeFileSync(configPath,JSON.stringify(config),{mode:0o600});
 if(transport==='combo-tls'){fs.mkdirSync(dir+'/exit/replay',{mode:0o700});execFileSync(build+'/clean-vpn-engine',['--init-transparent-replay',configPath],{stdio:'pipe'});}
 const service=nativeClientService({engine:build+'/clean-vpn-engine',directory:root+'/state'}),m=new NativeClientManager({directory:root+'/state',...service});
 await m.init({configPath,endpoint:'127.0.0.1',serverName:'localhost.test',caPath:dir+'/client-1/ca.pem',profilePath:dir+'/client-1/profile.json',...(transport==='combo-tls'?{relayMap:{'10.99.0.2':'client-1'}}:{})});
 await m.add('laptop');const first=await m.export('laptop');await m.rotate('laptop');const bundle=await m.export('laptop');assert.notEqual(bundle.files.psk,first.files.psk);assert.equal(bundle.ipv4,'10.99.0.3');await m.revoke('client-2');
 const imported=await importClientBundle(bundle,root+'/client',service);const clientConfig=JSON.parse(fs.readFileSync(imported.configPath));(clientConfig.boring??clientConfig).dns=false;fs.writeFileSync(imported.configPath,JSON.stringify(clientConfig));
 const run=(role,file)=>{const child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',file,'wan-'+role,bundle.ipv4]);let out='';for(const s of [child.stdout,child.stderr])s.on('data',b=>out+=b);const timer=setTimeout(()=>child.kill('SIGKILL'),28000);const done=once(child,'close').then(([code])=>{clearTimeout(timer);assert.equal(code,0,out);assert.match(out,/"status":"passed"/);});done.catch(()=>{});t.after(()=>{clearTimeout(timer);child.kill('SIGKILL');});return{done,output:()=>out};};
 const exit=run('exit',configPath);for(let i=0;!exit.output().includes('WAN_LISTENING');i++){assert.ok(i<100,exit.output());await delay(50);}const client=run('client',imported.configPath);await Promise.all([exit.done,client.done]);
});

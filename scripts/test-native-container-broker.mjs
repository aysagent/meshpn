import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createContainerBroker} from './clean-vpn-container-broker.mjs';

function fixture(role='client') {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-container-broker-')),config=path.join(dir,'engine.json');
 fs.writeFileSync(config,JSON.stringify({version:1,role,address:'192.0.2.1',port:443,tun:'cvpn0',server_name:'vpn.example',sni:'vpn.example',dns:role==='client'}),{mode:0o600});
 const calls=[],engine={state:dir,child:null,lines:['bounded'],desired:false,failReady:false,
  async prepare(){calls.push('guard');},async ready(){if(this.failReady){this.failReady=false;throw Error('injected_start_failure');}},
  async start(){calls.push('start');this.child={pid:123};this.desired=true;},async stop(){calls.push('stop');this.child=null;this.desired=false;},
  async restart(){await this.stop();await this.start();},status(){return{ActiveState:this.child?'active':'inactive',MainPID:this.child?.pid??0};},async close(){await this.stop();}};
 return{dir,config,calls,engine,c:{config,engine:'/engine',runtime:'/runtime',health:'/health',stateDirectory:dir+'/state',socket:dir+'/broker.sock'},cleanup:()=>fs.rmSync(dir,{recursive:true,force:true})};
}
async function settled(b) {for(let i=0;i<100;i++){const s=await b.dispatch('/status');if(!s.jobs.some(j=>j.status==='running'))return s.jobs[0];await new Promise(r=>setTimeout(r,5));}throw Error('job_timeout');}
test('container lifecycle API owns one child and does not expose host operations',async()=>{
 const f=fixture();const b=await createContainerBroker(f.c,{engine:f.engine,run:async()=>({out:''})});
 try{await b.start();assert.equal(f.engine.child.pid,123);const s=await b.dispatch('/status');assert.equal(s.capabilities.wifi,false);assert.equal(s.capabilities.guardToggle,false);
  for(const route of ['/guard','/wifi/save','/hostname','/observer/start','/shell'])await assert.rejects(b.dispatch(route,{}),/container_operation_not_supported/);
  await assert.rejects(b.dispatch('/vpn/action',{action:'exec',command:'arbitrary'}),/unknown_fields/);
  await b.dispatch('/vpn/action',{action:'stop'});assert.equal((await settled(b)).status,'passed');assert.equal(f.engine.child,null);assert.equal(JSON.parse(fs.readFileSync(f.dir+'/state/settings.json')).desired,false);
  await b.dispatch('/vpn/action',{action:'start'});assert.equal((await settled(b)).status,'passed');assert.equal(f.engine.child.pid,123);
 }finally{await b.close();f.cleanup();}
});
test('client settings keep endpoint fixed and rollback failed activation',async()=>{
 const f=fixture();let checks=0;const b=await createContainerBroker(f.c,{engine:f.engine,run:async(file,args)=>{if(file==='/engine'){assert.equal(args[0],'--check-config');checks++;}else{assert.equal(file,process.execPath);assert.deepEqual(args,['/health']);}return{out:''};}});
 try{await b.start();const before=fs.readFileSync(f.config,'utf8');
  const update={address:'192.0.2.2',port:443,serverName:'new.example',sni:'new.example',profile:null};
  await b.dispatch('/vpn/settings',update);assert.equal((await settled(b)).error,'endpoint_change_requires_container_recreate');assert.equal(fs.readFileSync(f.config,'utf8'),before);
  f.engine.failReady=true;update.address='192.0.2.1';await b.dispatch('/vpn/settings',update);assert.equal((await settled(b)).status,'failed');assert.equal(fs.readFileSync(f.config,'utf8'),before);assert.equal(f.engine.child.pid,123);assert.equal(checks,1);
  await b.dispatch('/vpn/settings',update);assert.equal((await settled(b)).status,'passed');assert.equal(JSON.parse(fs.readFileSync(f.config)).server_name,'new.example');
 }finally{await b.close();f.cleanup();}
});
test('exit exposes its role and rejects client-only settings',async()=>{
 const f=fixture('exit'),b=await createContainerBroker(f.c,{engine:f.engine,run:async()=>({out:''})});
 try{const s=await b.dispatch('/settings');assert.equal(s.vpn.role,'exit');assert.equal(s.capabilities.vpnSettings,false);await b.dispatch('/vpn/settings',{});assert.equal((await settled(b)).error,'client_settings_only');}finally{await b.close();f.cleanup();}
});
test('explicit stop persists across supervisor recreation',async()=>{
 const f=fixture();let b=await createContainerBroker(f.c,{engine:f.engine,run:async()=>({out:''})});
 try{await b.start();await b.dispatch('/vpn/action',{action:'stop'});await settled(b);await b.close();b=await createContainerBroker(f.c,{engine:f.engine,run:async()=>({out:''})});await b.start();assert.equal(f.engine.child,null);}finally{await b.close();f.cleanup();}
});

#!/usr/bin/env node
// No published ports or physical-machine access. All network changes stay in
// fresh namespaces inside a dedicated NIC-less Linux systemd container.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
const cli=JSON.parse(process.env.CVPN_CONTAINER_COMMAND??'["podman","--connection","meshpn-clean-vpn-lab-root"]');
assert.ok(Array.isArray(cli)&&cli.length&&cli.every(s=>typeof s==='string'));
const image=process.env.CVPN_PORT_LAB_IMAGE??'localhost/clean-vpn-port-lab:local';
const report=path.resolve(process.argv[2]??'');assert.ok(process.argv.length===3&&!fs.existsSync(report),'new_report_path_required');
const p=(args,opts={})=>execFileSync(cli[0],[...cli.slice(1),...args],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024,stdio:['ignore','pipe','pipe'],...opts});
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-port-lab-')),name='cvpn-port-lab-'+randomBytes(6).toString('hex');
let created=false;
try{
 const source=path.join(tmp,'project');fs.mkdirSync(source);
 // Only tracked worktree inputs, never untracked keys/builds or the entire repo.
 const files=execFileSync('git',['ls-files','-z','scripts','fixtures'],{encoding:'utf8'}).split('\0').filter(Boolean);
 const hashes={};for(const file of files){assert.ok(!file.split('/').includes('..'));const to=path.join(source,file);fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(file,to);hashes[file]=createHash('sha256').update(fs.readFileSync(file)).digest('hex');}
 assert.ok(fs.existsSync(path.join(source,'scripts/lib/native-port-coexistence-lab.mjs')),'track_new_fixture_before_snapshot');
 const inspected=JSON.parse(p(['image','inspect',image]))[0];
 p(['create','--name',name,'--label=org.meshpn.native-port-lab=1','--network=none','--privileged','--systemd=always','--security-opt=unmask=all',image]);created=true;
 p(['cp',source+'/.',name+':/project/']);p(['start',name]);
 const state=JSON.parse(p(['inspect',name]))[0];assert.equal(state.HostConfig.NetworkMode,'none');
 const output=p(['exec','-e','CVPN_DISPOSABLE_PORT_LAB=1',name,'node','/project/scripts/lib/native-port-coexistence-lab.mjs'],{timeout:600000});
 fs.writeFileSync(report+'.log',output,{mode:0o600});
 p(['cp',name+':/port-lab-report.json',report]);
 const result=JSON.parse(fs.readFileSync(report));result.imageId=inspected.Id;result.sourceSnapshotSha256=createHash('sha256').update(JSON.stringify(hashes)).digest('hex');
 result.sourceFiles=Object.fromEntries(['scripts/lib/native-port-coexistence-lab.mjs','scripts/clean-vpn-pcap-fingerprints.mjs','scripts/lib/native-port.mjs'].map(f=>[f,hashes[f]]));
 fs.writeFileSync(report,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}catch(e){
 fs.writeFileSync(report+'.failure.log',String(e.stdout??'')+'\n'+String(e.stderr??'')+'\n'+String(e.message),{mode:0o600});throw e;
}finally{
 if(created)p(['rm','-f',name]);fs.rmSync(tmp,{recursive:true,force:true});
}

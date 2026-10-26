#!/usr/bin/env node
// Fixture PKI/configuration and evidence only; C++ owns all test packet traffic.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {once} from 'node:events';
import {randomBytes,createHash} from 'node:crypto';
import {spawn,spawnSync,execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export async function runH2Budget({counts=[1,4,8],modes=['baseline','browser-credit'],cycles=3}={}) {
  assert.equal(process.platform,'linux','Linux laboratory required');
  assert.ok(counts.length&&counts.every(n=>[1,4,8].includes(n))&&new Set(counts).size===counts.length);
  assert.ok(modes.length&&modes.every(m=>['baseline','browser-credit'].includes(m))&&new Set(modes).size===modes.length);
  assert.ok(Number.isInteger(cycles)&&cycles>=3&&cycles<=30,'cycles must be 3..30');
  const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build'),root=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-h2-budget-'));
  let active=null,cancelled=false;
  const cancel=()=>{cancelled=true;active?.kill('SIGTERM');};
  process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
  try {
    const production=build+'/clean-vpn-engine',fixture=build+'/clean-vpn-engine-fixture';
    assert.equal(fs.readFileSync(production).includes(Buffer.from('CVPN_TEST_H2_BUDGET')),false,'fixture override leaked into production');
    const capabilities=JSON.parse(execFileSync(production,['--capabilities'],{encoding:'utf8',timeout:5000}));
    assert.equal(capabilities.profile_policy.http2.connection_window.max,1048576);
    assert.equal(capabilities.profile_policy.http2.settings.find(s=>s.id===4).max,1048576);
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',root+'/key.pem','-out',root+'/cert.pem',
      '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
    fs.chmodSync(root+'/key.pem',0o600);
    const profile=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/cold-alps.json'));
    profile.id='h2-budget-baseline';profile.http2.connection_window=1048576;
    profile.http2.settings.find(([id])=>id===4)[1]=1048576;
    fs.writeFileSync(root+'/profile.json',JSON.stringify(profile),{mode:0o600});
    const cases=[];
    for(const mode of modes)for(const count of counts){
      assert.equal(cancelled,false,'cancelled');
      const listener=net.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');
      const port=listener.address().port;await new Promise(r=>listener.close(r));
      const common={version:1,address:'127.0.0.1',port,tun:'cvtest0',dns:false};
      const peers=Array.from({length:count},(_,i)=>{
        const secret_path=root+`/psk-${i}`,ipv4=`10.99.0.${i+2}`;fs.writeFileSync(secret_path,randomBytes(32),{mode:0o600});
        fs.writeFileSync(root+`/client-${i}.json`,JSON.stringify({...common,role:'client',peer_ipv4:ipv4,secret_path,
          ca:root+'/cert.pem',server_name:'localhost',tls_profile_path:root+'/profile.json'}),{mode:0o600});
        return {ipv4,secret_path};
      });
      fs.writeFileSync(root+'/exit.json',JSON.stringify({...common,role:'exit',cert:root+'/cert.pem',key:root+'/key.pem',peers}),{mode:0o600});
      // Normal configuration accepts only the bounded baseline, never the
      // experimental receive credit installed inside the fixture afterwards.
      for(const name of ['client-0','exit'])assert.equal(JSON.parse(execFileSync(production,['--check-config',root+'/'+name+'.json'],{encoding:'utf8',timeout:5000})).valid,true);
      const oversized=structuredClone(profile);oversized.http2.connection_window=15728640;oversized.http2.settings.find(([id])=>id===4)[1]=6291456;
      fs.writeFileSync(root+'/oversized.json',JSON.stringify(oversized),{mode:0o600});
      const bad=JSON.parse(fs.readFileSync(root+'/client-0.json'));bad.tls_profile_path=root+'/oversized.json';
      fs.writeFileSync(root+'/oversized-config.json',JSON.stringify(bad),{mode:0o600});
      assert.equal(spawnSync(production,['--check-config',root+'/oversized-config.json'],{timeout:5000,encoding:'utf8'}).status,1,'production accepted oversized profile');
      const env={...process.env,CVPN_TEST_H2_BUDGET:mode,CVPN_TEST_H2_OBSERVER:'1',CVPN_TEST_H2_CYCLES:String(cycles)};
      for(const key of ['NOTIFY_SOCKET','CVPN_TEST_ALPS','CVPN_TEST_ALPS_CLIENT','CVPN_TEST_CERT_COMPRESSION','CVPN_TEST_SIGNATURE'])delete env[key];
      const child=spawn(build+'/integration-test',[fixture,root,root+'/exit.json','h2-budget',String(count)],{env,stdio:['ignore','pipe','pipe']});
      active=child;
      let output='',stderr='';
      const collect=(stream,save)=>stream.on('data',b=>{save(b.toString());if(output.length+stderr.length>2*1024*1024)child.kill('SIGKILL');});
      collect(child.stdout,s=>output+=s);collect(child.stderr,s=>stderr+=s);
      const timer=setTimeout(()=>child.kill('SIGKILL'),Math.max(90,cycles*12+30)*1000);
      let code;try{[code]=await once(child,'close');}finally{clearTimeout(timer);active=null;}
      assert.equal(code,0,`${mode}/${count}: ${output.slice(-5000)} ${stderr.slice(-2000)}`);
      const lines=output.split('\n').filter(l=>l.startsWith('H2_BUDGET_RESULT='));assert.equal(lines.length,1);
      const result=JSON.parse(lines[0].slice('H2_BUDGET_RESULT='.length));
      assert.equal(result.clients,count);assert.equal(result.mode,mode);assert.equal(result.cycles,cycles);
      assert.equal(result.phases.length,cycles*2);assert.equal(result.recoveries.length,cycles);
      const windows={stream:mode==='baseline'?1048576:6291456,connection:mode==='baseline'?1048576:15728640};
      const frames=stderr.split('\n').filter(line=>line.includes('fixture_h2 ')).map(line=>{
        assert.ok(line.startsWith('fixture_h2 '),'interleaved H2 observer prefix');
        try{return JSON.parse(line.slice('fixture_h2 '.length));}catch{throw new Error(`${mode}/${count}: malformed H2 observer record: ${line.slice(0,600)}`);}
      })
        .filter(f=>f.kind==='wire'&&f.receiver==='exit').map(f=>Buffer.from(f.hex,'hex'));
      const settings=frames.filter(b=>b[3]===4&&!(b[4]&1));
      assert.equal(settings.length,count*(cycles+1),'expected initial settings for every connection and reconnect');
      for(const b of settings){
        assert.equal(b.readUIntBE(0,3),b.length-9);let found=false;
        for(let offset=9;offset<b.length;offset+=6)if(b.readUInt16BE(offset)===4){assert.equal(b.readUInt32BE(offset+2),windows.stream);found=true;}
        assert.ok(found,'initial stream window missing');
      }
      const updates=frames.filter(b=>b[3]===8&&b.readUInt32BE(5)===0);
      assert.equal(updates.length,count*(cycles+1),'expected initial connection credit for every connection and reconnect');
      for(const b of updates)assert.equal(b.readUInt32BE(9),windows.connection-65535);
      result.observedClientCredit=windows;result.settingsSamples=settings.length;cases.push(result);
      console.error(`H2 budget ${mode}/${count} PASS (${result.duration_seconds.toFixed(1)}s)`);
    }
    return {schema:1,kind:'clean-vpn-native-h2-budget-report',status:'passed',timestamp:new Date().toISOString(),
      environment:{platform:process.platform,processArch:process.arch,kernel:os.release(),node:process.version},
      coverage:counts.length===3&&modes.length===2?'full-matrix':'subset',cycles,
      binaries:{engine:hash(production),fixture:hash(fixture),harness:hash(build+'/integration-test')},
      productionCapsChanged:false,productionOversizedProfileRejected:true,productionFixtureHookAbsent:true,physicalHostsTouched:false,hostNetworkSettingsChanged:false,
      kernelSocketMemoryComplete:cases.every(c=>c.phases.every(p=>p.kernel_socket_memory_available)),
      productionWindowIncreaseApproved:false,
      cases,limitations:['socketpair-not-real-TUN','loopback-not-WAN-throughput','sampled-RSS-and-logical-queue-bytes-not-all-allocations',
        'SO_MEMINFO-may-be-unavailable-or-truncated-under-emulation-null-is-not-zero',
        'fixture-only-client-receive-credit-override','no-browser-header-limit-or-HPACK-change','bounded-duration-not-proof-of-no-long-term-leaks']};
  }finally{process.off('SIGINT',cancel);process.off('SIGTERM',cancel);fs.rmSync(root,{recursive:true,force:true});}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  try {
    assert.equal(process.argv.length,3,'Usage: node scripts/clean-vpn-native-h2-budget.mjs NEW_REPORT.json');
    // Refuse an existing output before starting expensive work.
    assert.equal(fs.existsSync(process.argv[2]),false,'output exists');
    const report=await runH2Budget();fs.writeFileSync(process.argv[2],JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
    console.log(`H2_BUDGET=passed REPORT=${path.resolve(process.argv[2])}`);
  }catch(e){console.error(e.message);process.exitCode=1;}
}

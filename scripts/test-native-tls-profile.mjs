import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { randomBytes, createHash } from 'node:crypto';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { observeTlsProfile, compileTlsProfileCandidate } from './lib/native-tls-profile-observer.mjs';
import { parseFirstTlsClientHelloFromTcpBuf } from './lib/tls-clienthello-ja3.mjs';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
const baseline=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/cold-h2.json'));
function fixture(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-profile-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const cert=dir+'/cert.pem',key=dir+'/key.pem',secret=dir+'/psk';
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
  fs.writeFileSync(secret,randomBytes(32),{mode:0o600});
  return {dir,cert,key,secret};
}
function config(f,port=34443) {return {version:1,role:'client',address:'127.0.0.1',port,tun:'cvtest0',server_name:'localhost',ca:f.cert,secret_path:f.secret,tls_profile_path:f.dir+'/profile.json'};}
function checkConfig(f,p,c=config(f)) {
  fs.writeFileSync(f.dir+'/profile.json',JSON.stringify(p));fs.writeFileSync(f.dir+'/client.json',JSON.stringify(c));
  return spawnSync(build+'/clean-vpn-engine',['--check-config',f.dir+'/client.json'],{encoding:'utf8',timeout:5000});
}
test('profile validation is strict, offline and reports effective immutable settings',t=>{
  const f=fixture(t),r=checkConfig(f,baseline);assert.equal(r.status,0,r.stderr);
  const report=JSON.parse(r.stdout).tls_profile;assert.equal(report.id,baseline.id);assert.match(report.sha256,/^[a-f0-9]{64}$/);assert.deepEqual(report.tls,baseline.tls);
  const same=JSON.parse(checkConfig(f,JSON.parse(JSON.stringify(baseline,null,2))).stdout);assert.equal(same.tls_profile.sha256,report.sha256);
  const cap=JSON.parse(execFileSync(build+'/clean-vpn-engine',['--capabilities']));assert.equal(cap.browser_profiles,false);assert.equal(cap.experimental_tls_profiles.prewire_check,true);
  for(const change of [
    p=>{p.tls.cipher_suites.reverse();},p=>{p.tls.cipher_suites=[65535];},p=>{p.tls.cipher_suites.push(4865);},
    p=>{p.tls.supported_groups=[65535];},p=>{p.tls.key_share_groups=[24];},p=>{p.tls.key_share_groups=[23,29];},
    p=>{p.tls.optional_extension_types=[27];},p=>{p.tls.optional_extension_types=[0];},p=>{p.tls.signature_algorithms=[513];},p=>{p.tls.signature_algorithms=[65535];},p=>{p.tls.alpn=['http/1.1'];},p=>{p.tls.min_version=770;},
    p=>{p.tls.max_version=771;},p=>{p.tls.grease='true';},p=>{p.tls.extension_types.push(27);},
    p=>{p.tls.extension_types.reverse();},p=>{p.tls.extension_types.push(1234);},p=>{p.tls.client_hello_extra_extensions=[];},
    p=>{p.tls.random='secret';},p=>{p.scenario='resumed';},p=>{p.schema=2;},p=>{p.unknown=true;},
  ]) {
    const p=structuredClone(baseline);change(p);
    // Reordered supported ciphers are valid and must change the effective digest.
    if(p.tls.cipher_suites[0]===4866&&p.tls.cipher_suites.length===3) {
      const good=checkConfig(f,p);assert.equal(good.status,0);assert.notEqual(JSON.parse(good.stdout).tls_profile.sha256,report.sha256);continue;
    }
    const bad=checkConfig(f,p);assert.equal(bad.status,1,JSON.stringify(p));assert.equal(bad.stdout,'');assert.doesNotMatch(bad.stderr,/secret/);
  }
  const exit={...config(f),role:'exit',cert:f.cert,key:f.key};assert.equal(checkConfig(f,baseline,exit).status,1);
  assert.equal(checkConfig(f,baseline,{...config(f),tls_profile_path:'relative.json'}).status,1);
  fs.symlinkSync(f.dir+'/profile.json',f.dir+'/link.json');
  assert.equal(checkConfig(f,baseline,{...config(f),tls_profile_path:f.dir+'/link.json'}).status,1);
  const relay=f.dir+'/relay.psk';fs.writeFileSync(relay,randomBytes(32),{mode:0o600});
  const combo={version:1,role:'client',transport:'combo-tls',boring:{...config(f),sni:'localhost'},
    transparent:{version:1,role:'client',transport:'transparent-tls',public_name:'localhost',secret_path:relay,
      listen:{ipv4:'127.0.0.1',port:34444},exit:{ipv4:'127.0.0.1',port:34443},destinations:[{ipv4:'127.0.0.1',port:34445}]}};
  assert.equal(checkConfig(f,baseline,combo).status,0);
});

async function exchange(f,p,{mode='service',changes={},exitChanges={},combo=false,compression=null,signature=null,alps=false,alpsFault=null,clientAlps=false,h2Observe=false}={}) {
  const reserve=net.createServer();reserve.listen(0,'127.0.0.1');await once(reserve,'listening');const backend=reserve.address().port;await new Promise(r=>reserve.close(r));
  const captures=[],sockets=new Set(); captures.hrr=false;
  const proxy=net.createServer(client=>{
    const upstream=net.connect(backend,'127.0.0.1');sockets.add(client);sockets.add(upstream);
    for(const s of [client,upstream]){s.on('error',()=>{client.destroy();upstream.destroy();});s.on('close',()=>sockets.delete(s));}
    let bytes=Buffer.alloc(0),done=false;
    client.on('data',chunk=>{if(done)return;bytes=Buffer.concat([bytes,chunk]);if(bytes.length>65536){done=true;client.destroy();return;}
      const h=parseFirstTlsClientHelloFromTcpBuf(bytes);if(h.ok){captures.push(Buffer.from(bytes.subarray(0,h.bytesConsumed)));done=true;}});
    let reply=Buffer.alloc(0),serverHelloSeen=false;
    upstream.on('data',chunk=>{if(serverHelloSeen)return;reply=Buffer.concat([reply,chunk]);
      if(reply.length>=43){serverHelloSeen=true;captures.hrr ||= reply[0]===22 && reply[5]===2 &&
        reply.subarray(11,43).toString('hex')==='cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';}});
    client.pipe(upstream);upstream.pipe(client);
  });
  proxy.listen(0,'127.0.0.1');await once(proxy,'listening');
  try {
  fs.writeFileSync(f.dir+'/profile.json',JSON.stringify(p));
  let clientConfig={...config(f,proxy.address().port),...changes};
  let exitConfig={version:1,role:'exit',address:'127.0.0.1',port:backend,tun:'cvtest0',secret_path:f.secret,cert:f.serverCert??f.cert,key:f.serverKey??f.key,...(alps?{alps:true}:{}),...exitChanges};
  if(combo) {
    const relay=f.dir+'/relay.psk';fs.writeFileSync(relay,randomBytes(32),{mode:0o600});
    fs.mkdirSync(f.dir+'/replay',{mode:0o700});
    const portProbe=net.createServer();portProbe.listen(0,'127.0.0.1');await once(portProbe,'listening');
    const relayPort=portProbe.address().port;await new Promise(r=>portProbe.close(r));
    const common={version:1,transport:'transparent-tls',public_name:'localhost',secret_path:relay,destinations:[{ipv4:'127.0.0.1',port:34445}]};
    clientConfig={version:1,role:'client',transport:'combo-tls',boring:clientConfig,
      transparent:{...common,role:'client',listen:{ipv4:'127.0.0.1',port:relayPort},exit:{ipv4:'127.0.0.1',port:proxy.address().port}}};
    exitConfig={version:1,role:'exit',transport:'combo-tls',boring:exitConfig,
      transparent:{...common,role:'exit',listen:{ipv4:'127.0.0.1',port:backend},replay_directory:f.dir+'/replay'}};
  }
  fs.writeFileSync(f.dir+'/client.json',JSON.stringify(clientConfig));
  fs.writeFileSync(f.dir+'/exit.json',JSON.stringify(exitConfig));
  if(combo)execFileSync(build+'/clean-vpn-engine',['--init-transparent-replay',f.dir+'/exit.json'],{stdio:'pipe'});
    const child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',f.dir+'/client.json',f.dir+'/exit.json',...(mode==='full'?[]:[mode])],{stdio:['ignore','pipe','pipe'],
      env:{...process.env,...(compression?{CVPN_TEST_CERT_COMPRESSION:compression}:{}),...(signature?{CVPN_TEST_SIGNATURE:signature}:{}),...(alpsFault?{CVPN_TEST_ALPS:alpsFault}:{}),...(clientAlps?{CVPN_TEST_ALPS_CLIENT:'nonempty'}:{}),...(h2Observe?{CVPN_TEST_H2_OBSERVER:'1'}:{})}});
    let output='';for(const s of [child.stdout,child.stderr])s.on('data',b=>{output+=b;if(output.length>262144)child.kill('SIGKILL');});
    const timeout=setTimeout(()=>child.kill('SIGKILL'),mode==='full'?80000:15000);
    let code;try{[code]=await once(child,'exit');}finally{clearTimeout(timeout);}
    assert.equal(code,0,output);assert.ok(captures.length>0&&captures.length<=16);
    if(compression)assert.match(output,/fixture_compressed_certificate_sent/,'server did not send CompressedCertificate');
    captures.h2=[...output.matchAll(/fixture_h2 (\{[^\n]+\})/g)].map(m=>JSON.parse(m[1]));
    captures.signaturesSent=[...output.matchAll(/fixture_certificate_verify_sent=(\d+)/g)].map(m=>Number(m[1]));
    captures.signaturesVerified=[...output.matchAll(/fixture_peer_signature_verified=(\d+)/g)].map(m=>Number(m[1]));
    return captures;
  } finally {for(const s of sockets)s.destroy();await new Promise(r=>proxy.close(r));}
}

test('real native TCP ClientHello matches saved profile; keys/random fresh; fingerprints independently observed', {timeout:45000},async t=>{
  const f=fixture(t),captures=[];
  for(let i=0;i<3;i++)captures.push(...await exchange(f,baseline));
  const reports=captures.map(w=>observeTlsProfile(w,baseline));
  for(const r of reports){assert.equal(r.status,'matched',JSON.stringify(r.differences));assert.deepEqual(r.keyShares.filter(x=>x.group===29),[{group:29,length:32}]);}
  const expectedJa3='771,4865-4867-4866,0-10-16-13-51-45-43,29-23,';
  assert.equal(reports[0].ja3String,expectedJa3);assert.equal(reports[0].ja3,createHash('md5').update(expectedJa3).digest('hex'));
  assert.equal(new Set(reports.map(r=>r.ja3)).size,1);assert.equal(new Set(reports.map(r=>JSON.stringify(r.ja4))).size,1);
  const randoms=captures.map(w=>parseFirstTlsClientHelloFromTcpBuf(w).clientHelloBody.subarray(2,34).toString('hex'));
  assert.equal(new Set(randoms).size,captures.length);
  const shareHashes=captures.map(w=>{
    const b=parseFirstTlsClientHelloFromTcpBuf(w).clientHelloBody;
    let o=35+b[34];o+=2+b.readUInt16BE(o);o+=1+b[o];o+=2;
    while(o<b.length) {
      const type=b.readUInt16BE(o),size=b.readUInt16BE(o+2);o+=4;
      if(type===51)for(let k=o+2;k<o+size;) {
        const group=b.readUInt16BE(k),length=b.readUInt16BE(k+2);k+=4;
        if(group===29)return createHash('sha256').update(b.subarray(k,k+length)).digest('hex');k+=length;
      }
      o+=size;
    }
    assert.fail('missing X25519 share');
  });
  assert.equal(new Set(shareHashes).size,captures.length,'X25519 key reused');
  // Golden synthetic vector: t13/d/3 ciphers/7 extensions/h2; SHA256 of
  // 1301,1302,1303 and 000a,000d,002b,002d,0033_0403,0804,0805,0806.
  assert.equal(reports[0].ja4.fingerprint,'t13d0307h2_55b375c5d22e_70c6d19c6451');
  const compiled=compileTlsProfileCandidate(captures[0],{id:'measured-roundtrip',extensionOrder:'fixed',padding:'exact',echMode:'disabled'});
  assert.equal(compiled.status,'candidate');assert.deepEqual(compiled.profile.tls,baseline.tls);
  assert.equal(checkConfig(f,compiled.profile).status,0);
  for(const wire of await exchange(f,compiled.profile))assert.equal(observeTlsProfile(wire,compiled.profile).status,'matched');
  assert.equal(compiled.measurement.sessionIdBytes,reports[0].sessionIdBytes);
  assert.doesNotMatch(JSON.stringify(compiled),/random|private_key|ticket_hex/);
  const capturedPath=f.dir+'/hello.bin';fs.writeFileSync(capturedPath,captures[0],{mode:0o600});
  const offline=spawnSync(process.execPath,['scripts/clean-vpn-native-profile-observe.mjs',f.dir+'/profile.json',capturedPath],{encoding:'utf8'});
  assert.equal(offline.status,0,offline.stderr);assert.equal(JSON.parse(offline.stdout).ja3,reports[0].ja3);
  const cliCandidate=spawnSync(process.execPath,['scripts/clean-vpn-native-profile-observe.mjs','--candidate','cli-capture','fixed','exact','disabled',capturedPath],{encoding:'utf8'});
  assert.equal(cliCandidate.status,0,cliCandidate.stderr);assert.deepEqual(JSON.parse(cliCandidate.stdout).profile.tls,baseline.tls);
  const unsupportedWire=Buffer.from(captures[0]),body=parseFirstTlsClientHelloFromTcpBuf(unsupportedWire).clientHelloBody;
  let off=35+body[34];off+=2+body.readUInt16BE(off);off+=1+body[off];off+=2;
  while(body.readUInt16BE(off)!==13)off+=4+body.readUInt16BE(off+2);
  // This fixture is one TLS record. Replace ext13 by an unsupported ext50;
  // the candidate must refuse the extension rather than discard its body.
  unsupportedWire.writeUInt16BE(50,off+9);
  const unsupported=compileTlsProfileCandidate(unsupportedWire,{id:'unsupported',extensionOrder:'fixed',padding:'exact',echMode:'disabled'});
  assert.equal(unsupported.status,'unsupported');assert.equal(unsupported.profile,null);assert.ok(unsupported.unsupported.includes('extension:50'));

  const wrong=structuredClone(baseline);wrong.tls.cipher_suites.reverse();
  assert.ok(observeTlsProfile(captures[0],wrong).differences.some(d=>d.field==='cipher_suites'));
  console.log(JSON.stringify({observation:reports[0],samples:captures.length}));
});

test('profile keeps CA hostname and exporter-bound PSK verification', {timeout:45000},async t=>{
  const f=fixture(t),other=fixture(t);
  for(const changes of [{ca:other.cert},{server_name:'wrong.localhost'},{secret_path:other.secret}]) {
    const captured=await exchange(f,baseline,{mode:'reject',changes});
    for(const wire of captured)assert.equal(observeTlsProfile(wire,baseline).status,'matched');
  }
});

test('permuted modern profile uses real ECH GREASE and TLS12 advertisement without raw extension replay', {timeout:45000},async t=>{
  const f=fixture(t),p=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/cold-modern.json')),reports=[];
  assert.equal(checkConfig(f,p).status,0);
  for(let i=0;i<4;i++)for(const wire of await exchange(f,p)) {
    const r=observeTlsProfile(wire,p);assert.equal(r.status,'matched',JSON.stringify(r.differences));reports.push(r);
  }
  assert.ok(new Set(reports.map(r=>r.actual.extension_types.join(','))).size>1,'extension permutation absent');
  // Optional BoringSSL padding changes the extension set and thus JA hashes.
  // Compare within each actually observed set; never erase it from the report.
  for(const padding of [true,false]) {
    const group=reports.filter(r=>r.actual.extension_types.includes(21)===padding);
    if(group.length){assert.equal(new Set(group.map(r=>r.ja3Sorted)).size,1);assert.equal(new Set(group.map(r=>r.ja4.fingerprint)).size,1);}
  }
  assert.ok(reports.every(r=>r.actual.extension_types.includes(65037)));
  console.log(JSON.stringify({modernObservation:reports[0],samples:reports.length}));
});

test('empty initial key shares negotiate real HRR and native packet exchange', {timeout:15000},async t=>{
  const f=fixture(t),p=structuredClone(baseline);p.tls.key_share_groups=[];
  const captures=await exchange(f,p);assert.equal(captures.hrr,true,'server did not request HRR');
  for(const wire of captures)assert.equal(observeTlsProfile(wire,p).status,'matched');
});

test('saved TLS profile applies to the real combo boring branch with native exit dispatch', {timeout:15000},async t=>{
  const f=fixture(t),captures=await exchange(f,baseline,{combo:true});
  for(const wire of captures)assert.equal(observeTlsProfile(wire,baseline).status,'matched');
});

test('profile reconnect, blackhole and backpressure keep descriptors bounded and generate fresh hellos', {timeout:90000},async t=>{
  const f=fixture(t),captures=await exchange(f,baseline,{mode:'full'});
  assert.ok(captures.length>=6);
  for(const wire of captures)assert.equal(observeTlsProfile(wire,baseline).status,'matched');
  assert.equal(new Set(captures.map(w=>parseFirstTlsClientHelloFromTcpBuf(w).clientHelloBody.subarray(2,34).toString('hex'))).size,captures.length);
});

function compressedProfile() {
  const p=structuredClone(baseline);p.id='synthetic-brotli';
  p.tls.certificate_compression=[2];p.tls.extension_types.push(27);p.tls.permute_extensions=true;return p;
}
test('Brotli profile checks algorithms before wire and negotiates actual compressed certificates', {timeout:45000},async t=>{
  const f=fixture(t),p=compressedProfile();assert.equal(checkConfig(f,p).status,0);
  assert.equal(fs.readFileSync(build+'/clean-vpn-engine').includes(Buffer.from('fixture_compressed_certificate_sent')),false);
  for(const algorithms of [[1],[2,2],[2,3],'brotli',null,[]]) {
    const bad=structuredClone(p);bad.tls.certificate_compression=algorithms;assert.equal(checkConfig(f,bad).status,1);
  }
  const missing=structuredClone(p);missing.tls.extension_types=missing.tls.extension_types.filter(n=>n!==27);
  assert.equal(checkConfig(f,missing).status,1);
  for(const options of [{},{compression:'valid'},{compression:'valid',combo:true}]) {
    const fresh=fixture(t);
    for(const wire of await exchange(fresh,p,options)) {
      const r=observeTlsProfile(wire,p);assert.equal(r.status,'matched');assert.deepEqual(r.actual.certificate_compression,[2]);
      const candidate=compileTlsProfileCandidate(wire,{id:'brotli-roundtrip',extensionOrder:'permuted',padding:'exact',echMode:'disabled'});
      assert.equal(candidate.status,'candidate');assert.deepEqual(candidate.profile.tls.certificate_compression,[2]);
      assert.equal(checkConfig(f,candidate.profile).status,0);
    }
  }
  const hrr=structuredClone(p);hrr.tls.key_share_groups=[];
  const captures=await exchange(f,hrr,{compression:'valid'});assert.equal(captures.hrr,true);
});
test('compressed certificates do not bypass CA hostname PSK checks or malformed-stream rejection', {timeout:120000},async t=>{
  const f=fixture(t),other=fixture(t),p=compressedProfile();
  for(const compression of ['truncated','trailing','wrong-size','garbage'])
    await exchange(f,p,{compression,mode:'reject'});
  for(const changes of [{ca:other.cert},{server_name:'wrong.localhost'},{secret_path:other.secret}])
    await exchange(f,p,{compression:'valid',mode:'reject',changes});
});

const alpsProfile=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/cold-alps.json'));
function h2Frame(hex) {
  const bytes=Buffer.from(hex,'hex');assert.ok(bytes.length>=9);
  assert.equal(bytes.readUIntBE(0,3),bytes.length-9);assert.equal(bytes.readUInt32BE(5),0);
  const frame={type:bytes[3],flags:bytes[4]};
  if(frame.type===4) {
    assert.equal((bytes.length-9)%6,0);frame.settings=[];
    for(let i=9;i<bytes.length;i+=6)frame.settings.push([bytes.readUInt16BE(i),bytes.readUInt32BE(i+2)]);
  }
  if(frame.type===8){assert.equal(bytes.length,13);frame.increment=bytes.readUInt32BE(9);}
  return frame;
}
test('ALPS requires explicit bounded H2 settings and strict new-codepoint semantics',t=>{
  const f=fixture(t);assert.equal(checkConfig(f,alpsProfile).status,0);
  for(const mutate of [
    p=>{delete p.http2;},p=>{p.http2.extra=true;},p=>{p.tls.application_settings=['http/1.1'];},
    p=>{p.tls.extension_types=p.tls.extension_types.filter(n=>n!==17613);},
    p=>{p.tls.extension_types=p.tls.extension_types.map(n=>n===17613?17513:n);},
    p=>{p.http2.connection_window=1048577;},p=>{p.http2.connection_window=65534;},
    p=>{p.http2.settings.push([5,32768]);},p=>{p.http2.settings[0]=[1,65537];},
    p=>{p.http2.settings[1]=[2,1];},p=>{p.http2.settings[2]=[3,2];},
    p=>{p.http2.settings[3]=[4,1048577];},p=>{p.http2.settings[4]=[6,8193];},
    p=>{p.http2.settings.push([3,1]);},p=>{p.http2.settings.splice(1,1);},
    p=>{p.http2.settings.push([8,1]);},p=>{p.http2.settings[0]=[1,-1];},
  ]) {const p=structuredClone(alpsProfile);mutate(p);assert.equal(checkConfig(f,p).status,1,JSON.stringify(p));}
  assert.equal(checkConfig(f,alpsProfile,{...config(f),alps:true}).status,1);
});

test('negotiated ALPS and fallback match independently decoded real H2 settings, window and ACKs', {timeout:60000},async t=>{
  for(const alps of [false,true]) {
    const f=fixture(t),captures=await exchange(f,alpsProfile,{alps,h2Observe:true,compression:'valid'});
    for(const wire of captures) {
      const report=observeTlsProfile(wire,alpsProfile);assert.equal(report.status,'matched',JSON.stringify(report.differences));
      assert.deepEqual(report.actual.application_settings,['h2']);
      const candidate=compileTlsProfileCandidate(wire,{id:'alps-capture',extensionOrder:'permuted',padding:'exact',echMode:'disabled'});
      assert.equal(candidate.status,'unsupported');assert.ok(candidate.unsupported.includes('alps-requires-explicit-http2-settings'));
    }
    const seen=captures.h2;
    assert.equal(seen.some(x=>x.kind==='alps'),alps);
    const clientWire=seen.filter(x=>x.kind==='wire'&&x.receiver==='exit').map(x=>h2Frame(x.hex));
    assert.deepEqual(clientWire.filter(x=>x.type===4&&x.flags===0).map(x=>x.settings),[alpsProfile.http2.settings]);
    assert.deepEqual(clientWire.filter(x=>x.type===8).map(x=>x.increment),[alpsProfile.http2.connection_window-65535]);
    const serverWire=seen.filter(x=>x.kind==='wire'&&x.receiver==='client').map(x=>h2Frame(x.hex));
    if(alps) {
      assert.deepEqual(seen.filter(x=>x.kind==='alps'&&x.receiver==='client').map(x=>h2Frame(x.hex).settings),[[[3,1],[4,1048576],[6,8192]]]);
      assert.ok(seen.some(x=>x.kind==='alps'&&x.receiver==='exit'&&x.hex===''));
      assert.equal(serverWire.filter(x=>x.type===4&&x.flags===0).length,0);
      assert.equal(clientWire.filter(x=>x.type===4&&x.flags===1).length,0);
      assert.equal(serverWire.filter(x=>x.type===4&&x.flags===1).length,1);
    } else assert.deepEqual(serverWire.filter(x=>x.type===4&&x.flags===0).map(x=>x.settings),[[[3,1],[4,1048576],[6,8192]]]);
    console.log(JSON.stringify({alps,h2:seen,tls:observeTlsProfile(captures[0],alpsProfile)}));
  }
  // A legacy client can still use an opt-in ALPS exit.
  await exchange(fixture(t),baseline,{alps:true});
});

test('ALPS works with combo and HRR; rejects malformed negotiated settings before packet injection', {timeout:120000},async t=>{
  await exchange(fixture(t),alpsProfile,{alps:true,combo:true,compression:'valid'});
  const hrr=structuredClone(alpsProfile);hrr.tls.key_share_groups=[];
  assert.equal((await exchange(fixture(t),hrr,{alps:true,compression:'valid'})).hrr,true);
  for(const alpsFault of ['ack','stream','truncated','extra-frame','window','unknown','duplicate']) {
    const captures=await exchange(fixture(t),alpsProfile,{alps:true,alpsFault,h2Observe:true,mode:'reject'});
    assert.ok(captures.h2.some(x=>x.kind==='alps'&&x.receiver==='client'),'malformed ALPS was not actually negotiated');
    assert.equal(captures.h2.filter(x=>x.kind==='wire'&&x.receiver==='exit').length,0,'client sent H2 before rejecting ALPS');
  }
  const nonempty=await exchange(fixture(t),alpsProfile,{alps:true,clientAlps:true,h2Observe:true,mode:'reject'});
  assert.ok(nonempty.h2.some(x=>x.kind==='alps'&&x.receiver==='exit'&&x.hex!==''));
  const f=fixture(t),other=fixture(t);
  for(const changes of [{ca:other.cert},{server_name:'wrong.localhost'},{secret_path:other.secret}])
    await exchange(f,alpsProfile,{alps:true,mode:'reject',changes});
});

test('ALPS profile preserves reconnect blackhole and bounded packet flow under sustained exchange', {timeout:90000},async t=>{
  await exchange(fixture(t),alpsProfile,{alps:true,mode:'full'});
});

test('engine capability limits are the limits enforced by its profile loader',t=>{
  const f=fixture(t),caps=JSON.parse(execFileSync(build+'/clean-vpn-engine',['--capabilities']));
  const policy=caps.profile_policy;assert.equal(policy.id,'bounded-cold-v1');assert.equal(policy.schema,1);
  assert.deepEqual(policy,JSON.parse(fs.readFileSync('fixtures/clean-vpn-native-profile-policy-capabilities.json')).profile_policy);
  assert.equal(policy.activation.automatic,false);
  const profile=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/cold-alps.json'));
  for(const rule of policy.http2.settings) {
    const withValue=value=>{const p=structuredClone(profile);p.http2.settings=p.http2.settings.filter(([id])=>id!==rule.id);p.http2.settings.push([rule.id,value]);return p;};
    for(const value of new Set([rule.min,rule.max]))assert.equal(checkConfig(f,withValue(value)).status,0,JSON.stringify(rule));
    if(rule.min>0)assert.equal(checkConfig(f,withValue(rule.min-1)).status,1);
    assert.equal(checkConfig(f,withValue(rule.max+1)).status,1);
    const omitted=structuredClone(profile);omitted.http2.settings=omitted.http2.settings.filter(([id])=>id!==rule.id);
    assert.equal(checkConfig(f,omitted).status,rule.required?1:0);
  }
  for(const [value,status] of [[policy.http2.connection_window.min,0],[policy.http2.connection_window.max,0],
    [policy.http2.connection_window.min-1,1],[policy.http2.connection_window.max+1,1]]) {
    const p=structuredClone(profile);p.http2.connection_window=value;assert.equal(checkConfig(f,p).status,status);
  }
  for(const id of [47,156]) {const p=structuredClone(profile);p.tls.cipher_suites.push(id);assert.equal(checkConfig(f,p).status,1);}
  for(const id of [2308,2309,2310]) {const p=structuredClone(profile);p.tls.signature_algorithms.push(id);assert.equal(checkConfig(f,p).status,0);}
  for(const id of [35,41,42,50,17513,51764,65534]) {const p=structuredClone(profile);p.tls.extension_types.push(id);assert.equal(checkConfig(f,p).status,1);}
});

function signatureProfile() {
  return JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/cold-mldsa.json'));
}
function mldsaFixture(t,algorithm) {
  const f=fixture(t);f.serverCert=f.dir+'/leaf.pem';f.serverKey=f.dir+'/leaf-key.pem';
  execFileSync(build+'/profile-credentials-fixture',[f.cert,f.key,String(algorithm),f.serverCert,f.serverKey],{stdio:'pipe'});
  assert.equal(fs.statSync(f.serverKey).mode&0o777,0o600);return f;
}
test('ML-DSA 44/65/87 are negotiated and verified with real certificates and independently observed ClientHello', {timeout:60000},async t=>{
  const p=signatureProfile(),reports=[];
  assert.equal(fs.readFileSync(build+'/clean-vpn-engine').includes(Buffer.from('CVPN_TEST_SIGNATURE')),false);
  for(const [algorithm,id] of [[44,2308],[65,2309],[87,2310]]) {
    const f=mldsaFixture(t,algorithm);assert.equal(checkConfig(f,p).status,0);
    const captures=await exchange(f,p,{signature:'observe'});
    assert.ok(captures.signaturesSent.length>0);assert.ok(captures.signaturesVerified.length>0);
    assert.ok(captures.signaturesSent.every(x=>x===id));assert.ok(captures.signaturesVerified.every(x=>x===id));
    for(const wire of captures) {
      const r=observeTlsProfile(wire,p);assert.equal(r.status,'matched');reports.push(r);
      const candidate=compileTlsProfileCandidate(wire,{id:'mldsa-roundtrip',extensionOrder:'fixed',padding:'exact',echMode:'disabled'});
      assert.equal(candidate.status,'candidate');assert.equal(checkConfig(f,candidate.profile).status,0);
    }
    // A client without this algorithm cannot silently accept the ML-DSA leaf.
    const rejected=await exchange(f,baseline,{signature:'observe',mode:'reject'});
    assert.equal(rejected.signaturesVerified.length,0);
  }
  assert.equal(new Set(reports.map(r=>r.ja4.fingerprint)).size,1);
  console.log(JSON.stringify({mldsaClientHello:reports[0],negotiatedAlgorithms:[2308,2309,2310]}));
});

test('ML-DSA rejects invalid CertificateVerify signatures and preserves CA, hostname and exporter PSK checks', {timeout:90000},async t=>{
  const p=signatureProfile(),other=fixture(t);
  for(const [algorithm,id] of [[44,2308],[65,2309],[87,2310]]) {
    const f=mldsaFixture(t,algorithm);
    const rejected=await exchange(f,p,{signature:'corrupt',mode:'reject'});
    assert.ok(rejected.signaturesSent.includes(id),'invalid signature was not actually sent');
    assert.equal(rejected.signaturesVerified.length,0);
    for(const changes of [{ca:other.cert},{server_name:'wrong.localhost'},{secret_path:other.secret}]) {
      const captures=await exchange(f,p,{signature:'observe',mode:'reject',changes});
      assert.ok(captures.signaturesSent.includes(id));
      if(!changes.secret_path)assert.equal(captures.signaturesVerified.length,0);
      else assert.ok(captures.signaturesVerified.includes(id),'PSK rejection must follow a valid ML-DSA handshake');
    }
  }
});

test('ML-DSA composes with combo, HRR and ALPS without changing native packet authentication', {timeout:30000},async t=>{
  const p=signatureProfile(),f=mldsaFixture(t,65);
  assert.ok((await exchange(f,p,{signature:'observe',combo:true})).signaturesVerified.includes(2309));
  const hrr=structuredClone(p);hrr.tls.key_share_groups=[];
  const capture=await exchange(mldsaFixture(t,87),hrr,{signature:'observe'});
  assert.equal(capture.hrr,true);assert.ok(capture.signaturesVerified.includes(2310));
  const a=structuredClone(alpsProfile);a.tls.signature_algorithms=p.tls.signature_algorithms;
  assert.ok((await exchange(mldsaFixture(t,44),a,{signature:'observe',alps:true})).signaturesVerified.includes(2308));
});

test('bounded Chromium-derived pilot profile preserves supported fields and verifies real wire', {timeout:60000}, async t => {
  const f=fixture(t),file='fixtures/native-tls-profiles/chromium-156-bounded-cold.json';
  const p=JSON.parse(fs.readFileSync(file));
  const provenance=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.provenance.json'));
  assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'),provenance.profileSha256);
  assert.equal(createHash('sha256').update(fs.readFileSync(provenance.source)).digest('hex'),provenance.sourceSha256);
  const browser=JSON.parse(fs.readFileSync(provenance.source)).bundle.samples[0].measurement.actual;
  for(const key of ['supported_groups','key_share_groups','signature_algorithms','alpn','certificate_compression','application_settings'])
    assert.deepEqual(p.tls[key],browser[key]);
  assert.deepEqual(browser.cipher_suites.filter(x=>!p.tls.cipher_suites.includes(x)),provenance.deviations.removedCipherSuites);
  assert.deepEqual(browser.extension_types.filter(x=>!p.tls.extension_types.includes(x)),provenance.deviations.removedExtensions);
  const c=checkConfig(f,p);assert.equal(c.status,0,c.stderr);
  const reports=[];
  for(let i=0;i<3;i++)for(const wire of await exchange(f,p)) {
    const r=observeTlsProfile(wire,p);assert.equal(r.status,'matched',JSON.stringify(r.differences));reports.push(r);
    assert.equal(r.keyShares.find(k=>k.group===4588)?.length,1216);
  }
  const other=fixture(t);
  for(const changes of [{ca:other.cert},{server_name:'wrong.localhost'},{secret_path:other.secret}])
    await exchange(f,p,{mode:'reject',changes});
  console.log(JSON.stringify({boundedChromiumPilot:{reports,browserEquivalent:false}}));
});


test('HTTP/1.1-only profile: prewire verification, real tunnel and independent fingerprints', {timeout:45000},async t=>{
 const f=fixture(t),p=structuredClone(baseline);p.id='synthetic-cold-h1';p.tls.alpn=['http/1.1'];
 assert.equal(checkConfig(f,p,{...config(f),http_version:'1.1'}).status,0);
 assert.equal(checkConfig(f,p,{...config(f),http_version:'2'}).status,1);
 for(const wire of await exchange(f,p,{changes:{http_version:'1.1'},exitChanges:{http_version:'1.1'}})){
  const observed=observeTlsProfile(wire,p);assert.equal(observed.status,'matched');assert.deepEqual(observed.actual.alpn,['http/1.1']);
  const candidate=compileTlsProfileCandidate(wire,{id:'captured-h1',extensionOrder:'fixed',padding:'exact',echMode:'disabled'});
  assert.equal(candidate.status,'candidate');assert.equal(checkConfig(f,candidate.profile,{...config(f),http_version:'auto'}).status,0);
 }
});

test('browser profile remains unchanged on HTTP/1.1 negotiation, including combo boring branch', {timeout:45000},async t=>{
 const p=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json'));
 assert.deepEqual(p.tls.alpn,['h2','http/1.1']);
 for(const combo of[false,true]){
  const f=fixture(t);assert.equal(checkConfig(f,p,{...config(f),http_version:'1.1'}).status,1,'must not rewrite profile ALPN');
  for(const wire of await exchange(f,p,{combo,changes:{http_version:'auto'},exitChanges:{http_version:'1.1'},alps:true})){
   const r=observeTlsProfile(wire,p);assert.equal(r.status,'matched',JSON.stringify(r.differences));assert.deepEqual(r.actual.alpn,p.tls.alpn);
  }
 }
});

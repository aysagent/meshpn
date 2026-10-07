import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import net from 'node:net';
import { once } from 'node:events';

// Node provisions test config/PKI only. Native integration-test generates and
// checks every IP packet; native engine runs the entire TLS/H2/IP path.
test('native client/exit data plane: packets, control, reconnect, blackhole', { timeout: 90000 }, async t => {
  const build = path.resolve(process.env.CVPN_BUILD ?? 'native/clean_vpn/build');
  const capabilities=JSON.parse(execFileSync(path.join(build,'clean-vpn-engine'),['--capabilities'],{encoding:'utf8'}));
  assert.equal(capabilities.packet_ipc,false);assert.equal(capabilities.mode,'ipv4-packets');assert.equal(capabilities.multi_peer,true);assert.equal(capabilities.max_peers,32);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cvpn-native-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cert=path.join(dir,'cert.pem'), key=path.join(dir,'key.pem'), secret=path.join(dir,'psk');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
  fs.writeFileSync(secret,randomBytes(32),{mode:0o600});
  const listener=net.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');
  const port=listener.address().port;await new Promise(r=>listener.close(r));
  const common={version:1,address:'127.0.0.1',port,tun:'cvtest0',secret_path:secret};
  const client=path.join(dir,'client.json'), server=path.join(dir,'exit.json');
  fs.writeFileSync(client,JSON.stringify({...common,role:'client',server_name:'localhost',ca:cert}));
  fs.writeFileSync(server,JSON.stringify({...common,role:'exit',cert,key}));
  const result=spawnSync(path.join(build,'integration-test'),[path.join(build,'clean-vpn-engine-fixture'),client,server],{encoding:'utf8',timeout:80000,maxBuffer:1024*1024});
  assert.equal(result.status,0,`${result.error ?? ''}\n${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout,/native integration PASS/);
  console.log(result.stdout);
  const service=spawnSync(path.join(build,'integration-test'),[path.join(build,'clean-vpn-engine-fixture'),client,server,'service'],{encoding:'utf8',timeout:10000,maxBuffer:65536});
  assert.equal(service.status,0,service.stdout+'\n'+service.stderr);
  assert.match(service.stdout,/service mode ignores stdin\/EOF, 100 packets, SIGTERM clean stop PASS/);
  const otherSecret=path.join(dir,'other-psk');fs.writeFileSync(otherSecret,randomBytes(32),{mode:0o600});
  const otherCert=path.join(dir,'other.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(dir,'other.key'),'-out',otherCert,'-days','2','-subj','/CN=other','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
  for (const [name,changes] of [['hostname',{server_name:'not-localhost'}],['ca',{ca:otherCert}],['psk',{secret_path:otherSecret}]]) {
    fs.writeFileSync(client,JSON.stringify({...common,role:'client',server_name:'localhost',ca:cert,...changes}));
    const denied=spawnSync(path.join(build,'integration-test'),[path.join(build,'clean-vpn-engine-fixture'),client,server,'reject'],{encoding:'utf8',timeout:10000,maxBuffer:1024*1024});
    assert.equal(denied.status,0,`${name}: ${denied.stdout}\n${denied.stderr}`);
    console.log(`${name} rejected; no packet injection PASS`);
  }
  const production=spawnSync(path.join(build,'clean-vpn-engine'),['--config',client,'--test-packet-fd','4'],{encoding:'utf8',timeout:2000});
  assert.equal(production.status,1,'production binary must reject fixture packet descriptor');
});

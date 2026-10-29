import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseRuntimeConfig, createRuntimeConfig } from './clean-vpn-native-runtime-config.mjs';
import { tcpPort, publishedExitPort } from './lib/native-port.mjs';
import {runtimePlan} from './lib/native-runtime-plan.mjs';
const base = fs.realpathSync(os.tmpdir());
const args = dir => ['create', '--directory=' + dir, '--mode=container', '--endpoint=192.0.2.10', '--exit-address=172.30.77.2', '--server-name=runtime.test', '--clients=2'];
test('combo bundle gives unique packet identities, separate shared relay key and explicit replay state',()=>{
  const root=fs.mkdtempSync(path.join(base,'native-combo-config-'));
  try{for(const mode of ['container','standalone']){
    const dir=path.join(root,mode),a=args(dir).filter(a=>!a.startsWith('--mode='));
    const m=createRuntimeConfig(parseRuntimeConfig([...a,'--mode='+mode,'--transport=combo-tls','--public-name=relay.example','--port=3443','--exit-port=4443']));
    const get=f=>fs.readFileSync(path.join(dir,f));
    const clients=[1,2].map(i=>JSON.parse(get(`client-${i}/engine.json`))),exit=JSON.parse(get('exit/engine.json'));
    assert.equal(m.transport,'combo-tls');assert.equal(exit.boring.peers.length,2);
    assert.notEqual(clients[0].boring.peer_ipv4,clients[1].boring.peer_ipv4);
    for(let i=1;i<=2;i++){
      assert.deepEqual(get(`client-${i}/psk`),get(`exit/peer-${i}.psk`));
      assert.deepEqual(get(`client-${i}/relay.psk`),get(`exit/relay-${i}.psk`));
      assert.notDeepEqual(get(`client-${i}/psk`),get(`client-${i}/relay.psk`));
      assert.equal(clients[i-1].transparent.exit.port,3443);assert.equal(clients[i-1].boring.sni,'relay.example');
      runtimePlan(clients[i-1],{lan:{interface:'eth1',subnet:'192.168.88.0/24'}});
    }
    assert.notDeepEqual(get('client-1/psk'),get('client-2/psk'));
    assert.notDeepEqual(get('client-1/relay.psk'),get('client-2/relay.psk'));
    assert.equal(exit.transparent.peers.length,2);assert.equal(exit.transparent.secret_path,undefined);
    assert.deepEqual(exit.transparent.limits,{sessions:128,per_client:64});
    assert.equal(exit.transparent.listen.port,4443);runtimePlan(exit);
    assert.equal(exit.transparent.replay_directory,mode==='container'?'/replay/state':dir+'/exit/replay');
    assert.equal(fs.existsSync(dir+'/exit/replay'),false);
    assert.throws(()=>createRuntimeConfig(parseRuntimeConfig([...a,'--mode='+mode,'--transport=combo-tls','--public-name=relay.example'])),/EEXIST/);
  }}finally{fs.rmSync(root,{recursive:true,force:true});}
  for(const extra of [['--transport=combo-tls'],['--transport=transparent-tls'],['--public-name=relay.example'],
    ['--transport=combo-tls','--public-name=relay.example','--relay-port=1053'],
    ...['0','257','1e3'].map(n=>['--transport=combo-tls','--public-name=relay.example','--relay-sessions='+n]),
    ['--transport=combo-tls','--public-name=relay.example','--relay-per-client=128']])assert.throws(()=>parseRuntimeConfig([...args('/new/unused'),...extra]));
});
test('offline bundle isolates credentials, verifies server identity and refuses overwrites', () => {
  const root = fs.mkdtempSync(path.join(base, 'native-config-test-'));
  try {
    const dir = path.join(root, 'bundle'), options = parseRuntimeConfig(args(dir));
    createRuntimeConfig(options);
    const get = f => fs.readFileSync(path.join(dir, f));
    const c = JSON.parse(get('client-1/engine.json')), exit = JSON.parse(get('exit/engine.json'));
    assert.equal(c.ca, '/config/ca.pem'); assert.equal(c.peer_ipv4, '10.99.0.2');
    assert.equal(c.port,443); assert.equal(exit.port,443);
    assert.equal(exit.peers.length, 2); assert.equal(exit.peers[1].ipv4, '10.99.0.3');
    assert.deepEqual(get('client-1/psk'), get('exit/peer-1.psk')); assert.equal(get('client-1/psk').length, 32);
    assert.notDeepEqual(get('client-1/psk'), get('client-2/psk'));
    assert.deepEqual(fs.readdirSync(path.join(dir, 'client-1')).sort(), ['ca.pem', 'engine.json', 'profile.json', 'psk']);
    for (const role of ['authority', 'exit', 'client-1', 'client-2']) {
      assert.equal(fs.statSync(path.join(dir, role)).mode & 0o777, 0o700);
      for (const file of fs.readdirSync(path.join(dir, role))) assert.equal(fs.statSync(path.join(dir, role, file)).mode & 0o777, 0o600);
    }
    execFileSync('openssl', ['verify', '-CAfile', dir + '/client-1/ca.pem', '-verify_hostname', 'runtime.test', dir + '/exit/cert.pem']);
    assert.throws(() => execFileSync('openssl', ['verify', '-CAfile', dir + '/client-1/ca.pem', '-verify_hostname', 'wrong.test', dir + '/exit/cert.pem'], { stdio: 'pipe' }));
    const before = get('client-1/psk'); assert.throws(() => createRuntimeConfig(options), /EEXIST/); assert.deepEqual(get('client-1/psk'), before);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('nonstandard endpoint and container listener ports remain explicit through provisioning',()=>{
  const root=fs.mkdtempSync(path.join(base,'native-port-config-'));
  try {
    const dir=path.join(root,'bundle');
    const same=parseRuntimeConfig([...args(dir),'--port=3443']);
    assert.equal(same.port,3443);assert.equal(same.exitPort,3443);
    const manifest=createRuntimeConfig(parseRuntimeConfig([...args(dir),'--port=3443','--exit-port=4443']));
    const client=JSON.parse(fs.readFileSync(dir+'/client-1/engine.json'));
    const exit=JSON.parse(fs.readFileSync(dir+'/exit/engine.json'));
    assert.equal(client.port,3443);assert.equal(exit.port,4443);
    assert.equal(manifest.port,3443);assert.equal(manifest.exitPort,4443);
    assert.equal(publishedExitPort(exit,client.port),'3443:4443/tcp');
    assert.equal(publishedExitPort({...exit,port:3443},3443),'3443:3443/tcp');
    assert.throws(()=>publishedExitPort(client,3443),/requires_exit/);
  } finally {fs.rmSync(root,{recursive:true,force:true});}
});
test('port inputs cannot silently truncate, wrap or accept duplicate configuration',()=>{
  for(const port of ['0','65536','03443','3443x','-1','3.5','1e3','']) {
    assert.throws(()=>tcpPort(port));
    assert.throws(()=>parseRuntimeConfig([...args('/nonexistent/new'),'--port='+port]));
    assert.throws(()=>parseRuntimeConfig([...args('/nonexistent/new'),'--exit-port='+port]));
  }
  assert.equal(tcpPort('65535'),65535);
  assert.throws(()=>parseRuntimeConfig([...args('/nonexistent/new'),'--port=443','--port=3443']),/duplicate_option/);
});
test('invalid addresses, modes, counts and duplicate options are rejected before writes', () => {
  for (const tail of [['--clients=33'], ['--mode=host'], ['--endpoint=127.0.0.1'], ['--days=0'], ['--server-name=x\nsubjectAltName=DNS:evil']]) {
    const option = tail[0].split('=')[0];
    assert.throws(() => parseRuntimeConfig([...args('/nonexistent/new').filter(a => !a.startsWith(option + '=')), ...tail]));
  }
  assert.throws(() => parseRuntimeConfig([...args('/nonexistent/new'), '--mode=standalone']), /duplicate_option/);
});

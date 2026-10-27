// Experimental transport packaging fixture. Runs ONLY in an empty container
// netns. The public boring-tls runtime launcher does not enable these modes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import https from 'node:https';
import { randomBytes, createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';

const [transport, phase] = process.argv.slice(2);
assert.ok(['transparent-tls', 'combo-tls'].includes(transport));
assert.ok(['first', 'recreated', 'readonly'].includes(phase));
assert.equal(process.platform, 'linux');
assert.match(process.env.CVPN_PARENT_NETNS ?? '', /^net:\[\d+\]$/);
assert.notEqual(fs.readlinkSync('/proc/self/ns/net'), process.env.CVPN_PARENT_NETNS);
const run = (bin, args) => execFileSync(bin, args, { encoding: 'utf8', timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
assert.deepEqual(JSON.parse(run('ip', ['-j', 'link'])).map(x => x.ifname), ['lo']);
const engine = '/usr/local/bin/clean-vpn-engine', root = '/state/' + transport;
const file = name => root + '/' + name;
const write = (name, data) => fs.writeFileSync(file(name), data, { mode: 0o600 });
const checks = [], step = name => { checks.push(name); console.log('REPLAY_STEP=' + name); };
const children = [], servers = [], sockets = new Set();
const track = s => { sockets.add(s); s.on('close', () => sockets.delete(s)); s.on('error', () => {}); return s; };
const start = args => {
  const child = spawn(engine, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  child.output = ''; child.stdout.on('data', b => child.output += b); child.stderr.on('data', b => child.output += b);
  children.push(child); return child;
};
const wait = async check => {
  let error; for (let i = 0; i < 100; i++) { try { return check(); } catch (e) { error = e; await delay(50); } } throw error;
};
const ready = child => wait(() => assert.match(child.output, /"state":"(?:listening|ready)"/, child.output));
const deny = async args => {
  const c = start(args), timer = setTimeout(() => c.kill('SIGKILL'), 4000);
  try { const [code, signal] = await once(c, 'close'); assert.equal(signal, null, c.output); assert.notEqual(code, 0, c.output); return c.output; }
  finally { clearTimeout(timer); }
};
const digest = () => createHash('sha256').update(fs.readFileSync(file('replay/state'))).digest('hex');
const stop = async child => {
  const closed = once(child, 'close'); child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
  try { const [code, signal] = await closed; assert.equal(signal, null); assert.equal(code, 0, child.output); }
  finally { clearTimeout(timer); }
};
let held = false;
try {
  if (phase === 'first') {
    assert.equal(fs.existsSync(root), false);
    fs.mkdirSync(root, { mode: 0o700 }); fs.mkdirSync(file('replay'), { mode: 0o700 });
    run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=runtime.test',
      '-addext', 'subjectAltName=DNS:runtime.test', '-keyout', file('key.pem'), '-out', file('cert.pem')]);
    write('relay.psk', randomBytes(32)); write('boring.psk', randomBytes(32));
    const endpoint = port => ({ ipv4: '127.0.0.1', port });
    for (const role of ['client', 'exit']) {
      const relay = { version: 1, transport: 'transparent-tls', role, listen: endpoint(role === 'client' ? 9443 : 8443),
        public_name: 'relay.example', secret_path: file('relay.psk'), destinations: [endpoint(8444)],
        ...(role === 'client' ? { exit: endpoint(8445) } : { replay_directory: file('replay') }) };
      const boring = { version: 1, role, tun: role === 'client' ? 'cvc0' : 'cve0', address: '127.0.0.1',
        port: role === 'client' ? 8445 : 8443, secret_path: file('boring.psk'),
        ...(role === 'client' ? { ca: file('cert.pem'), server_name: 'runtime.test', sni: 'relay.example' }
          : { cert: file('cert.pem'), key: file('key.pem') }) };
      write(role + '.json', JSON.stringify(transport === 'combo-tls'
        ? { version: 1, transport, role, boring, transparent: relay } : relay));
    }
  }
  for (const role of ['client', 'exit']) assert.equal(JSON.parse(run(engine, ['--check-config', file(role + '.json')])).valid, true);
  step('production-engine-config-valid');
  if (phase === 'readonly') {
    const before = digest();
    assert.match(await deny(['--config', file('exit.json'), '--service']), /configuration or startup refused/);
    assert.equal(digest(), before); step('readonly-state-refused-without-reset');
  } else {
    if (transport === 'combo-tls') {
      for (const tun of ['cvc0', 'cve0']) { run('ip', ['tuntap', 'add', 'dev', tun, 'mode', 'tun']); run('ip', ['link', 'set', tun, 'up']); }
    }
    if (phase === 'first') {
      assert.match(await deny(['--config', file('exit.json'), '--service']), /configuration or startup refused/);
      assert.equal(JSON.parse(run(engine, ['--init-transparent-replay', file('exit.json')])).replay_initialized, true);
      assert.match(await deny(['--init-transparent-replay', file('exit.json')]), /configuration or startup refused/); step('explicit-init-only-and-repeat-init-refused');
    }
    let originConnections = 0, recording = false, captured;
    const origin = https.createServer({ key: fs.readFileSync(file('key.pem')), cert: fs.readFileSync(file('cert.pem')) },
      (_req, res) => res.end('RELAY_ORIGIN_OK'));
    origin.on('connection', s => { originConnections++; track(s); });
    origin.listen(8444, '127.0.0.1'); servers.push(origin); await once(origin, 'listening');
    // An external byte-forwarding fixture records the real client->exit first
    // record. It cannot manufacture an accepted token and is not the engine.
    const observer = net.createServer(incoming => {
      track(incoming); const outgoing = track(net.connect(8443, '127.0.0.1'));
      let prefix = Buffer.alloc(0), take = recording; if (take) recording = false;
      incoming.on('data', b => {
        if (take) {
          prefix = Buffer.concat([prefix, b]); assert.ok(prefix.length < 65536);
          if (prefix.length >= 5 && prefix.length >= 5 + prefix.readUInt16BE(3)) {
            captured = prefix.subarray(0, 5 + prefix.readUInt16BE(3)); take = false;
          }
        }
      });
      incoming.pipe(outgoing).pipe(incoming);
      incoming.on('close', () => outgoing.destroy()); outgoing.on('close', () => incoming.destroy());
    });
    observer.listen(8445, '127.0.0.1'); servers.push(observer); await once(observer, 'listening');
    const exit = start(['--config', file('exit.json'), '--service']); await ready(exit);
    assert.match(await deny(['--config', file('exit.json'), '--service']), /configuration or startup refused/); step('durable-scope-second-owner-refused');
    if (phase === 'recreated') {
      const before = originConnections;
      await new Promise((resolve, reject) => {
        let data = false; const s = track(net.connect(8443, '127.0.0.1', () => s.write(fs.readFileSync(file('captured.bin')))));
        s.setTimeout(3000, () => { s.destroy(); reject(Error('replay_rejection_timeout')); });
        s.on('data', () => data = true); s.on('close', () => { try { assert.equal(data, false); resolve(); } catch (e) { reject(e); } });
      });
      await delay(100); assert.equal(originConnections, before); step('captured-token-rejected-after-container-sigkill-recreation');
    }
    const client = start(['--config', file('client.json'), '--service']); await ready(client);
    if (transport === 'combo-tls') { await wait(() => assert.match(client.output, /"state":"ready"/, client.output)); step('combo-boring-authenticated-on-shared-exit-listener'); }
    // Only the unprivileged test application's connection is redirected.
    // Native exit -> origin remains root and never enters this rule.
    run('iptables-nft', ['-t', 'nat', '-A', 'OUTPUT', '-p', 'tcp', '-d', '127.0.0.1', '--dport', '8444',
      '-m', 'owner', '--uid-owner', '65534', '-j', 'REDIRECT', '--to-ports', '9443']);
    fs.writeFileSync('/run/origin-ca.pem', fs.readFileSync(file('cert.pem')), { mode: 0o644 });
    recording = true;
    const app = spawn(process.execPath, ['-e', `const https=require('https'),fs=require('fs');
https.get({host:'127.0.0.1',port:8444,servername:'runtime.test',ca:fs.readFileSync('/run/origin-ca.pem'),agent:false,timeout:3000},r=>{
let b='';r.on('data',x=>b+=x);r.on('end',()=>{if(b!=='RELAY_ORIGIN_OK')process.exitCode=1;});
}).on('error',e=>{console.error(e.message);process.exitCode=1}).on('timeout',function(){this.destroy()});`],
      { uid: 65534, gid: 65534, stdio: ['ignore', 'pipe', 'pipe'] });
    let appError = ''; app.stderr.on('data', b => appError += b);
    const [code] = await once(app, 'close'); assert.equal(code, 0, appError);
    assert.ok(captured?.length > 5); assert.equal(originConnections, 1); step('native-so-original-dst-tls-relay-fresh-request');
    if (phase === 'first') write('captured.bin', captured);
    else {
      await stop(client); await stop(exit);
      // Positive control: the very same captured token must still be valid.
      // Use a SEPARATE, explicitly initialized fixture scope; never reset the
      // durable state under test. This rules out expiry/corruption as the
      // explanation for rejection after container recreation.
      const preserved = digest(), control = JSON.parse(fs.readFileSync(file('exit.json')));
      fs.mkdirSync(file('positive-control'), { mode: 0o700 });
      (transport === 'combo-tls' ? control.transparent : control).replay_directory = file('positive-control');
      write('positive-control.json', JSON.stringify(control));
      run(engine, ['--init-transparent-replay', file('positive-control.json')]);
      const positive = start(['--config', file('positive-control.json'), '--service']); await ready(positive);
      await new Promise((resolve, reject) => {
        const s = track(net.connect(8443, '127.0.0.1', () => s.write(fs.readFileSync(file('captured.bin')))));
        s.setTimeout(3000, () => { s.destroy(); reject(Error('positive_token_timeout')); });
        let accepted = false;
        s.once('data', b => { accepted = b.length > 0; s.destroy(); });
        s.once('close', () => accepted ? resolve() : reject(Error('positive_token_refused')));
      });
      assert.equal(originConnections, 2); assert.equal(digest(), preserved);
      await stop(positive); step('same-captured-token-valid-in-independent-fresh-fixture-scope');
    }
    const report = { schema: 1, kind: 'native-runtime-replay-phase', transport, phase, checks, status: 'passed', replayStateSha256: digest() };
    if (phase === 'first') {
      // The controller kills the ENTIRE container here. Do not stop the exit
      // gracefully: durable state must survive an actual container SIGKILL.
      console.log('REPLAY_HOLD=' + JSON.stringify(report)); held = true; await new Promise(() => {});
    }
  }
  console.log('REPLAY_REPORT=' + JSON.stringify({ schema: 1, kind: 'native-runtime-replay-phase', transport, phase, checks, status: 'passed', replayStateSha256: digest() }));
} finally {
  if (!held) {
    for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill('SIGTERM');
    for (const s of sockets) s.destroy();
    for (const s of servers) s.close();
    await delay(100);
    for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill('SIGKILL');
  }
}

/** Network-only integration fixture: all NICs/endpoints live in disposable namespaces. */
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { execFileSync, spawn } from 'node:child_process';
import { statSync, writeFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { assertBrowserNamespace } from './browser-soak.mjs';
import { inspectIngress, installIngressRouting, INGRESS_TABLE, INGRESS_PRIORITY } from './ingress-routing.mjs';

const run = (file, args) => execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const ip = (...args) => run('ip', args);
const at = (name, ...args) => ip('netns', 'exec', name, ...args);
const source = `
  const net = require('net'), dgram = require('dgram');
  const tag = process.argv[1];
  const servers = [18080, 443].map(port => new Promise(resolve => {
    const callback = s => { s.on('error',()=>{}); s.end(tag + ':' + s.remoteAddress); };
    const directory = process.env.INGRESS_CERT_DIR;
    const server = port === 443 && directory ? require('tls').createServer({
      key: require('fs').readFileSync(directory + '/privkey.pem'),
      cert: require('fs').readFileSync(directory + '/fullchain.pem'), minVersion:'TLSv1.3',
    }, callback) : net.createServer(callback);
    server.listen(port, '0.0.0.0', resolve);
  }));
  servers.push(new Promise(resolve => {
    const s = dgram.createSocket('udp4'); s.on('message', (b,r) => s.send(Buffer.from(tag + ':' + r.address), r.port, r.address)); s.bind(53, '93.184.216.34', resolve);
  }));
  servers.push(new Promise(resolve => net.createServer(s => s.end(tag)).listen({port:18080, host:'::', ipv6Only:true}, resolve)));
  if (process.env.INGRESS_CERT_DIR) servers.push(new Promise(resolve => {
    const {parseDnsQuery, fixtureDnsAnswer} = require('./scripts/lib/lab-dns-wire.mjs');
    const dns = dgram.createSocket('udp4');
    dns.on('message', (b,r) => {
      try {
        const q = parseDnsQuery(b), known = q.name === 'origin.test';
        dns.send(fixtureDnsAnswer(b, {rcode:known ? 0 : 3, count:q.type === 1 ? 1 : 0,
          ...(q.type === 1 ? {rdata:Buffer.from([93,184,216,34])} : {})}), r.port, r.address);
      } catch {}
    });
    dns.bind(53, '127.0.0.55', resolve);
  }));
  Promise.all(servers).then(() => console.log('READY'));
`;

async function ready(child) {
  let stderr = '';
  child.stderr.on('data', (b) => { stderr += b; });
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (b) => { if (String(b).includes('READY')) resolve(); });
    child.once('exit', (code) => reject(new Error(`fixture exited ${code}: ${stderr}`)));
    child.once('error', reject);
  });
}

async function query(namespace, address = '93.184.216.34', port = 18080, udp = false, certificate = null) {
  const code = `
    const finish = b => { console.log(String(b)); process.exit(0); };
    setTimeout(() => finish('BLOCKED'), ${process.env.MESHPN_INGRESS_VM === '1' ? 4000 : 900});
    ${udp ? `const s = require('dgram').createSocket('udp4'); s.on('error',()=>finish('BLOCKED'));
      s.on('message',finish); s.send(Buffer.from('test'), ${port}, '${address}');`
    : `const s = require('${certificate ? 'tls' : 'net'}').connect({host:'${address}',port:${port},
      ${certificate ? `servername:'origin.test', ca:require('fs').readFileSync(${JSON.stringify(certificate)}), minVersion:'TLSv1.3',` : ''}});
      s.on('error',()=>finish('BLOCKED')); s.on('data',finish);`}
  `;
  const child = spawn(namespace ? 'ip' : process.execPath,
    namespace ? ['netns', 'exec', namespace, process.execPath, '-e', code] : ['-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '', error = '';
  child.stdout.on('data', (b) => { output += b; }); child.stderr.on('data', (b) => { error += b; });
  const [status] = await once(child, 'exit'); assert.equal(status, 0, error); return output.trim();
}

export async function runIngressRoutingLab({ transport = null, directory = null } = {}) {
  assertBrowserNamespace();
  assert.deepEqual(JSON.parse(ip('-j', 'link', 'show')).map((l) => l.ifname), ['lo']);
  // /run/netns belongs solely to this private mount namespace, never to the host.
  run('mount', ['--make-rprivate', '/']); run('mount', ['-t', 'tmpfs', 'tmpfs', '/run']);
  ip('link', 'set', 'lo', 'up');
  run('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  run('sysctl', ['-w', 'net.ipv6.conf.all.forwarding=1']);
  run('sysctl', ['-w', 'net.ipv6.conf.default.forwarding=1']);
  run('sysctl', ['-w', 'net.ipv6.conf.default.accept_dad=0']);
  const children = [], servers = [], checks = [];
  const check = (name, actual, expected) => { assert.equal(actual, expected, name); checks.push(name); };
  async function link(name, iface, prefix, v6) {
    ip('netns', 'add', name);
    ip('link', 'add', iface, 'type', 'veth', 'peer', 'name', `${iface}p`);
    ip('link', 'set', `${iface}p`, 'netns', name);
    at(name, 'sysctl', '-w', `net.ipv6.conf.${iface}p.accept_dad=0`);
    ip('addr', 'add', `${prefix}.1/24`, 'dev', iface); ip('link', 'set', iface, 'up');
    at(name, 'ip', 'link', 'set', 'lo', 'up'); at(name, 'ip', 'link', 'set', `${iface}p`, 'up');
    at(name, 'ip', 'addr', 'add', `${prefix}.2/24`, 'dev', `${iface}p`);
    at(name, 'ip', 'route', 'add', 'default', 'via', `${prefix}.1`);
    ip('-6', 'addr', 'add', `${v6}::1/64`, 'dev', iface, 'nodad');
    at(name, 'ip', '-6', 'addr', 'add', `${v6}::2/64`, 'dev', `${iface}p`, 'nodad');
    at(name, 'ip', '-6', 'route', 'add', 'default', 'via', `${v6}::1`);
  }
  async function listen(address, port, tag) {
    const server = net.createServer((s) => { s.on('error', () => {}); s.end(tag); });
    servers.push(server); server.listen(port, address); await once(server, 'listening'); return server;
  }
  const snapshot = () => JSON.stringify({
    routes: ip('-j', '-4', 'route', 'show', 'table', 'main'), rules: ip('-j', '-4', 'rule', 'show'),
    filter: run('iptables', ['-S']), nat: run('iptables', ['-t', 'nat', '-S']), v6: run('ip6tables', ['-S']),
    rp: run('sysctl', ['-n', 'net.ipv4.conf.wg0.rp_filter']),
  });
  try {
    if (transport) {
      assert.ok(['tls', 'boring-tls', 'transparent-tls', 'combo-tls'].includes(transport));
      assert.ok(directory);
      run('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
        '-subj', '/CN=vpn.test', '-addext', 'subjectAltName=DNS:vpn.test,DNS:origin.test',
        '-keyout', join(directory, 'privkey.pem'), '-out', join(directory, 'fullchain.pem')]);
      run('openssl', ['rand', '-out', join(directory, 'secret.key'), '32']);
      // Only this private mount namespace sees the fixture resolver; no host DNS edits or external queries.
      const resolver = join(directory, 'resolv.conf');
      writeFileSync(resolver, 'nameserver 127.0.0.55\noptions timeout:1 attempts:1\n', { flag: 'wx', mode: 0o644 });
      run('mount', ['--bind', resolver, realpathSync('/etc/resolv.conf')]);
    }
    await link('peer', 'wg0', '10.44.0', 'fd00:44');
    await link('other', 'other0', '10.45.0', 'fd00:45');
    await link('uplink', 'uplink0', '192.0.2', 'fd00:46');
    ip('route', 'add', 'default', 'via', '192.0.2.2');
    ip('-6', 'route', 'add', 'default', 'via', 'fd00:46::2');
    ip('route', 'add', '10.55.0.0/24', 'via', '192.0.2.2');
    run('iptables', ['-t', 'nat', '-A', 'POSTROUTING', '-o', 'uplink0', '-j', 'MASQUERADE']);
    const ingress = inspectIngress('wg0');
    // A veth emulates the TUN next hop; actual transport/TLS is outside this routing fixture.
    await link('tunnel', 'cvpntun', '10.99.0', 'fd00:99');
    ip('addr', 'del', '10.99.0.1/24', 'dev', 'cvpntun');
    at('tunnel', 'ip', 'addr', 'del', '10.99.0.2/24', 'dev', 'cvpntunp');
    ip('addr', 'add', '10.99.0.2/24', 'dev', 'cvpntun');
    at('tunnel', 'ip', 'addr', 'add', '10.99.0.1/24', 'dev', 'cvpntunp');
    at('tunnel', 'ip', 'route', 'replace', 'default', 'via', '10.99.0.2');
    for (const name of ['uplink', 'tunnel']) {
      at(name, 'ip', 'addr', 'add', '93.184.216.34/32', 'dev', 'lo');
      at(name, 'ip', 'addr', 'add', '10.55.0.1/32', 'dev', 'lo');
      at(name, 'ip', '-6', 'addr', 'add', '2606:4700::1111/128', 'dev', 'lo', 'nodad');
      const child = spawn('ip', ['netns', 'exec', name, process.execPath, '-e', source, name], {
        stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...(transport ? { INGRESS_CERT_DIR: directory } : {}) },
      });
      children.push(child); await ready(child);
    }
    await listen('10.44.0.1', 443, 'gateway');
    check('baseline forwarded IPv4', await query('peer'), 'uplink:192.0.2.1');
    check('baseline forwarded IPv6', await query('peer', '2606:4700::1111'), 'uplink');
    if (transport) {
      // Replace the simulated TUN link with an ordinary transport network. The CLI creates real TUNs.
      ip('addr', 'del', '10.99.0.2/24', 'dev', 'cvpntun');
      at('tunnel', 'ip', 'addr', 'del', '10.99.0.1/24', 'dev', 'cvpntunp');
      ip('addr', 'add', '192.0.3.1/24', 'dev', 'cvpntun');
      at('tunnel', 'ip', 'addr', 'add', '192.0.3.2/24', 'dev', 'cvpntunp');
      at('tunnel', 'ip', 'route', 'replace', 'default', 'via', '192.0.3.1');
      // TUN ioctls create interfaces in the caller's private network namespace, not on the host.
      // Do not try to create device nodes from an unprivileged user namespace; use the VM fixture if absent.
      assert.ok(statSync('/dev/net/tun', { throwIfNoEntry: false })?.isCharacterDevice(),
        'real transport lab requires /dev/net/tun; use the NIC-less ingress VM lab when unavailable');
      const cli = join(process.cwd(), 'scripts/clean-vpn.js');
      const common = [`--tls-cert-dir=${directory}`, `--shared-hmac-key=${join(directory, 'secret.key')}`, '--tls-public-name=vpn.test'];
      const logs = [];
      const launch = (namespace, args, marker) => {
        const child = spawn(namespace ? 'ip' : process.execPath,
          namespace ? ['netns', 'exec', namespace, process.execPath, cli, ...args] : [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
        children.push(child);
        const started = new Promise((resolve, reject) => {
          let output = '';
          for (const stream of [child.stdout, child.stderr]) stream.on('data', (b) => {
            output += b; logs.push(String(b)); if (output.includes(marker)) resolve();
          });
          child.once('exit', (code) => reject(new Error(`CLI startup ${code}: ${output}`))); child.once('error', reject);
        });
        return { child, started };
      };
      const stop = async (child, signal) => {
        const ended = once(child, 'exit'); child.kill(signal); const [code, sig] = await ended;
        if (signal === 'SIGTERM') assert.equal(code, 0, logs.join('')); else assert.equal(sig, signal);
      };
      const baseline = snapshot();
      const exitType = transport === 'boring-tls' ? 'tls' : transport;
      const exit = launch('tunnel', ['--role=exit', `--type=${exitType}`, '--server=192.0.3.2:24443', '--ext=cvpntunp', ...common],
        exitType === 'tls' ? 'exit TLS 192.0.3.2:24443' : `exit ${exitType} `);
      await exit.started;
      const client = launch(null, ['--role=client', `--type=${transport}`, '--server=192.0.3.2:24443', '--from-tun=wg0',
        '--tls-server-name=vpn.test', '--tls-client-sni=vpn.test', ...common], '--from-tun=wg0:');
      await client.started;
      try {
        let reply;
        for (let attempt = 0; attempt < 4; attempt++) { reply = await query('peer'); if (reply !== 'BLOCKED') break; }
        check(`${transport} actual TUN data plane`, reply, 'tunnel:10.99.0.2');
        const cert = join(directory, 'fullchain.pem');
        const https = await query('peer', '93.184.216.34', 443, false, cert);
        check(`${transport} real application TLS`, https,
          ['combo-tls', 'transparent-tls'].includes(transport) ? 'tunnel:93.184.216.34' : 'tunnel:10.99.0.2');
        check('actual CLI host HTTPS unaffected', await query(null, '93.184.216.34', 443, false, cert), 'uplink:192.0.2.1');
        check('actual CLI other ingress unaffected', await query('other'), 'uplink:192.0.2.1');
        check('actual CLI external UDP DNS through TUN', await query('peer', '93.184.216.34', 53, true), 'tunnel:10.99.0.2');
        check('actual CLI selected IPv6 blocked', await query('peer', '2606:4700::1111'), 'BLOCKED');
        await stop(client.child, 'SIGTERM');
        check('actual CLI graceful cleanup exact', snapshot(), baseline);
        const crashing = launch(null, ['--role=client', `--type=${transport}`, '--server=192.0.3.2:24443', '--form-tun=wg0',
          '--tls-server-name=vpn.test', '--tls-client-sni=vpn.test', ...common], '--from-tun=wg0:');
        await crashing.started;
        // Confirm complete transport/interception startup before killing the owner.
        for (let attempt = 0; attempt < 4; attempt++) { reply = await query('peer'); if (reply !== 'BLOCKED') break; }
        check('alias and CLI restart', reply, 'tunnel:10.99.0.2');
        await stop(crashing.child, 'SIGKILL');
        check('actual CLI SIGKILL removes TUN without IPv4 leak', await query('peer'), 'BLOCKED');
        check('actual CLI SIGKILL leaves HTTPS blocked', await query('peer', '93.184.216.34', 443, false, cert), 'BLOCKED');
        check('actual CLI SIGKILL leaves IPv6 guard', await query('peer', '2606:4700::1111'), 'BLOCKED');
        check('actual CLI SIGKILL does not affect host', await query(null), 'uplink:192.0.2.1');
        await stop(exit.child, 'SIGTERM');
        return { status: 'passed', checks, hostNetworkChanged: false, actualTransportTested: transport };
      } catch (error) { throw new Error(`${error.stack}\nCLI logs:\n${logs.join('')}`, { cause: error }); }
    }
    const before = snapshot();
    const routing = installIngressRouting({ ingress, tun: 'cvpntun' });
    check('selected ingress through TUN with SNAT', await query('peer'), 'tunnel:10.99.0.2');
    check('external UDP DNS also through TUN', await query('peer', '93.184.216.34', 53, true), 'tunnel:10.99.0.2');
    check('host IPv4 unchanged', await query(null), 'uplink:192.0.2.1');
    check('other ingress unchanged', await query('other'), 'uplink:192.0.2.1');
    check('private LAN stays direct', await query('peer', '10.55.0.1'), 'uplink:192.0.2.1');
    check('selected ingress IPv6 blocked', await query('peer', '2606:4700::1111'), 'BLOCKED');
    check('other ingress IPv6 unchanged', await query('other', '2606:4700::1111'), 'uplink');
    await listen('10.99.0.2', 19443, 'relay');
    routing.installHttpsRedirect(19443);
    check('HTTPS ingress intercepted', await query('peer', '93.184.216.34', 443), 'relay');
    check('host HTTPS not intercepted', await query(null, '93.184.216.34', 443), 'uplink:192.0.2.1');
    check('other ingress HTTPS not intercepted', await query('other', '93.184.216.34', 443), 'uplink:192.0.2.1');
    check('gateway local HTTPS preserved', await query('peer', '10.44.0.1', 443), 'gateway');
    check('no direct listener access from ingress', await query('peer', '10.99.0.2', 19443), 'BLOCKED');
    check('no direct listener access from other interface', await query('other', '10.99.0.2', 19443), 'BLOCKED');
    ip('-4', 'route', 'del', 'default', 'dev', 'cvpntun', 'metric', '10', 'table', String(INGRESS_TABLE));
    check('missing TUN route is unreachable, no uplink fallback', await query('peer'), 'BLOCKED');
    ip('-4', 'route', 'add', 'default', 'dev', 'cvpntun', 'metric', '10', 'table', String(INGRESS_TABLE));
    ip('-4', 'rule', 'del', 'priority', String(INGRESS_PRIORITY), 'iif', 'wg0', 'lookup', String(INGRESS_TABLE));
    check('missing policy rule is caught by firewall', await query('peer'), 'BLOCKED');
    ip('-4', 'rule', 'add', 'priority', String(INGRESS_PRIORITY), 'iif', 'wg0', 'lookup', String(INGRESS_TABLE));
    routing.close(); check('graceful cleanup restores exact rules/routes', snapshot(), before);
    check('explicit stop restores previous forwarding', await query('peer'), 'uplink:192.0.2.1');

    const owner = spawn(process.execPath, ['--input-type=module', '-e', `
      import {installIngressRouting} from './scripts/lib/ingress-routing.mjs';
      installIngressRouting({ingress:${JSON.stringify(ingress)},tun:'cvpntun'});
      console.log('READY'); setInterval(()=>{},1000);
    `], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(owner); await ready(owner);
    check('second owner installed', await query('peer'), 'tunnel:10.99.0.2');
    const killed = once(owner, 'exit'); owner.kill('SIGKILL'); await killed;
    ip('link', 'del', 'cvpntun'); // Models nonpersistent TUN removal when its owning process dies.
    check('SIGKILL plus TUN disappearance blocks IPv4', await query('peer'), 'BLOCKED');
    check('SIGKILL leaves IPv6 guard', await query('peer', '2606:4700::1111'), 'BLOCKED');
    check('host still direct after crash', await query(null), 'uplink:192.0.2.1');
    assert.throws(() => inspectIngress('wg0')); checks.push('stale state rejected, not silently adopted');
    return { status: 'passed', checks, hostNetworkChanged: false, actualTransportTested: false };
  } finally {
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    for (const server of servers) server.close();
  }
}

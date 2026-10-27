#!/usr/bin/env node
// Rootful container lab only. Unique resources, internal bridge, no published
// ports, no host network writes, no physical-machine access.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { inspectPcap } from './clean-vpn-pcap-fingerprints.mjs';
import { cleanupLab } from './clean-vpn-native-runtime-cleanup.mjs';
import { nativeProcessProbe, latencySummary } from './lib/native-runtime-metrics.mjs';
import { applicationProbe, parseApplicationTimings } from './lib/native-runtime-application-probe.mjs';

const cli = JSON.parse(process.env.CVPN_CONTAINER_COMMAND ?? '["podman"]');
assert.ok(Array.isArray(cli) && cli.length && cli.every(x => typeof x === 'string'));
const image = process.env.CVPN_RUNTIME_IMAGE; assert.ok(image, 'CVPN_RUNTIME_IMAGE required');
const observerImage = process.env.CVPN_OBSERVER_IMAGE;
const gateway = process.env.CVPN_GATEWAY === '1';
const testLauncher = process.env.CVPN_TEST_LAUNCHER === '1';
const soakSeconds = Number(process.env.CVPN_SOAK_SECONDS ?? 0);
assert.ok(Number.isInteger(soakSeconds) && soakSeconds >= 0 && soakSeconds <= 7200, 'soak_limit_0_to_7200_seconds');
const holdAfterReady = Number(process.env.CVPN_LAB_HOLD_AFTER_READY_SECONDS ?? 0);
assert.ok(Number.isInteger(holdAfterReady) && holdAfterReady >= 0 && holdAfterReady <= 60);
const backend = process.env.CVPN_IPTABLES_BACKEND ?? 'nft'; assert.ok(['nft', 'legacy'].includes(backend));
const iptables = 'iptables-' + backend;
const reportPath = path.resolve(process.argv[2] ?? ''); assert.ok(process.argv[2] && !fs.existsSync(reportPath), 'new report path required');
const prefix = 'cvpnrt-' + randomBytes(8).toString('hex'), network = prefix + '-net', volume = prefix + '-config';
const label = 'org.meshpn.native-runtime-lab=' + prefix;
const lanNetwork = prefix + '-lan';
const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix)), containers = [], checks = [];
const p = (args, opts = {}) => execFileSync(cli[0], [...cli.slice(1), ...args], { encoding: 'utf8', timeout: 45000, maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'], ...opts });
const e = (name, ...args) => p(['exec', name, ...args]);
const progress = label => { checks.push(label); console.log('RUNTIME_LAB=' + label); };
const wait = async (name, check, seconds = 25) => {
  let last; for (let i = 0; i < seconds; i++) { try { return check(); } catch (error) {
    last = error;
    if (!JSON.parse(p(['inspect', name]))[0].State.Running) break;
    await delay(1000);
  } }
  console.error(p(['logs', name])); throw last;
};
const put = (name, data) => fs.writeFileSync(path.join(root, name), data, { mode: 0o600 });
let completed = false, error, cleanupErrors = [], networkCreated = false, volumeCreated = false, lanCreated = false;
const report = { schema: 1, kind: 'native-runtime-container-lab', image, backend: cli, firewallBackend: backend, checks, status: 'running', scope: 'internal-lab-only' };
const ownership = reportPath + '.ownership.json';
const ownershipFd = fs.openSync(ownership, 'wx', 0o600);
try { fs.writeFileSync(ownershipFd, JSON.stringify({ schema: 1, kind: 'native-runtime-lab-ownership', prefix, cli, temp: root }) + '\n'); fs.fsyncSync(ownershipFd); }
finally { fs.closeSync(ownershipFd); }
try {
  const built = JSON.parse(p(['image', 'inspect', image]))[0];
  report.imageId = built.Id; report.architecture = built.Architecture;
  report.engineSha256 = p(['run', '--rm', '--network=none', '--entrypoint=sha256sum', image, '/usr/local/bin/clean-vpn-engine']).split(/\s+/)[0];
  const parent = p(['run', '--rm', '--network=host', '--entrypoint=readlink', image, '/proc/self/ns/net']).trim();
  assert.match(parent, /^net:\[\d+\]$/);
  p(['network', 'create', '--label', label, '--internal', '--subnet=10.77.0.0/24', network]); networkCreated = true;
  if (gateway) { p(['network', 'create', '--label', label, '--internal', '--subnet=192.168.88.0/24', lanNetwork]); lanCreated = true; }
  p(['volume', 'create', '--label', label, volume]); volumeCreated = true;
  const init = prefix + '-init'; containers.push(init);
  p(['run', '-d', '--name', init, '--label', label, '--no-healthcheck', '--memory=96m', '--pids-limit=96', '--network=none', '-v', `${volume}:/config`, '--entrypoint=sleep', image, String(soakSeconds + 1800)]);
  const cert = ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=runtime.test',
    '-addext', 'subjectAltName=DNS:runtime.test', '-keyout', '/config/key.pem', '-out', '/config/cert.pem'];
  p(['exec', init, 'openssl', ...cert], { stdio: ['ignore', 'pipe', 'pipe'] });
  p(['exec', init, 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=wrong-ca',
    '-keyout', '/config/wrong-key.pem', '-out', '/config/wrong-ca.pem']);
  put('psk', randomBytes(32));
  const client = { version: 1, role: 'client', tun: 'cvpn0', address: '10.77.0.2', port: 443,
    secret_path: '/config/psk', ca: '/config/cert.pem', server_name: 'runtime.test', dns: true, tls_profile_path: '/config/profile.json' };
  put('client.json', JSON.stringify(client));
  put('wrong.psk', randomBytes(32));
  const negatives = [['wrong-name', { server_name: 'wrong.test' }], ['wrong-psk', { secret_path: '/config/wrong.psk' }],
    ['wrong-ca', { ca: '/config/wrong-ca.pem' }], ['unreachable-exit', { address: '10.77.0.99' }]];
  for (const [label, patch] of negatives) put(label + '.json', JSON.stringify({ ...client, ...patch }));
  put('exit.json', JSON.stringify({ version: 1, role: 'exit', tun: 'cvpn0', address: '10.77.0.2', port: 443,
    secret_path: '/config/psk', cert: '/config/cert.pem', key: '/config/key.pem', alps: true }));
  put('profile.json', fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json'));
  put('origin.mjs', fs.readFileSync('scripts/lib/native-runtime-lab-origin.mjs'));
  p(['cp', root + '/.', `${init}:/config/`]); e(init, 'sh', '-c', 'chmod 600 /config/*');
  const base = name => ['run', '-d', '--name', name, '--label', label, '--memory=128m', '--pids-limit=96', '--network', network, '--no-healthcheck', '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
    '--cap-add=NET_BIND_SERVICE', '--device=/dev/net/tun', '--security-opt=no-new-privileges', '--read-only',
    '--tmpfs=/run:rw,nosuid,nodev,mode=755', '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777', '-v', `${volume}:/config:ro`, '-e', `CVPN_PARENT_NETNS=${parent}`, '-e', `CVPN_IPTABLES_BACKEND=${backend}`];
  const origin = prefix + '-origin'; containers.push(origin);
  p([...base(origin), '--ip=10.77.0.4', '--entrypoint=sh', image, '-c',
    'ip addr add 198.18.0.80/32 dev lo; exec node /config/origin.mjs']);
  await wait(origin, () => assert.match(p(['logs', origin]), /ORIGIN_READY/));
  const exit = prefix + '-exit'; containers.push(exit);
  const defaultRoute = 'ip route show default | grep -q . || ip route add default via 10.77.0.1 dev eth0; ';
  p([...base(exit), '--ip=10.77.0.2', '--sysctl=net.ipv4.ip_forward=1', '--entrypoint=sh', image, '-ec',
    defaultRoute + 'ip route add 198.18.0.80/32 via 10.77.0.4 dev eth0; exec native-runtime /config/exit.json']);
  await wait(exit, () => e(exit, 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs'));
  // Fixture-only DNS destinations; no public upstream queries leave this bridge.
  for (const server of ['1.1.1.1', '8.8.8.8']) for (const proto of ['udp', 'tcp'])
    e(exit, iptables, '-t', 'nat', '-A', 'PREROUTING', '-i', 'cvpn0', '-d', server, '-p', proto, '--dport', '53', '-j', 'DNAT', '--to-destination', '10.77.0.4:5353');
  const capture = prefix + '-capture';
  if (observerImage) {
    containers.push(capture);
    p(['run', '-d', '--name', capture, '--label', label, '--memory=96m', '--pids-limit=96', '--network=container:' + exit, '--cap-drop=ALL', '--cap-add=NET_RAW', '--cap-add=SETUID', '--cap-add=SETGID',
      '-v', `${volume}:/capture`, '--entrypoint=sh', observerImage, '-c',
      'exec tcpdump -p -n -U -i eth0 -s 0 -c 20000 -w - "tcp dst port 443" > /capture/wire.pcap 2>/capture/capture.log']);
    await wait(capture, () => assert.match(e(init, 'cat', '/config/capture.log'), /listening on eth0/));
  }
  const clientName = prefix + '-client'; containers.push(clientName);
  const launch = action => {
    const engine = path.basename(cli[0]); assert.ok(['docker', 'podman'].includes(engine), 'launcher_requires_direct_engine_cli');
    const args = ['scripts/clean-vpn-native-container.mjs', action, '--engine=' + engine, '--name=' + clientName];
    if (cli.length > 1) { assert.deepEqual(cli.slice(1, 2), ['--connection']); assert.equal(cli.length, 3); args.push('--connection=' + cli[2]); }
    if (action === 'start') args.push('--role=client', '--image=' + image, '--network=' + network, '--ip=10.77.0.3',
      '--config-volume=' + volume, '--config-file=client.json', '--lab-owner=' + prefix,
      ...(gateway ? ['--lan-network=' + lanNetwork, '--lan-ip=192.168.88.2', '--lan-subnet=192.168.88.0/24'] : []));
    return execFileSync(process.execPath, args, { encoding: 'utf8', timeout: 60000,
      env: { ...process.env, PATH: path.dirname(cli[0]) + ':' + process.env.PATH }, stdio: ['ignore', 'pipe', 'pipe'] });
  };
  if (testLauncher) launch('start');
  else {
  p([...base(clientName), '--ip=10.77.0.3', ...(gateway ? ['--sysctl=net.ipv4.ip_forward=1', '-e', 'CVPN_UPLINK=auto', '-e', 'CVPN_LAN_INTERFACE=auto', '-e', 'CVPN_LAN_SUBNET=192.168.88.0/24'] : []), '--entrypoint=sh', image, '-ec',
    (gateway ? 'while ! ip link show eth1 >/dev/null 2>&1; do sleep 1; done; ' : '') + defaultRoute +
    `${iptables} -N FOREIGN_SENTINEL; ${iptables} -A OUTPUT -j FOREIGN_SENTINEL; exec native-runtime /config/client.json`]);
  if (gateway) p(['network', 'connect', '--ip=192.168.88.2', lanNetwork, clientName]);
  }
  const health = () => e(clientName, 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs');
  await wait(clientName, health); progress('profiled-tunnel-and-dns-udp-tcp');
  if (testLauncher) {
    assert.equal(JSON.parse(launch('status')).running, true);
    e(clientName, iptables, '-N', 'FOREIGN_SENTINEL'); e(clientName, iptables, '-A', 'OUTPUT', '-j', 'FOREIGN_SENTINEL');
    progress('public-launcher-start-status');
  }
  if (holdAfterReady) { console.log('RUNTIME_LAB_HOLD_FOR_CONTROLLER_FAULT'); await delay(holdAfterReady * 1000); }
  const probe = applicationProbe();
  e(clientName, 'node', '--input-type=module', '-e', probe); progress('loopback-dns-https-tcp-udp');
  let lanApp;
  if (gateway) {
    lanApp = prefix + '-lan-app'; containers.push(lanApp);
    p(['run', '-d', '--name', lanApp, '--label', label, '--memory=96m', '--pids-limit=96', '--network', lanNetwork, '--ip=192.168.88.3', '--cap-drop=ALL', '--cap-add=NET_ADMIN',
      '--read-only', '-v', `${volume}:/config:ro`, '--entrypoint=sh', image, '-ec',
      `ip route replace default via 192.168.88.2 dev eth0; exec sleep ${soakSeconds + 1800}`]);
    assert.match(e(lanApp, 'node', '--input-type=module', '-e', applicationProbe('192.168.88.2')), /APPLICATION_PROBES_OK/);
    progress('isolated-lan-gateway-dns-https-tcp-udp');
  }
  if (soakSeconds) {
    const samples = [], began = performance.now(); let nextRestart = 300, restarts = 0;
    // Keep completed observations even when a later probe fails. The final
    // report must not discard the measurements that led up to a failure.
    report.soak = { requestedSeconds: soakSeconds, samples, restarts: 0, elapsedSeconds: 0, restartEvents: [] };
    while ((performance.now() - began) / 1000 < soakSeconds) {
      const probeStart = performance.now(); health(); const healthEnd = performance.now();
      const applicationTimings = parseApplicationTimings(e(clientName, 'node', '--input-type=module', '-e', probe));
      const applicationEnd = performance.now();
      const lanTimings = lanApp ? parseApplicationTimings(e(lanApp, 'node', '--input-type=module', '-e', applicationProbe('192.168.88.2'))) : undefined;
      const elapsed = Math.round((performance.now() - began) / 1000);
      const sample = { elapsed, applicationTimings, ...(lanTimings ? { lanTimings } : {}), healthWallMs: healthEnd - probeStart, applicationWallMs: applicationEnd - healthEnd,
        ...(lanApp ? { lanWallMs: performance.now() - applicationEnd } : {}) };
      for (const [role, name] of [['client', clientName], ['exit', exit]]) {
        sample[role] = JSON.parse(e(name, 'node', '-e', nativeProcessProbe));
        assert.ok(sample[role].rssKiB < 262144 && sample[role].fds < 128, 'soak_resource_ceiling');
        assert.equal(sample[role].nativeProcesses, 1, 'one_native_process_per_role');
        assert.equal(sample[role].zombies, 0, 'no_zombie_processes');
      }
      samples.push(sample);
      report.soak.elapsedSeconds = elapsed;
      if (samples.length % 6 === 0) console.log('RUNTIME_SOAK_SECONDS=' + elapsed);
      if (elapsed >= nextRestart) {
        const event = { elapsed, signal: restarts % 2 ? 'SIGKILL' : 'SIGTERM' };
        report.soak.restartEvents.push(event);
        if (restarts % 2) p(['kill', '--signal=KILL', clientName]); else p(['stop', '--time=5', clientName]);
        p(['start', clientName]); await wait(clientName, health); restarts++; nextRestart += 300;
        event.readyElapsed = Math.round((performance.now() - began) / 1000); report.soak.restarts = restarts;
      }
      await delay(Math.min(10000, Math.max(0, soakSeconds * 1000 - (performance.now() - began))));
    }
    report.soak = { ...report.soak, elapsedSeconds: Math.round((performance.now() - began) / 1000), restarts, samples,
      latency: Object.fromEntries(['healthWallMs','applicationWallMs',...(lanApp ? ['lanWallMs'] : [])].map(k=>[k,latencySummary(samples.map(s=>s[k]))])) };
    report.soak.transactionLatency = Object.fromEntries(['applicationTimings', ...(lanApp ? ['lanTimings'] : [])].map(group => [group,
      Object.fromEntries(Object.keys(samples[0][group]).map(k => [k, { ...latencySummary(samples.map(s => s[group][k])), scope: 'application-namespace-transaction-no-container-exec' }]))]));
    for (const role of ['client', 'exit']) {
      const warm = samples[Math.min(5, samples.length - 1)][role];
      assert.ok(samples.at(-1)[role].rssKiB - warm.rssKiB < 32768, 'soak_retained_memory_growth');
      assert.ok(samples.at(-1)[role].fds <= warm.fds + 8, 'soak_retained_fd_growth');
      assert.ok(samples.at(-1)[role].sockets <= warm.sockets + 4, 'soak_retained_socket_growth');
    }
    progress('bounded-soak-with-restarts-passed');
  }
  assert.match(e(clientName, iptables + '-save'), /-A OUTPUT -j FOREIGN_SENTINEL/); progress('foreign-rules-preserved');
  // Re-entry audits protection instead of duplicating jumps. No second engine.
  e(clientName, 'node', '/opt/clean-vpn/clean-vpn-native-runtime.mjs', '/config/client.json'); progress('same-namespace-reentry-audited');
  const unhealthy = name => {
    let error;
    try { e(name, 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs'); } catch (caught) { error = caught; }
    assert.equal(error?.status, 1); assert.match(String(error.stderr), /NATIVE_HEALTH=unhealthy/);
  };
  // A live authenticated TLS connection alone must not make DNS healthy.
  for (const proto of ['udp', 'tcp']) e(exit, iptables, '-I', 'CVPN_R_FORWARD', '1', '-p', proto, '--dport', '5353', '-j', 'DROP');
  unhealthy(clientName); progress('unreachable-upstreams-unhealthy');
  for (const proto of ['udp', 'tcp']) e(exit, iptables, '-D', 'CVPN_R_FORWARD', '-p', proto, '--dport', '5353', '-j', 'DROP');
  await wait(clientName, health); progress('dns-restores-with-upstream');
  let ip = 5;
  for (const [label] of negatives) {
    const name = prefix + '-' + label; containers.push(name);
    p([...base(name), '--ip=10.77.0.' + ip++, '--entrypoint=sh', image, '-ec', defaultRoute + `exec native-runtime /config/${label}.json`]);
    await wait(name, () => assert.match(p(['logs', name]), /"state":"connecting"/));
    unhealthy(name); p(['stop', '--time=5', name]); progress(label + '-unhealthy');
  }
  for (const [label, args] of [['without-net-admin', ['--cap-drop=ALL']], ['without-tun', ['--cap-add=NET_ADMIN', '--cap-add=NET_RAW']]]) {
    let refused = false;
    try { p(['run', '--rm', '--network', network, ...args, '-v', `${volume}:/config:ro`, '-e', `CVPN_PARENT_NETNS=${parent}`, image, '/config/client.json'], { stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { refused = true; } assert.ok(refused); progress(label + '-refused');
  }
  let hostError;
  try { p(['run', '--rm', '--network=host', '--cap-drop=ALL', '-v', `${volume}:/config:ro`, '-e', `CVPN_PARENT_NETNS=${parent}`, image, '/config/client.json']); }
  catch (caught) { hostError = caught; }
  assert.match(String(hostError?.stderr), /host_network_refused/); progress('host-network-refused-before-mutation');
  if (testLauncher) {
    launch('stop'); assert.equal(JSON.parse(launch('status')).running, false);
    p(['start', clientName]); await wait(clientName, health); progress('public-launcher-stop-and-restart');
  }
  // Namespace held by an ordinary app after PID 1 dies: guard must survive.
  const app = prefix + '-app'; containers.push(app);
  p(['run', '-d', '--name', app, '--label', label, '--memory=96m', '--pids-limit=96', '--network=container:' + clientName, '--cap-drop=ALL', '-v', `${volume}:/config:ro`, '--entrypoint=sleep', image, '600']);
  assert.match(e(app, 'node', '--input-type=module', '-e', probe), /APPLICATION_PROBES_OK/); progress('unprivileged-shared-namespace-application');
  p(['kill', '--signal=KILL', clientName]);
  const blocked = `const net=require('node:net');const s=net.connect(5353,'10.77.0.4',()=>{console.error('LEAK');process.exit(2)});s.setTimeout(1200,()=>{s.destroy();console.log('BLOCKED')});s.on('error',()=>console.log('BLOCKED'));`;
  assert.match(e(app, 'node', '-e', blocked), /BLOCKED/); progress('pid1-sigkill-shared-namespace-no-direct-fallback');
  if (lanApp) { assert.match(e(lanApp, 'node', '-e', blocked), /BLOCKED/); progress('lan-gateway-crash-no-direct-fallback'); }
  const deadDns = `import {dnsProbe} from '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs';
    try { await dnsProbe('10.99.0.2',1053,false); process.exitCode=2; }
    catch(e) { if (!/dns_health_timeout|ECONNREFUSED/.test(e.message)) throw e; console.log('DNS_BLOCKED'); }`;
  assert.match(e(app, 'node', '--input-type=module', '-e', deadDns), /DNS_BLOCKED/); progress('dead-engine-app-dns-blocked');
  // Recreate a fresh namespace; never reopen the stranded application's network.
  const replacement = prefix + '-replacement'; containers.push(replacement);
  p([...base(replacement), '--ip=10.77.0.20', '--entrypoint=sh', image, '-ec', defaultRoute + 'exec native-runtime /config/client.json']);
  await wait(replacement, () => e(replacement, 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs'));
  assert.match(e(replacement, 'node', '--input-type=module', '-e', probe), /APPLICATION_PROBES_OK/);
  assert.match(e(app, 'node', '-e', blocked), /BLOCKED/); progress('replacement-works-old-namespace-stays-blocked');
  p(['stop', '--time=5', replacement]); assert.equal(JSON.parse(p(['inspect', replacement]))[0].State.ExitCode, 0); progress('client-sigterm-clean');
  p(['start', replacement]); await wait(replacement, () => e(replacement, 'node', '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs'));
  progress('container-restart-healthy');
  p(['stop', '--time=5', replacement]);
  if (observerImage) {
    p(['stop', '--time=5', capture]);
    assert.equal(JSON.parse(p(['inspect', capture]))[0].State.Running, false);
    p(['cp', `${init}:/config/wire.pcap`, path.join(root, 'wire.pcap')]);
    fs.copyFileSync(path.join(root, 'wire.pcap'), reportPath + '.pcap', fs.constants.COPYFILE_EXCL);
    fs.chmodSync(reportPath + '.pcap', 0o600);
    report.wire = inspectPcap(fs.readFileSync(path.join(root, 'wire.pcap')), { destination: '10.77.0.2', profile: JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-cold.json', 'utf8')) });
    assert.ok(report.wire.connections.length > 0);
    assert.ok(report.wire.connections.every(c => c.profile?.status === 'matched'));
    report.capture = e(init, 'cat', '/config/capture.log').trim(); progress('independent-clienthello-profile-matched');
    assert.match(report.capture, /\b0 packets dropped by kernel\b/);
  }
  p(['stop', '--time=5', exit]); assert.equal(JSON.parse(p(['inspect', exit]))[0].State.ExitCode, 0); progress('exit-sigterm-clean');
  report.clientLogs = p(['logs', clientName]).trim().split('\n').slice(-12);
  if (testLauncher) {
    // Podman requires removing the application before its namespace donor.
    assert.equal(JSON.parse(p(['inspect', app]))[0].Config.Labels['org.meshpn.native-runtime-lab'], prefix);
    p(['rm', '-f', app]); containers.splice(containers.indexOf(app), 1);
    launch('remove'); containers.splice(containers.indexOf(clientName), 1); progress('public-launcher-owned-remove');
  }
  completed = true;
} catch (caught) { error = caught; report.error = String(caught.message).slice(0, 3000); }
finally {
  // Use the same name+label ownership check on normal completion as on an
  // independent recovery. A failed create must never remove a foreign object.
  try { cleanupLab({ schema: 1, kind: 'native-runtime-lab-ownership', prefix }, p); }
  catch (caught) { cleanupErrors.push(String(caught.message).slice(0, 500)); }
  fs.rmSync(root, { recursive: true, force: true });
  report.cleanup = cleanupErrors.length ? { status: 'failed', resources: cleanupErrors } : { status: 'passed' };
  report.status = completed && !cleanupErrors.length ? 'passed' : 'failed';
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
if (error) throw error;
assert.equal(report.status, 'passed'); console.log('RUNTIME_LAB_REPORT=' + reportPath);

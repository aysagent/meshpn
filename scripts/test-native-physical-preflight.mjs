import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseNativePhysicalPreflightArgs, collectNativePhysicalPreflight, assessNativePhysicalPreflight } from './lib/native-physical-preflight.mjs';
import { composeNativePhysicalPair } from './lib/native-physical-pair-plan.mjs';

const empty = table => `*${table}\n${table === 'filter' ? ':INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n' : ':PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n'}COMMIT\n`;
function fixture(t, role = 'client') {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'native-physical-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const binary = dir + '/engine', config = dir + '/config.json', siteProfile = dir + '/site.json';
  const engine = Buffer.alloc(64); engine.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]); engine.writeUInt16LE(process.arch === 'arm64' ? 183 : 62, 18);
  fs.writeFileSync(binary, engine, { mode: 0o700 });
  for (const name of ['boring.psk', 'relay.psk']) fs.writeFileSync(dir + '/' + name, Buffer.alloc(32, name === 'boring.psk' ? 1 : 2), { mode: 0o600 });
  for (const name of ['cert.pem', 'key.pem']) fs.writeFileSync(dir + '/' + name, name, { mode: 0o600 });
  const profile = { version: 1, transport: 'combo-tls', role, tun: 'tun9', tun_address: role === 'client' ? '10.99.0.2/32' : '10.99.0.1/24',
    mtu: 1400, uplink: 'wan0', endpoint: '198.51.100.10', port: 443, listen_port: role === 'client' ? 2443 : 443,
    lan: role === 'client' ? { interface: 'lan0', subnet: '192.168.7.0/24' } : null, deny_ipv4: [] };
  const boring = { version: 1, role, tun: 'tun9', address: profile.endpoint, port: 443,
    ...(role === 'client' ? { secret_path: dir + '/boring.psk', ca: dir + '/cert.pem', server_name: 'vpn.example', sni: 'cover.example', dns: true } :
      { cert: dir + '/cert.pem', key: dir + '/key.pem', peers: [{ ipv4: '10.99.0.2', secret_path: dir + '/boring.psk' }] }) };
  const transparent = { version: 1, transport: 'transparent-tls', role, public_name: 'cover.example', secret_path: dir + '/relay.psk',
    destination_policy: { mode: 'public-https', deny_ipv4: [] }, listen: { ipv4: role === 'client' ? '0.0.0.0' : profile.endpoint, port: profile.listen_port },
    ...(role === 'client' ? { exit: { ipv4: profile.endpoint, port: 443 } } : { replay_directory: dir + '/future-replay' }) };
  fs.writeFileSync(config, JSON.stringify({ version: 1, transport: 'combo-tls', role, boring, transparent }), { mode: 0o600 });
  fs.writeFileSync(siteProfile, JSON.stringify({ link_unit: 'trial-links.service', profile }), { mode: 0o600 });
  const capabilities = { engine: 'clean-vpn-native-m1', packet_ipc: false, service_mode: true, dns_socket_mark: '0x43564e',
    experimental_transports: { 'combo-tls': { single_exit_listener: true, packet_ipc: false, site_provisioning: true },
      'transparent-tls': { durable_replay: true, client_interception: 'SO_ORIGINAL_DST', destination_policies: ['public-https'] } } };
  const calls = [];
  const run = async (file, args, options) => {
    calls.push([file, args, options]); let stdout = '';
    if (file === binary && args[0] === '--capabilities') stdout = JSON.stringify(capabilities);
    else if (file === binary && args[0] === '--check-config') stdout = '';
    else if (file === 'git') stdout = 'abcdef0\n';
    else if (file === 'ip' && args.includes('link')) stdout = JSON.stringify([{ ifname: 'wan0', ifindex: 2, flags: ['BROADCAST'], link_type: 'ether' }, ...(role === 'client' ? [{ ifname: 'lan0', ifindex: 3, flags: ['BROADCAST'], link_type: 'ether' }] : [])]);
    else if (file === 'ip' && args.includes('address')) stdout = JSON.stringify([{ ifname: 'wan0', addr_info: role === 'exit' ? [{ family: 'inet', local: profile.endpoint, prefixlen: 24 }] : [{ family: 'inet', local: '192.0.2.2', prefixlen: 24 }] }, ...(role === 'client' ? [{ ifname: 'lan0', addr_info: [{ family: 'inet', local: '192.168.7.1', prefixlen: 24 }] }] : [])]);
    else if (file === 'ip' && args.includes('get')) stdout = JSON.stringify([{ dev: 'wan0' }]);
    else if (file === 'ip') stdout = '[]';
    else if (file === 'ss') stdout = '';
    else if (file === 'sysctl') stdout = '0\n';
    else if (file === 'iptables-save') stdout = args.length ? empty(args.at(-1)) : empty('filter') + empty('nat') + empty('mangle') + '*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n';
    else if (file === 'ip6tables-save') stdout = args.length ? empty('filter') : empty('filter') + '*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n';
    else if (file === 'systemctl') {
      const unit = args[2]; stdout = unit === 'trial-links.service' ? 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\nFragmentPath=/etc/systemd/system/trial-links.service\n' : 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\nFragmentPath=\n';
    }
    return { code: 0, reason: null, signal: null, stdout, stderr: '', durationMs: 1 };
  };
  return { options: { role, name: `trial-${role}`, binary, config, siteProfile }, run, calls, capabilities,
    deps: { run, dryRun: () => ({ status: 'eligible' }), runtime: { node: process.version, platform: 'linux', arch: process.arch, uid: 0 },
      hostFacts: { pid1: 'systemd', sameNetworkNamespace: true, tunDevice: true, earlyNetworkParameters: [] },
      tools: Object.fromEntries(['git', 'ip', 'ss', 'systemctl', 'sysctl', 'iptables', 'ip6tables', 'iptables-save', 'ip6tables-save', 'iptables-restore', 'ip6tables-restore'].map(name => [name, '/usr/bin/' + name])) } };
}

test('strict parser has no apply, probe or implicit role path', () => {
  const args = ['--role=client', '--name=trial-client', '--binary=/x/engine', '--config=/x/config.json', '--site-profile=/x/site.json'];
  assert.deepEqual(parseNativePhysicalPreflightArgs(args), { role: 'client', name: 'trial-client', binary: '/x/engine', config: '/x/config.json', siteProfile: '/x/site.json' });
  for (const bad of [[], [...args, '--apply'], args.slice(1), args.map(v => v.replace('/x/engine', 'relative'))]) assert.throws(() => parseNativePhysicalPreflightArgs(bad));
  assert.equal(parseNativePhysicalPreflightArgs([...args, `--pair-challenge=${'ab'.repeat(32)}`]).pairChallenge, 'ab'.repeat(32));
  assert.throws(() => parseNativePhysicalPreflightArgs([...args, '--pair-challenge=AB']));
});
for (const role of ['client', 'exit']) test(`valid ${role} fixture produces exact plan without mutation authority`, async t => {
  const f = fixture(t, role), report = await collectNativePhysicalPreflight(f.options, f.deps);
  assert.equal(report.status, 'ready-for-reviewed-trial-plan'); assert.equal(report.mutationAllowed, false);
  assert.equal(report.systemSettingsChanged, false); assert.equal(report.networkProbesSent, 0); assert.equal(report.installationAttempted, false);
  assert.equal(report.engine.architectureMatchesHost, true); assert.equal(report.offlineInstallDryRun.status, 'eligible');
  assert.equal(report.pairProof, null);
  assert.equal(report.plan.units.length, role === 'client' ? 5 : 4); assert.match(report.plan.network.ipv4, /\*filter/);
  assert.ok(!JSON.stringify(report).includes('boring.psk')); assert.ok(!JSON.stringify(report).includes('relay.psk'));
  for (const [file, args] of f.calls) {
    assert.ok(!args.some(value => /^(start|stop|restart|enable|disable|add|del|set|flush|apply)$/.test(value)));
    assert.notEqual(file, 'curl');
  }
});
test('one-use challenge proves both combo secrets without exposing them', async t => {
  const f = fixture(t, 'client'), challenge = '12'.repeat(32);
  const report = await collectNativePhysicalPreflight({ ...f.options, pairChallenge: challenge }, f.deps);
  assert.equal(report.pairProof.challenge, challenge); assert.match(report.pairProof.boring[0].value, /^[0-9a-f]{64}$/);
  assert.match(report.pairProof.relay, /^[0-9a-f]{64}$/);
  const serialized = JSON.stringify(report);
  assert.equal(serialized.includes('boring.psk'), false); assert.equal(serialized.includes('relay.psk'), false);
});
test('real client and exit collectors produce matching one-use proofs', async t => {
  const challenge = '78'.repeat(32), client = fixture(t, 'client'), exit = fixture(t, 'exit');
  const clientReport = await collectNativePhysicalPreflight({ ...client.options, pairChallenge: challenge }, client.deps);
  const exitReport = await collectNativePhysicalPreflight({ ...exit.options, pairChallenge: challenge }, exit.deps);
  const pair = composeNativePhysicalPair(clientReport, exitReport);
  assert.equal(pair.status, 'ready-for-human-approved-transient-design');
  assert.equal(pair.pair.pskProof, 'matched-one-use-challenge');
});
test('live-host conflicts are blockers, never cleanup actions', async t => {
  const f = fixture(t), report = await collectNativePhysicalPreflight(f.options, f.deps);
  report.host.links[0].flags.push('UP'); report.host.forwarding = '1'; report.host.firewall[0].empty = false;
  report.host.listeners = 'tcp LISTEN 0 4096 0.0.0.0:2443 0.0.0.0:*\n';
  const assessment = assessNativePhysicalPreflight(report);
  assert.equal(assessment.status, 'blocked');
  for (const issue of ['fresh-contract-requires-link-down:wan0', 'fresh-forwarding-must-be-disabled', 'dedicated-empty-firewall-contract-not-met', 'listener-port-in-use:tcp:2443']) assert.ok(assessment.observedIssues.includes(issue));
  assert.equal(assessment.mutationAllowed, false);
});

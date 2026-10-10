import test from 'node:test';
import assert from 'node:assert/strict';
import { assessNativeSandboxPreflight, collectNativeSandboxPreflight, parseNativeSandboxPreflightArgs } from './lib/native-sandbox-preflight.mjs';

const toolNames = ['ip', 'ss', 'systemctl', 'sysctl', 'iptables', 'ip6tables', 'iptables-save', 'ip6tables-save', 'iptables-restore', 'ip6tables-restore', 'nft'];
function fixture(role = 'client') {
  const options = { role, name: role === 'client' ? 'radxa' : 'exit', endpoint: '154.62.226.216', port: 18443,
    sandboxCidr: role === 'client' ? '10.203.0.0/30' : '10.203.0.4/30' };
  const calls = [];
  const run = async (file, args) => {
    calls.push([file, args]); let stdout = '';
    if (file === 'ip' && args.includes('link')) stdout = JSON.stringify([{ ifname: role === 'client' ? 'wlan0' : 'eth0', flags: ['UP'] }]);
    else if (file === 'ip' && args.includes('address')) stdout = JSON.stringify([{ ifname: role === 'client' ? 'wlan0' : 'eth0',
      addr_info: [{ family: 'inet', local: role === 'client' ? '192.168.1.8' : options.endpoint, prefixlen: 24 }] }]);
    else if (file === 'ip' && args.includes('get')) stdout = JSON.stringify([{ dev: role === 'client' ? 'wlan0' : 'eth0' }]);
    else if (file === 'ip' && args[0] === 'netns') stdout = '';
    else if (file === 'ip' && args.includes('-4')) stdout = JSON.stringify([{ dst: role === 'client' ? '192.168.1.0/24' : '154.62.226.0/24' }]);
    else if (file === 'ip' && args.includes('-6')) stdout = '[]';
    else if (file === 'ss') stdout = 'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n';
    else if (file === 'sysctl') stdout = role === 'client' ? '1\n' : '0\n';
    else if (file === 'iptables') stdout = 'iptables v1.8.9 (nf_tables)\n';
    else if (file === 'nft') stdout = 'nftables v1.0.6\n';
    else if (file === 'iptables-save' || file === 'ip6tables-save') stdout = '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n';
    else if (file === 'systemctl') {
      const unit = args[2], manager = ['firewalld.service', 'ufw.service', 'nftables.service', 'netfilter-persistent.service',
        'docker.service', 'podman.service', 'libvirtd.service', 'fail2ban.service', 'kubelet.service'].includes(unit);
      stdout = manager ? `LoadState=${unit === 'nftables.service' ? 'loaded' : 'not-found'}\nActiveState=inactive\nUnitFileState=disabled\nFragmentPath=\n`
        : 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\nFragmentPath=\n';
    }
    return { code: 0, reason: null, signal: null, stdout, stderr: '', durationMs: 1 };
  };
  return { options, calls, deps: { run, runtime: { node: process.version, platform: 'linux', arch: process.arch, uid: 0 },
    hostFacts: { pid1: 'systemd', sameNetworkNamespace: true, tunDevice: true },
    tools: Object.fromEntries(toolNames.map(name => [name, `/usr/bin/${name}`])) } };
}

test('strict parser requires an explicit isolated non-primary port and /30', () => {
  const args = ['--role=client', '--name=radxa', '--endpoint=154.62.226.216', '--port=18443', '--sandbox-cidr=10.203.0.0/30'];
  assert.deepEqual(parseNativeSandboxPreflightArgs(args), { role: 'client', name: 'radxa', endpoint: '154.62.226.216', port: 18443, sandboxCidr: '10.203.0.0/30' });
  for (const bad of [args.slice(1), args.map(v => v === '--port=18443' ? '--port=443' : v), args.map(v => v.endsWith('/30') ? '--sandbox-cidr=10.203.0.0/24' : v), [...args, '--apply']])
    assert.throws(() => parseNativeSandboxPreflightArgs(bad));
});

for (const role of ['client', 'exit']) test(`${role} inventory can reach design review without mutation`, async () => {
  const f = fixture(role), report = await collectNativeSandboxPreflight(f.options, f.deps);
  assert.equal(report.status, 'ready-for-sandbox-design-review'); assert.equal(report.mutationAllowed, false);
  assert.equal(report.systemSettingsChanged, false); assert.equal(report.networkProbesSent, 0);
  assert.equal(report.plan.namespace, `cvpn-${f.options.name}`); assert.match(report.host.firewallSnapshots.ipv4Sha256, /^[0-9a-f]{64}$/);
  assert.ok(!f.calls.some(([file, args]) => file === 'ip' && ['add', 'del', 'set', 'exec'].includes(args[0])));
  assert.ok(!f.calls.some(([file, args]) => file === 'systemctl' && args.some(value => ['start', 'stop', 'enable', 'disable'].includes(value))));
});

test('occupied resources, manager ownership and route overlap block without cleanup', async () => {
  const f = fixture('exit'), report = await collectNativeSandboxPreflight(f.options, f.deps);
  report.host.namespaceNames.push(report.plan.namespace); report.host.links.push({ ifname: report.plan.hostVeth });
  report.host.routes4.push({ dst: '10.203.0.0/16' }); report.host.listeners += 'tcp LISTEN 0 4096 0.0.0.0:18443 0.0.0.0:*\n';
  report.host.firewallManagers['nftables.service'].ActiveState = 'active';
  const result = assessNativeSandboxPreflight(report);
  assert.equal(result.status, 'blocked'); assert.equal(result.mutationAllowed, false);
  for (const issue of ['sandbox-namespace-already-present', `sandbox-link-already-present:${report.plan.hostVeth}`,
    'sandbox-cidr-overlaps-host-route', 'trial-port-in-use', 'concurrent-firewall-manager-active:nftables.service'])
    assert.ok(result.observedIssues.includes(issue));
});

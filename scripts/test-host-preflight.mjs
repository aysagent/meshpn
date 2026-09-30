import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHostPreflightArgs, collectHostPreflight, assessHostPreflight } from './lib/host-preflight.mjs';

const missing = () => { throw Object.assign(Error('absent'), { code: 'ENOENT' }); };
function fixture({ tun = false, malformed = false } = {}) {
  const calls = [], reads = [];
  const io = {
    constants: { X_OK: 1 }, accessSync() {}, lstatSync: missing,
    statSync: () => ({ size: 0, isFile: () => true, isCharacterDevice: () => true }),
    readlinkSync: () => 'net:[1]',
    readFileSync(path) {
      reads.push(path);
      if (path === '/proc/1/comm') return 'systemd\n';
      if (path === '/proc/cmdline') return 'console=ttyS0 secret=do-not-print';
      if (path === '/run/systemd/netif/links/2') return 'NETWORK_FILE=/run/systemd/network/10-netplan-wlan0.network\nSETUP_STATE=configured\nWIFI_PASSWORD=do-not-print\nDNS=private-name';
      return missing();
    }
  };
  const run = async (file, args, options) => {
    calls.push([file, args, options]);
    if (options.signal.aborted) return { code: null, reason: 'aborted', stdout: '' };
    let stdout = '';
    if (file === 'git') stdout = 'abcdef0\n';
    if (file === 'systemctl') {
      const active = args.includes('systemd-networkd.service') || args.includes('systemd-networkd.socket');
      stdout = `LoadState=${active ? 'loaded' : 'not-found'}\nActiveState=${active ? 'active' : 'inactive'}\nUnitFileState=${active ? 'enabled' : ''}\n`;
    }
    if (file === 'ip') stdout = JSON.stringify(args.includes('link') ? [{ ifname: 'wlan0', ifindex: 2 }, ...(tun ? [{ ifname: 'tun0' }] : [])] : args.includes('get') ? [{ dev: 'wlan0' }] : []);
    if (malformed && file === 'ip') stdout = '[null]';
    return { code: 0, signal: null, reason: null, stdout, stderr: '', durationMs: 1 };
  };
  return { io, run, calls, reads, runtime: { uid: 0 } };
}
test('preflight parses only one numeric exit, with no installation/probe options', () => {
  assert.deepEqual(parseHostPreflightArgs(['--exit-ip=154.62.226.216']), { exitIp: '154.62.226.216' });
  for (const args of [[], ['--apply'], ['--exit-ip=host'], ['--exit-ip=::1'], ['--exit-ip=1.2.3.4', '--probe'], ['--exit-ip=1.2.3.4', '--exit-ip=1.2.3.4']]) assert.throws(() => parseHostPreflightArgs(args));
});
test('read-only report requires human review even with good inventory; filters secrets', async () => {
  const f = fixture(), r = await collectHostPreflight({ exitIp: '154.62.226.216' }, f);
  assert.equal(r.status, 'inventory-ready-for-review'); assert.equal(r.systemSettingsChanged, false); assert.equal(r.networkProbesSent, 0);
  assert.equal(r.requiredHumanReview.length, 5); assert.equal(r.uplink, 'wlan0');
  assert.doesNotMatch(JSON.stringify(r), /do-not-print|WIFI_PASSWORD|private-name/);
  assert.equal(f.calls.length, 17);
  for (const [file, args, opts] of f.calls) {
    assert.ok(['ip', 'git', 'systemctl'].includes(file));
    assert.ok(!args.some(a => /^(start|stop|restart|enable|disable|daemon-reload|add|del|flush|apply)$/.test(a)));
    if (file === 'systemctl') assert.equal(args[1], 'show');
    assert.equal(opts.timeoutMs, 4000); assert.equal(opts.maxBytes, 65536);
  }
  assert.ok(f.reads.every(p => p.startsWith('/proc/') || p === '/run/systemd/netif/links/2'));
});
test('active manual TUN requests stop before installation but is not stopped', async () => {
  const r = await collectHostPreflight({ exitIp: '1.2.3.4' }, fixture({ tun: true }));
  assert.equal(r.status, 'review-required'); assert.ok(r.issues.includes('manual-TUN-present-stop-before-install'));
});
test('malformed network evidence and aborted inventory never pass', async () => {
  const r = await collectHostPreflight({ exitIp: '1.2.3.4' }, fixture({ malformed: true }));
  assert.equal(r.status, 'review-required'); assert.ok(r.issues.includes('link-inventory-unavailable'));
  const controller = new AbortController(); controller.abort();
  const a = await collectHostPreflight({ exitIp: '1.2.3.4' }, { ...fixture(), signal: controller.signal });
  assert.ok(a.issues.includes('collection-aborted'));
});
test('manager, installation, prerequisites and early network uncertainty fail review', async () => {
  const r = await collectHostPreflight({ exitIp: '1.2.3.4' }, fixture());
  for (const change of [x => x.units['NetworkManager.service'] = { LoadState: 'loaded', ActiveState: 'active' }, x => x.units['clean-vpn.service'] = null, x => x.installationPaths.extra = 'unknown', x => x.tools.ip = null, x => x.tunDevice = false, x => x.earlyNetworkParameters = ['ip'], x => x.uplinkNetworkd = {}, x => x.sameNetworkNamespace = false]) {
    const value = structuredClone(r); change(value); assert.equal(assessHostPreflight(value).status, 'review-required');
  }
});

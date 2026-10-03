#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { installUsbGateway, removeUsbGateway, gatewayRun as run, readGatewayFile as read } from './lib/host-usb-gateway.mjs';
import { checkHostUpdateUnits, switchHostWrapper } from './lib/host-update.mjs';
import { assertNetworkdGate, usesNetworkdGate } from './lib/host-networkd-gate.mjs';

export function assertInstalledUsbGatewayProfile({ readInstalled = p => read(fs, p),
  ctl = (...a) => run('systemctl', a), gate = assertNetworkdGate,
  guardSource = fs.readFileSync(new URL('./autostart/killswitch.sh', import.meta.url), 'utf8') } = {}) {
  const base = '/etc/systemd/system/';
  const main = readInstalled(base + 'clean-vpn.service'), guard = readInstalled(base + 'clean-vpn-killswitch.service');
  assert.equal(checkHostUpdateUnits('clean-vpn', main, guard), 'cvks2:both:block:tun0:154.62.226.216:22');
  assert.ok(usesNetworkdGate(guard), 'networkd guarded installation required');
  gate({ service: 'clean-vpn', ctl });
  for (const unit of ['clean-vpn.service', 'clean-vpn-killswitch.service']) {
    assert.equal(ctl('show', unit, '--property=FragmentPath', '--value').trim(), base + unit);
    assert.equal(ctl('show', unit, '--property=DropInPaths', '--value').trim(), '');
    assert.equal(ctl('show', unit, '--property=NeedDaemonReload', '--value').trim(), 'no');
  }
  const wrapper = readInstalled('/usr/local/bin/clean-vpn-run.sh');
  switchHostWrapper(wrapper, '/var/lib/clean-vpn-usb-gateway-inspection'); // parsing only, no write
  for (const arg of ['--type=tls', '--split-default', '--ipv6=auto', '--server=154.62.226.216:443'])
    assert.ok(wrapper.trim().split(/\s+/).includes(arg), `required profile option: ${arg}`);
  assert.equal(readInstalled('/usr/local/bin/clean-vpn-killswitch.sh'), guardSource, 'installed guard version differs');
  assert.equal(ctl('is-active', 'clean-vpn-killswitch.service').trim(), 'active');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) try {
  const args = process.argv.slice(2);
  assert.ok(args.every(a => ['--apply', '--prepare', '--remove'].includes(a)) && new Set(args).size === args.length,
    'use [--prepare | --remove] [--apply]');
  assert.ok(!(args.includes('--prepare') && args.includes('--remove')));
  assert.equal(process.getuid(), 0, 'root required');
  assert.equal(process.env.SERVICE_NAME || 'clean-vpn', 'clean-vpn', 'USB gateway supports only SERVICE_NAME=clean-vpn');
  assert.equal(fs.readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
  assert.equal(fs.readlinkSync('/proc/self/ns/net'), fs.readlinkSync('/proc/1/ns/net'));
  const apply = args.includes('--apply');
  if (args.includes('--remove')) console.log(JSON.stringify(removeUsbGateway({ apply })));
  else {
    if (!args.includes('--prepare')) assertInstalledUsbGatewayProfile();
    console.log(JSON.stringify(installUsbGateway({ apply, prepareOnly: args.includes('--prepare') })));
  }
} catch (e) {
  console.error(JSON.stringify({ status: 'refused-or-incomplete', error: e.message,
    note: 'No VPN/guard/USB restart or automatic rollback. Keep USB SSH open; inspect any partial installation.' }));
  process.exitCode = 1;
}

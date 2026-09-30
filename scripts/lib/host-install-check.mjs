/** Read-only refusal gate, NOT an update transaction or installer lock.
 * Refuse existing/partial installations even when stopped. Never recover or
 * remove their guard. Concurrent administrators/installers are not supported.
 */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { runTunnelDnsCommand } from './dns-tunnel-command.mjs';
import { networkdGatePaths } from './host-networkd-gate.mjs';

export function assertFreshHostInstall({ service = 'clean-vpn', io = fs, run = runTunnelDnsCommand } = {}) {
  assert.match(service, /^[A-Za-z0-9_][A-Za-z0-9._-]*$/);
  assert.ok(service.length <= 200);
  const units = [`${service}.service`, `${service}-killswitch.service`];
  const paths = [...units.map(n => `/etc/systemd/system/${n}`),
    `/usr/local/bin/${service}-run.sh`, `/usr/local/bin/${service}-killswitch.sh`, ...networkdGatePaths(service)];
  for (const path of paths) {
    let present = false;
    try { io.lstatSync(path); present = true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    assert.ok(!present, `existing installation: ${path}; in-place update refused; service and guard unchanged`);
  }
  // Include loaded/transient units and units installed outside /etc. A manager
  // error is not evidence of absence. Read all properties in one invocation.
  for (const unit of units) {
    const output = run('systemctl', ['--no-pager', 'show', unit,
      '--property=LoadState,ActiveState,FragmentPath,DropInPaths'], { timeoutMs: 20000 });
    const values = Object.fromEntries(output.split('\n').filter(Boolean).map(line => {
      const i = line.indexOf('='); assert.ok(i > 0, 'invalid systemd response');
      return [line.slice(0, i), line.slice(i + 1)];
    }));
    assert.ok(values.LoadState === 'not-found' && values.ActiveState === 'inactive' &&
      values.FragmentPath === '' && values.DropInPaths === '',
    `existing or uncertain systemd unit: ${unit}; in-place update refused; service and guard unchanged`);
  }
  return { status: 'fresh-install-only', systemSettingsChanged: false };
}

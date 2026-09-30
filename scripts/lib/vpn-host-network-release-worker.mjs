/** VM-only guard ExecStop; refuse release if the network teardown did not succeed. */
import assert from 'node:assert/strict';
import { readFileSync, readlinkSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { assertManagedNetworkStopped } from './vpn-host-network-release.mjs';

assert.match(readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.host-networkd=1(?:\s|$)/);
assert.match(readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
assert.equal(readFileSync('/proc/1/comm', 'utf8').trim(), 'systemd');
assert.equal(process.getuid(), 0);
assert.notEqual(readlinkSync('/proc/self/ns/net'), readlinkSync('/proc/1/ns/net'));
assert.equal(statSync('/proc/self/ns/net').ino, statSync('/run/netns/client').ino);
assert.equal(readlinkSync('/proc/self/ns/pid'), readlinkSync('/proc/1/ns/pid'));
assert.equal(process.argv.length, 2);
const run = (f, a) => execFileSync(f, a, { encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 }).trim();
const property = k => run('/usr/bin/systemctl', ['show', 'systemd-networkd.service', `--property=${k}`, '--value']);
assertManagedNetworkStopped(JSON.parse(readFileSync('/run/host-networkd-link.json', 'utf8')),
  JSON.parse(run('/usr/bin/ip', ['-j', 'link', 'show'])), { state: property('ActiveState'), pid: property('MainPID') });
console.log('VM network release: manager stopped and pinned links down');
run('/usr/local/bin/clean-vpn-killswitch.sh', ['down', '--tun=tun0']);

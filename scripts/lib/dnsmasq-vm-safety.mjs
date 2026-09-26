/** Dedicated NIC-less QEMU authority, never a live-client opt-in flag. */
import assert from 'node:assert/strict';
import { readFile, readlink } from 'node:fs/promises';
import { vmBootOptions } from './dns-vm-protocol.mjs';
import { exec } from './browser-lab-driver.mjs';

export async function assertDnsmasqVm({ peer = false } = {}) {
  const options = vmBootOptions(await readFile('/proc/cmdline', 'utf8'));
  assert.equal(options.phase, 'dnsmasq'); assert.equal(options.point, 'lifecycle');
  assert.match(await readFile('/sys/class/dmi/id/sys_vendor', 'utf8'), /^QEMU\s*$/);
  assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
  assert.equal(process.getuid(), 0);
  const permitted = peer ? ['lo', 'usbpeer'] : ['lo', 'dnsfixture', 'usb0'];
  // The child shares the VM's sysfs mount, which shows its mounting netns.
  // Netlink reports interfaces of the caller's actual network namespace.
  const links = JSON.parse((await exec('ip', ['-j', 'link'])).stdout);
  assert.ok(links.every((link) => permitted.includes(link.ifname)), 'unexpected guest NIC');
  for (const key of ['mnt', 'pid']) assert.equal(await readlink(`/proc/self/ns/${key}`), await readlink(`/proc/1/ns/${key}`));
  const sameNet = await readlink('/proc/self/ns/net') === await readlink('/proc/1/ns/net');
  assert.equal(sameNet, !peer); return options;
}

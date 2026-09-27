/** Fresh installer prerequisite on real PID1, only in the explicit NIC-less VM.
 * Fixture service/firewall changes below are never host installer authority. */
import assert from 'node:assert/strict';
import { mkdir, open, chmod, writeFile, unlink, rmdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { DNS_BOOT_LOCK } from './dns-boot-guard.mjs';
import { createDnsSystemCommands } from './dns-system-command.mjs';
import { inspectFreshDnsDeployment } from './dns-deployment-inactive.mjs';
import { compileDnsClientGuard } from './dns-client-guard.mjs';
import { exec } from './browser-lab-driver.mjs';

const input = { schema: 1, client: 'vps2', id: 'b'.repeat(32) };
async function gate() { const o = await assertCoupledDnsVm(); assert.equal(o.phase, 'coupled'); assert.equal(o.point, 'deployment'); }
async function inspect() {
  await gate();
  const commands = await createDnsSystemCommands({ assertAuthority: gate, required: ['ip', 'busctl', 'iptables', 'ip6tables'] });
  return inspectFreshDnsDeployment({ commands, input, firewallBackend: 'legacy' });
}
export async function checkFreshDnsDeploymentVm() {
  await gate(); const checks = [];
  const ctl = (...args) => exec('/usr/bin/systemctl', args, { timeout: 30000 });
  const probe = async () => {
    const began = performance.now();
    const result = await exec('/usr/bin/flock', ['-n', '-E', '75', '-F', DNS_BOOT_LOCK,
      '/usr/bin/node', '/project/scripts/lib/dns-deployment-vm-check.mjs', '--inspect'], { timeout: 90000 });
    console.log(`DNS_DEPLOYMENT_PROBE passed elapsedMs=${Math.round(performance.now() - began)}`);
    const value = JSON.parse(result.stdout); assert.equal(value.freshInactive, true); assert.equal(value.activationAuthorized, false);
    return value;
  };
  await mkdir('/var/lib', { recursive: true, mode: 0o755 });
  await mkdir('/run/clean-vpn-dns-guard', { mode: 0o700 });
  const lock = await open(DNS_BOOT_LOCK, 'wx', 0o600); await lock.close();
  await ctl('start', 'dbus.service');
  const firewall = async () => Promise.all(['iptables', 'ip6tables'].map(async (tool) => (await exec(tool, ['-S'])).stdout));
  const before = await firewall();
  const refused = (message) => assert.rejects(probe(), (e) => typeof e.stderr === 'string' && e.stderr.includes(message));
  await probe(); checks.push('fresh-inactive-systemd-and-firewall');
  const name = 'clean-vpn-dns-client.service', path = `/etc/systemd/system/${name}`;
  await writeFile(path, '[Unit]\nDescription=Fresh inspection VM fixture\nDefaultDependencies=no\n[Service]\nType=simple\nExecStart=/bin/busybox sleep 300\n', { flag: 'wx', mode: 0o644 });
  await chmod(path, 0o644); await ctl('daemon-reload'); await ctl('show', name, '--property=LoadState');
  await probe(); checks.push('loaded-inactive-service-accepted');
  await ctl('start', name); await refused('DNS service is not inactive'); checks.push('running-service-refused'); await ctl('stop', name);
  await exec('ip', ['link', 'add', 'cvdnsdeadbeef', 'type', 'dummy']);
  await refused('DNS link remains'); checks.push('owned-link-refused'); await exec('ip', ['link', 'delete', 'cvdnsdeadbeef']);
  // Install/remove only this fixture's exact rules; preserve the early VM
  // REJECT rules. No generic flush or production restore-proof bypass.
  const plan = compileDnsClientGuard(input);
  for (const family of plan.families) {
    const tool = family.family === 4 ? 'iptables' : 'ip6tables';
    for (const chain of family.chains) {
      await exec(tool, ['-N', chain.name]);
      for (const rule of chain.rules) await exec(tool, ['-A', chain.name, ...rule]);
      await exec(tool, ['-I', chain.hook, '1', ...chain.jump]);
    }
  }
  await refused('DNS guard remains'); checks.push('owned-guard-refused');
  for (const family of plan.families) {
    const tool = family.family === 4 ? 'iptables' : 'ip6tables';
    for (const chain of family.chains) {
      await exec(tool, ['-D', chain.hook, ...chain.jump]);
      for (const rule of chain.rules) await exec(tool, ['-D', chain.name, ...rule]);
      await exec(tool, ['-X', chain.name]);
    }
  }
  await mkdir('/var/lib/clean-vpn', { mode: 0o700 }); await mkdir('/var/lib/clean-vpn/dns-v1', { mode: 0o700 });
  await refused('DNS runtime history requires explicit recovery/uninstall'); checks.push('runtime-history-refused');
  await rmdir('/var/lib/clean-vpn/dns-v1'); await rmdir('/var/lib/clean-vpn');
  await unlink(path); await ctl('daemon-reload'); await probe();
  assert.deepEqual(await firewall(), before); checks.push('fresh-state-rechecked-after-cleanup');
  return checks;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv[2], '--inspect');
  inspect().then((v) => console.log(JSON.stringify(v))).catch((e) => { console.error(e.stack); process.exitCode = 1; });
}

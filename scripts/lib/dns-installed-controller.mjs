/** Installed controller factory. Fixed state paths, real guard, shared journal
 * transaction. No caller-supplied guard, commands, backend or restore proof. */
import assert from 'node:assert/strict';
import { lstat, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { assertDnsInstalledAuthority, dnsInstalledAuthorityInfo } from './dns-installed-authority.mjs';
import { validateVps2DnsConfig } from './dns-vps2-baseline.mjs';
import { loadDnsBootGuard } from './dns-boot-guard.mjs';
import { createBootGuardLifecycle } from './dns-boot-guard-lifecycle.mjs';
import { createDnsClientController } from './dns-client-controller.mjs';
import { createInstalledCoupledBackend } from './dns-coupled-backend.mjs';
import { syncDirectory } from './dns-lifecycle-journal.mjs';

export const DNS_INSTALLED_STATE = '/var/lib/clean-vpn/dns-v1';
export const DNS_INSTALLED_TRANSACTION = `${DNS_INSTALLED_STATE}/transaction`;
export const DNS_INSTALLED_GUARD = `${DNS_INSTALLED_STATE}/guard`;

async function directory(path, privateMode) {
  const s = await lstat(path, { bigint: true });
  assert.ok(s.isDirectory() && s.uid === 0n && !(s.mode & 0o022n), 'untrusted installed state directory');
  if (privateMode) assert.equal(s.mode & 0o7777n, 0o700n);
  return `${s.dev}:${s.ino}:${s.mode}`;
}
export async function createInstalledVps2Controller({ token, command }) {
  await assertDnsInstalledAuthority(token);
  assert.ok(['start', 'disable'].includes(command));
  const info = dnsInstalledAuthorityInfo(token); assert.equal(info.client, 'vps2'); validateVps2DnsConfig(info.config);
  const pinned = new Map();
  const checkStorage = async () => {
    await assertDnsInstalledAuthority(token);
    for (const [path, expected] of pinned) assert.equal(await directory(path, path.startsWith('/var/lib/clean-vpn')), expected, 'installed state directory replaced');
  };
  const controller = await createDnsClientController({ client: 'vps2', command, directory: DNS_INSTALLED_TRANSACTION,
    createContext: async (hooks) => {
      await checkStorage();
      return { scope: info.scope, backend: await createInstalledCoupledBackend({ token, ...hooks }) };
    },
    createGuard: async ({ restoring, authorizeRelease, dnsStateExists, client }) => {
      await assertDnsInstalledAuthority(token); assert.equal(client, 'vps2');
      const boot = await loadDnsBootGuard();
      assert.equal(boot.policy.input.client, client); assert.equal(boot.policy.input.id, info.guardId);
      try {
        for (const path of ['/var', '/var/lib']) pinned.set(path, await directory(path, false));
        for (const path of ['/var/lib/clean-vpn', DNS_INSTALLED_STATE, DNS_INSTALLED_GUARD]) {
          try { await lstat(path); }
          catch (e) {
            if (e.code !== 'ENOENT') throw e;
            await boot.guard.ensure(); await checkStorage();
            await mkdir(path, { mode: 0o700 }); await syncDirectory(dirname(path));
          }
          pinned.set(path, await directory(path, true));
        }
      } catch (e) { await boot.guard.ensure(); throw e; }
      const backend = boot.createJournalBackend({ authorizeRelease,
        context: async () => {
          await checkStorage(); const s = await lstat(DNS_INSTALLED_GUARD);
          return { bootId: info.bootId, netns: info.scope.net, directoryIdentity: `${s.dev}:${s.ino}`,
            firewall: { ipv4: boot.policy.firewallBackend, ipv6: boot.policy.firewallBackend }, usb: null };
        } });
      let allowBind;
      try { allowBind = !await dnsStateExists(); }
      catch (e) { await boot.guard.ensure(); throw e; }
      return createBootGuardLifecycle({ directory: DNS_INSTALLED_GUARD, boot, backend, restoring, allowBind });
    } });
  // Shared run prepares protection before accessing transaction storage. Do
  // not move a fallible storage check ahead of that fail-closed preparation.
  return Object.freeze({ run: async () => {
    const result = await controller.run(); await assertDnsInstalledAuthority(token); return result;
  } });
}

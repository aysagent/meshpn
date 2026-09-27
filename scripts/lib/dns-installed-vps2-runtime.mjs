/** Fixed installed VPS2 OS context; no caller-supplied commands/bus/authority.
 * The journal controller still owns lifecycle ordering and restore proof. */
import assert from 'node:assert/strict';
import { readlink } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { assertDnsInstalledAuthority, assertDnsInstalledSession, dnsInstalledAuthorityInfo } from './dns-installed-authority.mjs';
import { createDnsSystemCommands, inspectDnsSystemExecutable } from './dns-system-command.mjs';
import { createDnsSystemBus } from './dns-system-bus.mjs';
import { loadDnsBootGuard } from './dns-boot-guard.mjs';
import { validateVps2DnsConfig } from './dns-vps2-baseline.mjs';
import { readTrustedDnsText, validateVps2DnsUnit, inspectInstalledVps2Dns } from './dns-installed-vps2.mjs';
import { DNS_NETWORKD_POLICY, DNS_NETWORKD_CONTENTS, assertDnsNetworkdUnmanaged } from './dns-networkd-policy.mjs';

export function isReadOnlyInstalledIp(args) {
  if (!Array.isArray(args)) return false;
  if (JSON.stringify(args) === JSON.stringify(['-d', '-j', 'link', 'show'])) return true;
  const prefix = args.slice(0, -1).join(' ');
  return ['-d -j link show dev', '-j addr show dev'].includes(prefix)
    && args.length === (prefix.startsWith('-d') ? 6 : 5) && /^cvdns[a-f0-9]{8}$/.test(args.at(-1));
}
export async function createInstalledVps2Runtime(token) {
  await assertDnsInstalledAuthority(token);
  const info = dnsInstalledAuthorityInfo(token); assert.equal(info.client, 'vps2');
  const config = validateVps2DnsConfig(info.config);
  const commands = await createDnsSystemCommands({ assertAuthority: () => assertDnsInstalledSession(token) });
  const readBus = createDnsSystemBus(commands.run), boot = await loadDnsBootGuard();
  // No raw command runner escapes. Every write still has FULL code-bundle
  // authority checks immediately before and after its pinned OS helper.
  const mutate = async (fn) => { await assertDnsInstalledAuthority(token); const result = await fn(); await assertDnsInstalledAuthority(token); return result; };
  const bus = Object.freeze({ ...readBus, set: (owner, args) => mutate(() => readBus.set(owner, args)) });
  const runIp = (args) => isReadOnlyInstalledIp(args) ? commands.run('ip', args) : mutate(() => commands.run('ip', args));
  assert.equal(boot.policy.input.client, 'vps2'); assert.equal(boot.policy.input.id, info.guardId);
  const services = [['systemd-resolved', 'org.freedesktop.resolve1'], ['systemd-networkd', 'org.freedesktop.network1']];
  const fields = ['Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'NeedDaemonReload'];
  const managers = async () => {
    const result = {};
    for (const [name, service] of services) {
      const owner = await bus.owner(service), pid = await bus.ownerPid(owner), uid = await bus.ownerUid(owner);
      const unit = validateVps2DnsUnit((await commands.run('systemctl', ['show', `${name}.service`, ...fields.map((f) => `--property=${f}`)])).stdout, name, pid);
      const executable = await inspectDnsSystemExecutable(await readlink(`/proc/${pid}/exe`));
      assert.ok([`/usr/lib/systemd/${name}`, `/lib/systemd/${name}`].includes(executable.actual));
      assert.equal(await readlink(`/proc/${pid}/ns/net`), info.scope.net);
      result[service] = { owner, pid, uid, unit, executable };
    }
    return result;
  };
  const pinned = await managers(), busId = await bus.id();
  const policy = await readTrustedDnsText(DNS_NETWORKD_POLICY, 0o644);
  assert.equal(policy.text, DNS_NETWORKD_CONTENTS);
  const readContext = async () => {
    await assertDnsInstalledSession(token);
    const currentBus = await bus.id(), owner = await bus.owner();
    assert.equal(currentBus, busId); assert.equal(owner, pinned['org.freedesktop.resolve1'].owner);
    return { scope: structuredClone(info.scope), bootId: info.bootId, busId: currentBus, owner };
  };
  const assertContext = async () => {
    await assertDnsInstalledAuthority(token); assert.equal(await bus.id(), busId);
    for (const [, service] of services) assert.equal(await bus.owner(service), pinned[service].owner, 'DNS manager owner changed');
    assert.deepEqual(await readTrustedDnsText(DNS_NETWORKD_POLICY, 0o644), policy, 'networkd policy changed');
    return { scope: structuredClone(info.scope), bootId: info.bootId, busId, owner: pinned['org.freedesktop.resolve1'].owner };
  };
  const requireGuard = async () => {
    await assertContext(); assert.deepEqual(await boot.guard.inspect(), ['present', 'present'], 'DNS guard required before mutation');
  };
  const assertMutation = async (current) => {
    await requireGuard(); assert.deepEqual(await managers(), pinned, 'DNS manager invocation changed');
    if (current === null) {
      // Creation is a fresh takeover, even when resuming a prepared journal:
      // no existing cvdns link, reserved address/route or baseline policy drift.
      await inspectInstalledVps2Dns(token);
    } else {
      assert.match(current.name, /^cvdns[a-f0-9]{8}$/);
      assert.ok(Number.isInteger(current.ifindex) && current.ifindex > 1 && current.ifindex <= 2147483647);
      const deadline = performance.now() + 2000;
      for (;;) {
        let state;
        try { state = (await readTrustedDnsText(`/run/systemd/netif/links/${current.ifindex}`, undefined,
          { root: '/run/systemd/netif', uid: pinned['org.freedesktop.network1'].uid })).text; }
        catch (e) { if (e.code !== 'ENOENT' || performance.now() >= deadline) throw e; await delay(20); continue; }
        assertDnsNetworkdUnmanaged({ name: current.name, ifindex: current.ifindex, state }); break;
      }
    }
    await requireGuard();
  };
  return Object.freeze({ runIp, bus, config: structuredClone(config), scope: structuredClone(info.scope),
    assertRead: () => assertDnsInstalledSession(token), readContext, assertMutation, requireGuard });
}

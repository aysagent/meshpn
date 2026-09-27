/** Empty-link backends with separate namespace, VM and installed authority gates. */
import assert from 'node:assert/strict';
import { readFile, readlink } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { validateOwnedLinkContext } from './dns-owned-link-journal.mjs';
import { assertCoupledDnsVm } from './dns-systemd-vm-safety.mjs';
import { assertDnsSystemCommands } from './dns-system-command.mjs';
import { createInstalledVps2Runtime } from './dns-installed-vps2-runtime.mjs';

export const createOwnedLinkBackend = (options) => buildBackend(options, assertDnsMountNamespace);
export const createVmOwnedLinkBackend = (options) => buildBackend(options, assertCoupledDnsVm);
export async function createVmLockedOwnedLinkBackend(options) {
  await assertCoupledDnsVm(); assertDnsSystemCommands(options.commands);
  return buildBackend(options, assertCoupledDnsVm, (_file, args) => options.commands.run('ip', args));
}
export const createInstalledOwnedLinkBackend = async (options) => (await createInstalledOwnedLinkContext(options)).link;
export async function createInstalledOwnedLinkContext({ token, ensureGuard, releaseGuard }) {
  const runtime = await createInstalledVps2Runtime(token);
  assert.equal(typeof ensureGuard, 'function'); assert.equal(typeof releaseGuard, 'function');
  // Guard callbacks coordinate journals; they cannot replace the real guard
  // check or select tools, bus, paths, namespaces or manager authority.
  const run = (_file, args) => runtime.runIp(args);
  const link = await buildBackend({ bus: runtime.bus, ensureGuard: async () => { await ensureGuard(); await runtime.requireGuard(); }, releaseGuard },
    runtime.assertRead, run, runtime.assertMutation, runtime.readContext);
  return { link, bus: runtime.bus, run, config: runtime.config };
}
// Authority is selected by the exported factory, never supplied by a caller.
async function buildBackend({ bus, ensureGuard, releaseGuard }, authority, run = exec, assertMutation = async () => {}, readContext) {
  await authority();
  const scope = {};
  for (const key of ['net', 'mnt', 'pid']) scope[key] = await readlink(`/proc/self/ns/${key}`);
  const context = async () => {
    // The installed reader checks process authority and observes fresh bus
    // identities. Full mutation authority is separate, never granted by reads.
    if (readContext) return validateOwnedLinkContext(await readContext());
    await authority();
    return validateOwnedLinkContext({ scope: structuredClone(scope), bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(),
      busId: await bus.id(), owner: await bus.owner() });
  };
  const nameCheck = (name) => assert.match(name, /^cvdns[a-f0-9]{8}$/);
  const view = async (name) => {
    await authority(); nameCheck(name);
    const links = JSON.parse((await run('ip', ['-d', '-j', 'link', 'show'])).stdout);
    const link = links.find((v) => v.ifname === name); if (!link) return null;
    const addresses = JSON.parse((await run('ip', ['-j', 'addr', 'show', 'dev', name])).stdout);
    let dns = {}; const owner = await bus.owner();
    // A newly created link may not yet have reached resolved's netlink monitor.
    const end = performance.now() + 2000;
    for (;;) {
      try {
        if (bus.linkSnapshot) dns = await bus.linkSnapshot(owner, link.ifindex);
        else for (const property of ['DNSEx', 'Domains', 'DefaultRoute']) dns[property] = await bus.property(owner, link.ifindex, property);
        break;
      } catch (e) { if (performance.now() >= end) throw e; await delay(20); }
    }
    return { ifindex: link.ifindex, name: link.ifname, kind: link.linkinfo?.info_kind ?? '', mac: link.address,
      alias: link.ifalias ?? '', mtu: link.mtu, up: link.flags.includes('UP'), master: link.master ?? null,
      addresses: addresses.flatMap((v) => v.addr_info.map((a) => `${a.family}:${a.local}/${a.prefixlen}`)).sort(), dns };
  };
  const check = async (expected) => { await authority(); assert.deepEqual(await context(), expected, 'link backend context changed'); };
  return { context, view, ensureGuard, assertMutation,
    async create(expected, spec) {
      await check(expected); nameCheck(spec.name); assert.equal(spec.kind, 'dummy');
      assert.equal(spec.alias, ''); assert.match(spec.mac, /^02(?::[a-f0-9]{2}){5}$/);
      assert.deepEqual(spec, { name: spec.name, kind: 'dummy', alias: spec.alias, mac: spec.mac, mtu: 1500, up: false, master: null, addresses: [] });
      assert.equal(await view(spec.name), null, 'name occupied before creation'); await check(expected);
      await assertMutation(null);
      // The 5.4 fixture retains name + MAC on creation, but needs a separate alias setter.
      await run('ip', ['link', 'add', 'name', spec.name, 'address', spec.mac, 'mtu', '1500', 'type', 'dummy']);
    },
    async stamp(expected, current, alias) {
      await check(expected); assert.equal(current.alias, ''); assert.match(alias, /^clean-vpn-dns:[a-f0-9]{32}$/);
      assert.deepEqual(await view(current.name), current, 'link changed before stamp'); await check(expected);
      await assertMutation(current);
      await run('ip', ['link', 'set', 'dev', current.name, 'alias', alias]);
    },
    async remove(expected, current) {
      await check(expected); assert.deepEqual(await view(current.name), current, 'link changed before deletion'); await check(expected);
      await assertMutation(current);
      await run('ip', ['link', 'delete', 'dev', current.name]);
    },
    async releaseGuard(expected, name) {
      await check(expected); assert.equal(await view(name), null, 'name reused before guard release'); await check(expected); await releaseGuard();
    },
  };
}

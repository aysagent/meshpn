/** Empty link backend: usable only by private namespace PID1, private bus injected. */
import assert from 'node:assert/strict';
import { readFile, readlink } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { exec } from './browser-lab-driver.mjs';
import { assertDnsMountNamespace } from './dns-lifecycle-namespace.mjs';
import { validateOwnedLinkContext } from './dns-owned-link-journal.mjs';

export async function createOwnedLinkBackend({ bus, ensureGuard, releaseGuard }) {
  await assertDnsMountNamespace();
  const scope = {};
  for (const key of ['net', 'mnt', 'pid']) scope[key] = await readlink(`/proc/self/ns/${key}`);
  const context = async () => validateOwnedLinkContext({ scope: structuredClone(scope), bootId: (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim(),
    busId: await bus.id(), owner: await bus.owner() });
  const nameCheck = (name) => assert.match(name, /^cvdns[a-f0-9]{8}$/);
  const view = async (name) => {
    await assertDnsMountNamespace(); nameCheck(name);
    const links = JSON.parse((await exec('ip', ['-d', '-j', 'link', 'show'])).stdout);
    const link = links.find((v) => v.ifname === name); if (!link) return null;
    const addresses = JSON.parse((await exec('ip', ['-j', 'addr', 'show', 'dev', name])).stdout);
    const dns = {}, owner = await bus.owner();
    // A newly created link may not yet have reached resolved's netlink monitor.
    const end = performance.now() + 2000;
    for (;;) {
      try {
        for (const property of ['DNSEx', 'Domains', 'DefaultRoute']) dns[property] = await bus.property(owner, link.ifindex, property);
        break;
      } catch (e) { if (performance.now() >= end) throw e; await delay(20); }
    }
    return { ifindex: link.ifindex, name: link.ifname, kind: link.linkinfo?.info_kind ?? '', mac: link.address,
      alias: link.ifalias ?? '', mtu: link.mtu, up: link.flags.includes('UP'), master: link.master ?? null,
      addresses: addresses.flatMap((v) => v.addr_info.map((a) => `${a.family}:${a.local}/${a.prefixlen}`)).sort(), dns };
  };
  const check = async (expected) => { await assertDnsMountNamespace(); assert.deepEqual(await context(), expected, 'link backend context changed'); };
  return { context, view, ensureGuard,
    async create(expected, spec) {
      await check(expected); nameCheck(spec.name); assert.equal(spec.kind, 'dummy');
      assert.equal(spec.alias, ''); assert.match(spec.mac, /^02(?::[a-f0-9]{2}){5}$/);
      assert.deepEqual(spec, { name: spec.name, kind: 'dummy', alias: spec.alias, mac: spec.mac, mtu: 1500, up: false, master: null, addresses: [] });
      assert.equal(await view(spec.name), null, 'name occupied before creation'); await check(expected);
      // The 5.4 fixture retains name + MAC on creation, but needs a separate alias setter.
      await exec('ip', ['link', 'add', 'name', spec.name, 'address', spec.mac, 'mtu', '1500', 'type', 'dummy']);
    },
    async stamp(expected, current, alias) {
      await check(expected); assert.equal(current.alias, ''); assert.match(alias, /^clean-vpn-dns:[a-f0-9]{32}$/);
      assert.deepEqual(await view(current.name), current, 'link changed before stamp'); await check(expected);
      await exec('ip', ['link', 'set', 'dev', current.name, 'alias', alias]);
    },
    async remove(expected, current) {
      await check(expected); assert.deepEqual(await view(current.name), current, 'link changed before deletion'); await check(expected);
      await exec('ip', ['link', 'delete', 'dev', current.name]);
    },
    async releaseGuard(expected, name) {
      await check(expected); assert.equal(await view(name), null, 'name reused before guard release'); await check(expected); await releaseGuard();
    },
  };
}

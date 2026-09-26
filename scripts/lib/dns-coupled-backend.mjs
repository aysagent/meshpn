/** Separate namespace and VM-gated adapters for coupled address/link/resolved operations. */
import assert from 'node:assert/strict';
import { createOwnedLinkBackend, createVmOwnedLinkBackend } from './dns-owned-link-backend.mjs';
import { resolvedMethod } from './dns-resolved-backend.mjs';
import { exec } from './browser-lab-driver.mjs';

export const createCoupledBackend = (options) => buildBackend(options, createOwnedLinkBackend);
export const createVmCoupledBackend = (options) => buildBackend(options, createVmOwnedLinkBackend);
async function buildBackend({ bus, ensureGuard, releaseGuard, port, probe }, factory) {
  const link = await factory({ bus, ensureGuard, releaseGuard });
  const view = async (name) => {
    const v = await link.view(name); if (!v) return null;
    const [info] = JSON.parse((await exec('ip', ['-d', '-j', 'link', 'show', 'dev', name])).stdout);
    assert.equal(info.ifindex, v.ifindex); return { ...v, addrgen: info.inet6_addr_gen_mode };
  };
  return { ...link, linkView: link.view, view, adapterPort: async () => port, probe,
    async set(context, current, step, target) {
      assert.deepEqual(await link.context(), context); assert.deepEqual(await view(current.name), current);
      assert.equal(target.name, current.name); assert.equal(target.ifindex, current.ifindex);
      assert.deepEqual(await link.context(), context);
      if (step === 'addrgen') {
        assert.ok(['eui64', 'none', 'stable_secret', 'random'].includes(target.addrgen));
        await exec('ip', ['link', 'set', 'dev', current.name, 'addrgenmode', target.addrgen]);
      } else if (step === 'address') {
        assert.ok(target.addresses.length === 0 || (target.addresses.length === 1 && target.addresses[0] === 'inet:192.0.2.1/32'));
        await exec('ip', ['addr', target.addresses.length ? 'add' : 'del', '192.0.2.1/32', 'dev', current.name]);
      } else if (step === 'up') {
        assert.equal(typeof target.up, 'boolean'); await exec('ip', ['link', 'set', 'dev', current.name, target.up ? 'up' : 'down']);
      } else {
        const property = step.startsWith('DefaultRoute') ? 'DefaultRoute' : step;
        assert.ok(['DefaultRoute', 'DNSEx', 'Domains'].includes(property));
        await bus.set(context.owner, resolvedMethod(property, target.dns[property], current.ifindex));
      }
    },
  };
}

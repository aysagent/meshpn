import assert from 'node:assert/strict';
import test from 'node:test';
import { createResolvedBackend, validateResolvedSettings, resolvedMethod } from './lib/dns-resolved-backend.mjs';

const baseline = () => ({ DNSEx: [[2, [192, 0, 2, 53], 53, '']], Domains: [['corp.test', false]], DefaultRoute: false });
async function fixture(initial = baseline()) {
  const state = { settings: structuredClone(initial), owner: ':1.2', link: { ifindex: 2, ifname: 'fixture' }, guard: false, ready: true, writes: [] };
  const properties = { SetLinkDNSEx: 'DNSEx', SetLinkDomains: 'Domains', SetLinkDefaultRoute: 'DefaultRoute' };
  const bus = {
    async owner() { return state.owner; },
    async property(owner, index, property) { assert.equal(owner, ':1.2'); assert.equal(index, 2); return structuredClone(state.settings[property]); },
    async set(owner, args) {
      assert.equal(owner, ':1.2'); assert.ok(state.guard); state.writes.push(args[0]);
      const key = properties[args[0]];
      if (key === 'DNSEx') {
        const bytes = args.slice(6, 10).map(Number);
        state.settings[key] = [[Number(args[4]), bytes, Number(args[10]), args[11]]];
      } else if (key === 'Domains') {
        state.settings[key] = [];
        for (let i = 4; i < args.length; i += 2) state.settings[key].push([args[i], args[i + 1] === 'true']);
      } else state.settings[key] = args[3] === 'true';
    },
  };
  const options = { bus, ifindex: 2, identity: async () => ({ ...state.link }),
    ensureGuard: async () => { state.guard = true; }, removeGuard: async () => { state.guard = false; },
    probe: async () => { assert.ok(state.ready, 'readiness failed'); } };
  return { state, bus, options, backend: await createResolvedBackend(options) };
}
test('resolved apply and disable restore exact baseline, no RevertLink', async () => {
  const { state, backend } = await fixture(); await backend.apply(1053);
  assert.deepEqual(state.settings, { DNSEx: [[2, [127, 0, 0, 1], 1053, '']], Domains: [['.', true]], DefaultRoute: true });
  assert.ok(state.guard); assert.deepEqual(await backend.verify(), { active: true, released: false });
  await backend.disable(); assert.deepEqual(state.settings, baseline()); assert.equal(state.guard, false);
  assert.ok(!state.writes.includes('RevertLink')); await assert.rejects(backend.apply(1053), /released/);
});
test('snapshot returned to caller is detached', async () => {
  const { backend } = await fixture(); const snapshot = backend.snapshot(); snapshot.DNSEx[0][1][0] = 255;
  assert.deepEqual(backend.snapshot(), baseline());
});
test('readiness failure never changes DNS or removes guard', async () => {
  const { state, backend } = await fixture(); state.ready = false;
  await assert.rejects(backend.apply(1053), /readiness/); assert.deepEqual(state.settings, baseline());
  assert.deepEqual(state.writes, []); assert.ok(state.guard);
});
for (const changed of ['DNSEx', 'Domains', 'DefaultRoute']) test(`foreign ${changed} prevents restore`, async () => {
  const { state, backend } = await fixture(); await backend.apply(1053);
  state.settings[changed] = changed === 'DNSEx' ? baseline().DNSEx : changed === 'Domains' ? [['foreign.test', true]] : false;
  const foreign = structuredClone(state.settings);
  await assert.rejects(backend.disable(), /ownership conflict/); assert.deepEqual(state.settings, foreign); assert.ok(state.guard);
});
test('resolved restart cannot be mistaken for old owner', async () => {
  const { state, backend } = await fixture(); await backend.apply(1053); state.owner = ':1.99';
  await assert.rejects(backend.disable(), /owner changed/); assert.ok(state.guard);
});
test('link replacement prevents restore even when settings match', async () => {
  const { state, backend } = await fixture(); await backend.apply(1053); state.link.ifindex = 3;
  await assert.rejects(backend.disable(), /owned link changed/); assert.ok(state.guard);
});
test('interrupted setter retains guard and does not attempt automatic rollback', async () => {
  const f = await fixture(); const set = f.bus.set;
  f.bus.set = async (owner, args) => { if (args[0] === 'SetLinkDomains') throw new Error('bus failure'); return set(owner, args); };
  await assert.rejects(f.backend.apply(1053), /bus failure/); assert.ok(f.state.guard);
  f.bus.set = set; await f.backend.disable(); assert.deepEqual(f.state.settings, baseline()); assert.equal(f.state.guard, false);
});
test('lost reply after successful setter is conflict, not permission to overwrite', async () => {
  const f = await fixture(), set = f.bus.set;
  f.bus.set = async (...args) => { await set(...args); throw new Error('reply lost'); };
  await assert.rejects(f.backend.apply(1053), /reply lost/); f.bus.set = set;
  await assert.rejects(f.backend.disable(), /ownership conflict/); assert.ok(f.state.guard);
});
test('concurrent operations on one controller are rejected', async () => {
  const f = await fixture(); let release, entered;
  const ready = new Promise((resolve) => { entered = resolve; });
  f.options.probe = () => { entered(); return new Promise((resolve) => { release = resolve; }); };
  const backend = await createResolvedBackend(f.options), pending = backend.apply(1053); await ready;
  try { await assert.rejects(backend.disable(), /already in progress/); await assert.rejects(backend.verify(), /already in progress/); }
  finally { release(); await pending; }
  await backend.disable(); assert.equal(f.state.guard, false);
});
test('external changes during readiness are checked before first write', async () => {
  const f = await fixture(); f.options.probe = async () => { f.state.settings.Domains = [['changed.test', true]]; };
  const backend = await createResolvedBackend(f.options);
  await assert.rejects(backend.apply(1053), /ownership conflict/); assert.deepEqual(f.state.writes, []); assert.ok(f.state.guard);
});
test('empty baseline is rejected, not restored as a successful setup', async () => {
  await assert.rejects(fixture({ ...baseline(), DNSEx: [] }), /baseline DNS/);
});
test('managed adapter port and link index are strictly bounded', async () => {
  const f = await fixture();
  for (const port of [0, 53, 1023, 65536, '1053', NaN]) await assert.rejects(f.backend.apply(port));
  assert.deepEqual(f.state.writes, []);
  for (const ifindex of [0, 1, -1, '2', Infinity]) await assert.rejects(createResolvedBackend({ ...f.options, ifindex }));
});
test('settings schema rejects invalid byte arrays, types, extras and oversized domains', () => {
  for (const edit of [(s) => { s.extra = true; }, (s) => { s.DNSEx[0][1] = [1]; },
    (s) => { s.DNSEx[0][1][0] = 256; }, (s) => { s.DNSEx[0][0] = 6; },
    (s) => { s.DNSEx[0][2] = -1; }, (s) => { s.Domains = [['x'.repeat(254), true]]; },
    (s) => { s.Domains = [['.', 1]]; }, (s) => { s.DefaultRoute = 'false'; }]) {
    const value = baseline(); edit(value); assert.throws(() => validateResolvedSettings(value));
  }
});
test('D-Bus signatures preserve port, routeOnly and empty arrays without shell expansion', () => {
  assert.deepEqual(resolvedMethod('DNSEx', [[2, [127, 0, 0, 1], 1053, '']], 2),
    ['SetLinkDNSEx', 'ia(iayqs)', '2', '1', '2', '4', '127', '0', '0', '1', '1053', '']);
  assert.deepEqual(resolvedMethod('Domains', [], 2), ['SetLinkDomains', 'ia(sb)', '2', '0']);
  assert.throws(() => resolvedMethod('RevertLink', [], 2));
});

/** Experimental owned-link backend; never constructs a host/system bus connection. */
import assert from 'node:assert/strict';

const properties = ['DNSEx', 'Domains', 'DefaultRoute'];
export function validateResolvedSettings(settings) {
  assert.deepEqual(Object.keys(settings).sort(), [...properties].sort());
  assert.ok(Array.isArray(settings.DNSEx) && settings.DNSEx.length <= 8);
  for (const item of settings.DNSEx) {
    assert.ok(Array.isArray(item) && item.length === 4);
    const [family, address, port, name] = item;
    assert.ok(family === 2 || family === 10);
    assert.ok(Array.isArray(address) && address.length === (family === 2 ? 4 : 16));
    assert.ok(address.every((n) => Number.isInteger(n) && n >= 0 && n <= 255));
    assert.ok(Number.isInteger(port) && port >= 0 && port <= 65535);
    assert.ok(typeof name === 'string' && name.length <= 253 && /^[a-zA-Z0-9.-]*$/.test(name));
  }
  assert.ok(Array.isArray(settings.Domains) && settings.Domains.length <= 32);
  for (const item of settings.Domains) {
    assert.ok(Array.isArray(item) && item.length === 2);
    assert.ok(typeof item[0] === 'string' && item[0].length >= 1 && item[0].length <= 253 && /^[a-zA-Z0-9_.-]+$/.test(item[0]));
    assert.equal(typeof item[1], 'boolean');
  }
  assert.equal(typeof settings.DefaultRoute, 'boolean'); return settings;
}
export function resolvedMethod(property, value, ifindex) {
  assert.ok(Number.isSafeInteger(ifindex) && ifindex > 1);
  if (property === 'DNSEx') return ['SetLinkDNSEx', 'ia(iayqs)', String(ifindex), String(value.length),
    ...value.flatMap(([family, bytes, port, name]) => [String(family), String(bytes.length), ...bytes.map(String), String(port), name])];
  if (property === 'Domains') return ['SetLinkDomains', 'ia(sb)', String(ifindex), String(value.length),
    ...value.flatMap(([name, routeOnly]) => [name, String(routeOnly)])];
  assert.equal(property, 'DefaultRoute'); return ['SetLinkDefaultRoute', 'ib', String(ifindex), String(value)];
}

// bus is injected by a namespace-verified factory; guard/probe are independently owned.
// This controller is deliberately in-memory: NOT wired to the file/inode journal.
export async function createResolvedBackend({ bus, ifindex, identity, ensureGuard, removeGuard, probe }) {
  assert.ok(Number.isSafeInteger(ifindex) && ifindex > 1);
  const owner = await bus.owner(), initialIdentity = await identity();
  assert.match(owner, /^:\d+\.\d+$/);
  const assertIdentity = async () => {
    assert.equal(await bus.owner(), owner, 'resolved owner changed; explicit recovery required');
    assert.deepEqual(await identity(), initialIdentity, 'owned link changed');
  };
  const read = async () => {
    await assertIdentity(); const snapshot = {};
    for (const property of properties) snapshot[property] = await bus.property(owner, ifindex, property);
    await assertIdentity(); return validateResolvedSettings(snapshot);
  };
  const original = structuredClone(await read());
  assert.ok(original.DNSEx.length > 0, 'baseline DNS must be configured before takeover');
  let expected = structuredClone(original), active = false, released = false;
  let busy = false;
  const exclusive = (operation) => async (...args) => {
    assert.equal(busy, false, 'resolved operation already in progress'); busy = true;
    try { return await operation(...args); } finally { busy = false; }
  };
  const check = async () => assert.deepEqual(await read(), expected, 'resolved settings ownership conflict');
  const write = async (settings) => {
    validateResolvedSettings(settings);
    for (const property of properties) {
      await check();
      // Target the captured unique bus owner, never the replaceable well-known name.
      await bus.set(owner, resolvedMethod(property, settings[property], ifindex));
      expected[property] = structuredClone(settings[property]); await check();
    }
  };
  return {
    snapshot: () => structuredClone(original),
    apply: exclusive(async (port) => {
      assert.equal(released, false, 'released controller cannot be reused');
      assert.ok(Number.isInteger(port) && port >= 1024 && port <= 65535);
      await ensureGuard(); await check(); await probe(); await check();
      await write({ DNSEx: [[2, [127, 0, 0, 1], port, '']], Domains: [['.', true]], DefaultRoute: true });
      active = true;
    }),
    verify: exclusive(async () => { await check(); return { active, released }; }),
    disable: exclusive(async () => {
      assert.equal(released, false);
      await ensureGuard(); await check(); await write(original); await check();
      await removeGuard(); active = false; released = true;
    }),
  };
}

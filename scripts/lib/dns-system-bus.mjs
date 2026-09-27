/** Checked resolve1 calls over the fixed system socket. Execution/authority is
 * provided by the pinned DNS command runner, never by environment bus options. */
import assert from 'node:assert/strict';
import { resolvedMethod, validateResolvedSettings } from './dns-resolved-backend.mjs';

const root = '/org/freedesktop/resolve1', manager = 'org.freedesktop.resolve1.Manager';
const properties = ['DNSEx', 'Domains', 'DefaultRoute'];
const empty = () => ({ DNSEx: [], Domains: [], DefaultRoute: false });
const ownerCheck = (owner) => assert.match(owner, /^:\d+\.\d+$/);
const indexCheck = (index) => assert.ok(Number.isInteger(index) && index > 1 && index <= 2147483647);
export function validateResolvedCall(args) {
  assert.ok(Array.isArray(args) && args.every((s) => typeof s === 'string'));
  const [method, signature, rawIndex, ...rest] = args, index = Number(rawIndex); indexCheck(index);
  let property, value;
  if (method === 'SetLinkDefaultRoute') {
    property = 'DefaultRoute'; assert.equal(signature, 'ib'); assert.equal(rest.length, 1);
    assert.ok(['true', 'false'].includes(rest[0])); value = rest[0] === 'true';
  } else if (method === 'SetLinkDomains') {
    property = 'Domains'; assert.equal(signature, 'ia(sb)'); const count = Number(rest.shift());
    assert.ok(Number.isInteger(count) && count >= 0 && count <= 32 && rest.length === count * 2);
    value = Array.from({ length: count }, (_, i) => { assert.ok(['true', 'false'].includes(rest[i * 2 + 1])); return [rest[i * 2], rest[i * 2 + 1] === 'true']; });
  } else {
    assert.equal(method, 'SetLinkDNSEx'); property = 'DNSEx'; assert.equal(signature, 'ia(iayqs)');
    const count = Number(rest.shift()); assert.ok(Number.isInteger(count) && count >= 0 && count <= 8); value = [];
    for (let i = 0; i < count; i++) {
      const family = Number(rest.shift()), length = Number(rest.shift());
      assert.ok([2, 10].includes(family)); assert.equal(length, family === 2 ? 4 : 16);
      value.push([family, rest.splice(0, length).map(Number), Number(rest.shift()), rest.shift()]);
    }
    assert.equal(rest.length, 0);
  }
  validateResolvedSettings({ ...empty(), [property]: value });
  assert.deepEqual(args, resolvedMethod(property, value, index), 'non-canonical resolved call');
  return args;
}
export function createDnsSystemBus(run) {
  assert.equal(typeof run, 'function');
  const execute = (args) => run('busctl', ['--address=unix:path=/run/dbus/system_bus_socket', '--timeout=5s',
      '--auto-start=no', '--allow-interactive-authorization=no', '--json=short', ...args]);
  const call = async (args) => {
    const { stdout } = await execute(args);
    assert.equal(typeof stdout, 'string'); assert.ok(Buffer.byteLength(stdout) <= 262144);
    const value = JSON.parse(stdout); assert.ok(value && Object.hasOwn(value, 'data')); return value.data;
  };
  const singleton = (value) => { assert.ok(Array.isArray(value) && value.length === 1); return value[0]; };
  return {
    async id() {
      const id = singleton(await call(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetId']));
      assert.match(id, /^[a-f0-9]{32}$/); return id;
    },
    async owner() {
      const owner = singleton(await call(['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.resolve1']));
      ownerCheck(owner); return owner;
    },
    async property(owner, index, property) {
      ownerCheck(owner); indexCheck(index); assert.ok(properties.includes(property));
      const path = singleton(await call(['call', owner, root, manager, 'GetLink', 'i', String(index)]));
      assert.match(path, /^\/org\/freedesktop\/resolve1\/link\/[A-Za-z0-9_]+$/);
      const result = await call(['get-property', owner, path, 'org.freedesktop.resolve1.Link', property]);
      validateResolvedSettings({ ...empty(), [property]: result }); return result;
    },
    // Void methods can return empty stdout. Success still requires the caller's
    // journaled readback; process completion alone is not a DNS state proof.
    async set(owner, args) { ownerCheck(owner); validateResolvedCall(args); await execute(['call', owner, root, manager, ...args]); },
  };
}

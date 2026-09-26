/** Client DNS53 guard executor. Caller owns the durable intent/context and flock.
 * No automatic host invocation, service stop hook, or implicit release. */
import assert from 'node:assert/strict';
import { isIPv4 } from 'node:net';

const keys = (value, expected) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
};
export function compileDnsClientGuard(input) {
  keys(input, input?.client === 'radxa' ? ['schema', 'client', 'id', 'usbInterface', 'usbAddress'] : ['schema', 'client', 'id']);
  assert.equal(input.schema, 1); assert.ok(['vps2', 'radxa'].includes(input.client));
  assert.match(input.id, /^[a-f0-9]{32}$/);
  if (input.client === 'radxa') {
    assert.match(input.usbInterface, /^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/);
    assert.notEqual(input.usbInterface, 'lo');
    assert.ok(isIPv4(input.usbAddress) && !/^(?:0|127|22[4-9]|2[3-5]\d)\./.test(input.usbAddress));
  }
  const marker = `cvdns:${input.id}:`;
  const families = [4, 6].map((family) => {
    const hooks = input.client === 'radxa' ? ['OUTPUT', 'INPUT', 'FORWARD'] : ['OUTPUT'];
    const chains = hooks.map((hook) => {
      const name = `CVD_${input.id.slice(0, 16)}_${hook[0]}`;
      const tagged = (role, args) => [...args, '-m', 'comment', '--comment', `${marker}${hook}:${role}`];
      const rules = [];
      for (const proto of ['udp', 'tcp']) {
        const dns = ['-p', proto, '-m', proto, '--dport', '53'];
        if (hook === 'OUTPUT') {
          const local = input.client === 'vps2' ? (family === 4 ? '127.0.0.53' : null) : (family === 4 ? '127.0.0.1' : '::1');
          if (local) rules.push(tagged(`local-${proto}`, ['-o', 'lo', '-d', local, ...dns, '-j', 'RETURN']));
          rules.push(tagged(`deny-${proto}`, [...dns, '-j', 'DROP']));
        } else {
          const incoming = ['-i', input.usbInterface, ...dns];
          if (hook === 'INPUT' && family === 4) rules.push(tagged(`local-${proto}`, [...incoming, '-d', input.usbAddress, '-j', 'RETURN']));
          rules.push(tagged(`deny-${proto}`, [...incoming, '-j', 'DROP']));
        }
      }
      return { hook, name, rules, jump: ['-m', 'comment', '--comment', `${marker}${hook}:hook`, '-j', name] };
    });
    return { family, chains };
  });
  return { schema: 1, input: { ...input }, families };
}

// Only normalize our own simple rules. Foreign syntax is not reserialized or
// executed. -S supplies implicit /32 and /128; option ordering is not semantic.
function canonical(line) {
  const words = line.replace(/"([A-Za-z0-9:_-]+)"/g, '$1').trim().split(/\s+/);
  assert.ok(words.every((word) => !/["'\\]/.test(word)), 'unexpected owned rule syntax');
  assert.equal(words.shift(), '-A');
  const chain = words.shift(), pairs = [];
  assert.equal(words.length % 2, 0);
  for (let i = 0; i < words.length; i += 2) {
    const key = words[i]; let value = words[i + 1];
    assert.ok(key.startsWith('-'));
    if (key === '-d') value = value.replace(/\/(?:32|128)$/, '');
    pairs.push(`${key} ${value}`);
  }
  return `${chain} ${pairs.sort().join(' ')}`;
}
const rule = (name, args) => `-A ${name} ${args.join(' ')}`;
function checkedPlan(plan) {
  const expected = compileDnsClientGuard(plan.input);
  assert.deepEqual(plan, expected, 'guard plan changed'); return expected;
}
export function inspectDnsClientGuard(plan, family, stdout) {
  checkedPlan(plan);
  assert.equal(typeof stdout, 'string'); assert.ok(Buffer.byteLength(stdout) <= 262144, 'firewall snapshot limit');
  const part = plan.families.find((entry) => entry.family === family); assert.ok(part);
  const lines = stdout.trim().split('\n').filter(Boolean);
  const names = new Set(part.chains.map((chain) => chain.name));
  const related = lines.filter((line) => /\bCVD_|cvdns:/.test(line));
  if (!related.length) return 'absent';
  const expected = part.chains.flatMap((chain) => [`-N ${chain.name}`, rule(chain.hook, chain.jump), ...chain.rules.map((args) => rule(chain.name, args))]);
  const normalize = (line) => line.startsWith('-N ') ? line : canonical(line);
  assert.deepEqual(related.map(normalize).sort(), expected.map(normalize).sort(), 'foreign, partial or duplicate DNS guard');
  for (const chain of part.chains) {
    const actualRules = lines.filter((line) => line.startsWith(`-A ${chain.name} `));
    assert.deepEqual(actualRules.map(canonical), chain.rules.map((args) => canonical(rule(chain.name, args))), 'DNS guard rule order changed');
    const first = lines.find((line) => line.startsWith(`-A ${chain.hook} `));
    assert.equal(canonical(first ?? ''), canonical(rule(chain.hook, chain.jump)), 'DNS guard hook is not first');
  }
  // Every reference contains the CVD_ name and was included above; no other
  // jump/goto can retain or bypass a chain unnoticed by this ownership check.
  assert.equal(names.size, part.chains.length);
  return 'present';
}
export function dnsClientGuardBatch(plan, family, action) {
  checkedPlan(plan); assert.ok(['install', 'release'].includes(action));
  const part = plan.families.find((entry) => entry.family === family); assert.ok(part);
  const lines = ['*filter'];
  for (const chain of part.chains) {
    if (action === 'install') {
      // -N, not :CHAIN declarations: an existing chain must fail, never flush.
      lines.push(`-N ${chain.name}`, ...chain.rules.map((args) => rule(chain.name, args)), `-I ${chain.hook} 1 ${chain.jump.join(' ')}`);
    } else {
      // Delete exact rules; a concurrently added foreign rule/reference makes
      // -X fail. Never flush a chain or restore a saved global firewall table.
      lines.push(`-D ${chain.hook} ${chain.jump.join(' ')}`, ...chain.rules.map((args) => `-D ${chain.name} ${args.join(' ')}`), `-X ${chain.name}`);
    }
  }
  return `${lines.join('\n')}\nCOMMIT\n`;
}

export function createDnsClientGuard({ input, read, restore, assertContext }) {
  const plan = compileDnsClientGuard(input);
  for (const fn of [read, restore, assertContext]) assert.equal(typeof fn, 'function');
  const inspect = async () => {
    await assertContext();
    const states = [];
    for (const family of [4, 6]) states.push(inspectDnsClientGuard(plan, family, await read(family)));
    return states;
  };
  const change = async (action) => {
    // Validate BOTH families before the first setter. A previous interrupted
    // family transaction is resumed, not rolled back to an open baseline.
    const before = await inspect();
    for (const [index, family] of [4, 6].entries()) {
      const wanted = action === 'install' ? 'present' : 'absent';
      if (before[index] === wanted) continue;
      await assertContext();
      assert.equal(inspectDnsClientGuard(plan, family, await read(family)), before[index], 'firewall changed before commit');
      await restore(family, dnsClientGuardBatch(plan, family, action));
      assert.equal(inspectDnsClientGuard(plan, family, await read(family)), wanted, 'guard commit readback failed');
    }
    const final = await inspect();
    assert.deepEqual(final, [action === 'install' ? 'present' : 'absent', action === 'install' ? 'present' : 'absent']);
    return { schema: 1, kind: 'clean-vpn-dns-client-guard', action, verified: true, families: [4, 6] };
  };
  return { inspect, ensure: () => change('install'),
    // This callback must read durable restore intent and verify current baseline;
    // a caller-supplied boolean or service stop is not a release protocol.
    async release(authorizeRestoredBaseline) {
      assert.equal(typeof authorizeRestoredBaseline, 'function');
      await assertContext(); assert.equal(await authorizeRestoredBaseline(), true, 'explicit verified restore required');
      return change('release');
    } };
}

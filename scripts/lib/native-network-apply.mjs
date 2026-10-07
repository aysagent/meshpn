// Network control only. Partial installs remain closed and require review;
// no blanket cleanup, rule adoption, overwrite or automatic rollback.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { nativeNetworkPlan, canonicalNativeTables, assertEmptyNativeTables } from './native-network-profile.mjs';
const hash = s => createHash('sha256').update(s).digest('hex');
export function applyNativeNetworkProfile(config, { run, read, save, scope }) {
  const plan = nativeNetworkPlan(config), fingerprint = hash(JSON.stringify(config));
  const tables = () => Object.fromEntries([['ipv6', 'ip6tables-save', 'filter'], ['ipv4', 'iptables-save', 'filter'],
    ['nat', 'iptables-save', 'nat'], ['mangle', 'iptables-save', 'mangle']].map(([key, bin, table]) =>
    [key, canonicalNativeTables(run(bin, ['-t', table]))]));
  const unmanaged = () => Object.fromEntries(['iptables-save', 'ip6tables-save'].map(bin => {
    const owned = bin === 'iptables-save' ? ['filter', 'nat', 'mangle'] : ['filter'];
    const blocks = canonicalNativeTables(run(bin, [])).split(/(?=^\*)/m).filter(Boolean);
    return [bin, blocks.filter(block => !owned.includes(block.split('\n')[0].slice(1))).join('')];
  }));
  const links = () => JSON.parse(run('ip', ['-j', '-d', 'link', 'show']));
  const identity = l => ({ index: l.ifindex, name: l.ifname, address: l.address ?? '', kind: l.linkinfo?.info_kind ?? l.link_type });
  const forwarding = () => run('sysctl', ['-n', 'net.ipv4.ip_forward']).trim();
  const verifyRules = (key, expected) => {
    const bin = key === 'ipv6' ? 'ip6tables' : 'iptables', table = key === 'ipv4' || key === 'ipv6' ? 'filter' : key;
    const lines = expected.trim().split('\n'), rules = lines.filter(l => l.startsWith('-A '));
    const policies = lines.filter(l => l.startsWith(':')).map(l => '-P ' + l.slice(1).split(' ').slice(0, 2).join(' ')).sort();
    const current = run(bin, ['-w', '5', '-t', table, '-S']).trim().split('\n');
    assert.deepEqual(current.filter(l => !l.startsWith('-A ')).sort(), policies, 'firewall_policy_readback');
    assert.equal(current.filter(l => l.startsWith('-A ')).length, rules.length, 'firewall_rule_count');
    for (const rule of rules) run(bin, ['-w', '5', '-t', table, '-C', ...rule.split(' ').slice(1)]);
  };
  const auditTun = () => {
    const l = links().find(l => l.ifname === config.tun);
    assert.ok(l && l.linkinfo?.info_kind === 'tun' && l.flags.includes('UP') && l.mtu === config.mtu, 'tun_readback_failed');
    const a = JSON.parse(run('ip', ['-j', '-4', 'addr', 'show', 'dev', config.tun]));
    assert.deepEqual(a[0].addr_info.filter(a => a.family === 'inet').map(a => `${a.local}/${a.prefixlen}`), [config.tun_address]);
    return identity(l);
  };
  let state = read();
  if (state !== null) {
    assert.equal(state.schema, 1); assert.equal(state.fingerprint, fingerprint, 'profile_changed');
    assert.deepEqual(state.scope, scope, 'different_boot_namespace');
    assert.equal(state.stage, 'installed', 'partial_network_install_requires_review');
    assert.deepEqual(tables(), state.tables, 'foreign_firewall_change');
    assert.deepEqual(unmanaged(), state.unmanaged, 'foreign_other_firewall_change');
    assert.deepEqual(auditTun(), state.tun, 'tun_replaced');
    for (const old of state.links) assert.deepEqual(identity(links().find(l => l.ifname === old.name) ?? {}), old, 'link_replaced');
    assert.equal(forwarding(), state.forwarding);
    return { status: 'verified', changed: false };
  }
  const initial = tables(); for (const t of Object.values(initial)) assertEmptyNativeTables(t);
  const other = unmanaged(); for (const t of Object.values(other)) assertEmptyNativeTables(t);
  const before = links(); assert.ok(!before.some(l => l.ifname === config.tun), 'existing_tun_refused');
  const ownedLinks = [config.uplink, ...(config.lan ? [config.lan.interface] : [])].map(name => {
    const l = before.find(l => l.ifname === name);
    assert.ok(l && !l.flags.includes('UP'), 'fresh_profile_requires_links_down'); return identity(l);
  });
  assert.equal(forwarding(), '0', 'fresh_forwarding_must_be_disabled');
  // Check syntax/modules before any mutation. IPv4/IPv6 commits are not atomic
  // together: links MUST stay down until this service has completed.
  for (const key of ['ipv6', 'ipv4', 'nat', 'mangle']) run(key === 'ipv6' ? 'ip6tables-restore' : 'iptables-restore', ['--test'], plan[key]);
  state = { schema: 1, fingerprint, scope, stage: 'prepared', links: ownedLinks, unmanaged: other };
  save(state);
  for (const key of ['ipv6', 'ipv4', 'nat', 'mangle']) {
    // Explicit owner of empty dedicated tables; no concurrent administrators.
    run(key === 'ipv6' ? 'ip6tables-restore' : 'iptables-restore', ['--wait', '5'], plan[key]);
    verifyRules(key, plan[key]);
    state.stage = key; save(state);
  }
  for (const args of plan.tun) run('ip', args);
  state.tun = auditTun(); state.stage = 'tun'; save(state);
  if (plan.forwarding) run('sysctl', ['-w', 'net.ipv4.ip_forward=1']);
  state.forwarding = forwarding(); assert.equal(state.forwarding, plan.forwarding ? '1' : '0');
  state.tables = tables(); assert.deepEqual(unmanaged(), other, 'foreign_other_firewall_change');
  state.stage = 'installed'; save(state);
  return { status: 'installed', changed: true };
}

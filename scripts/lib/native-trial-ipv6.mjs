/** Read-only IPv6 admission/cleanup checks for the IPv4-only native trial. */
import fs from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { ipv6StateDirectory, validateIpv6State } from './vpn-ipv6-runtime.mjs';
import { CLIENT6, IPV6_TABLE, IPV6_PRIORITY, isVpnIpv6Rule, ipv6Plan, overlapsVpnIpv6 } from './vpn-ipv6.mjs';

const check = (ok, code) => { if (!ok) throw Error(code); };
const ownedRule = r => String(r.priority) === IPV6_PRIORITY || String(r.table) === IPV6_TABLE;
export const trialIpv6Scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
  net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });

// The running legacy client holds the journal lock. Read an atomic snapshot,
// without acquiring/stealing its lock or invoking recovery on a live client.
export function readTrialIpv6State(directory = ipv6StateDirectory()) {
  const c = fs.constants;
  const dir = fs.openSync(directory, c.O_RDONLY | c.O_DIRECTORY | c.O_NOFOLLOW);
  try {
    const d = fs.fstatSync(dir);
    check(d.uid === 0 && (d.mode & 0o777) === 0o700, 'unsafe_ipv6_journal_directory');
    const fd = fs.openSync(`/proc/self/fd/${dir}/journal.json`, c.O_RDONLY | c.O_NOFOLLOW | c.O_NONBLOCK);
    try {
      const s = fs.fstatSync(fd);
      check(s.isFile() && s.uid === 0 && s.nlink === 1 && (s.mode & 0o777) === 0o600
        && s.size > 0 && s.size < 16384, 'unsafe_ipv6_journal');
      const b = Buffer.alloc(s.size);
      check(fs.readSync(fd, b, 0, b.length, 0) === b.length, 'ipv6_journal_read_failed');
      return validateIpv6State(JSON.parse(b.toString()));
    } finally { fs.closeSync(fd); }
  } finally { fs.closeSync(dir); }
}

export function validateBlockedTrialIpv6(e) {
  check(e && typeof e === 'object', 'ipv6_auto_requires_blocked_evidence');
  let s;
  try { s = validateIpv6State(e.state); } catch { throw Error('invalid_ipv6_trial_journal'); }
  check(isDeepStrictEqual(s.scope, e.scope), 'ipv6_journal_scope_mismatch');
  check(s.config.role === 'client' && s.config.tun === 'tun0' && s.config.ext === null,
    'ipv6_trial_profile_mismatch');
  check(s.stage === 'active' && s.dynamic === false, 'ipv6_tunnel_not_supported');
  check(s.backend === e.backend, 'ipv6_backend_changed');
  const tun = e.links.find(l => l.ifname === 'tun0');
  check(tun && isDeepStrictEqual(s.links.tun0,
    { ifindex: tun.ifindex, address: tun.address ?? '', type: tun.link_type }), 'ipv6_tun_identity_changed');
  check(tun.addr_info.some(a => a.family === 'inet6' && a.local === CLIENT6 && a.prefixlen === 126),
    'ipv6_owned_address_missing');
  // Fixed reviewed policy only: no earlier policy route can bypass the block.
  check(e.rules.filter(isVpnIpv6Rule).length === 1 && e.rules.every(r => isVpnIpv6Rule(r)
    || isDeepStrictEqual(r, { priority: 0, src: 'all', table: 'local' })
    || isDeepStrictEqual(r, { priority: 32766, src: 'all', table: 'main' })), 'ipv6_block_rule_mismatch');
  const routes = e.routes.filter(r => String(r.table) === IPV6_TABLE);
  check(routes.length === 1 && routes[0].type === 'unreachable' && routes[0].dst === 'default'
    && routes[0].metric === 32767, 'ipv6_block_route_mismatch');
  check(!e.routes.some(r => r.dev === 'tun0' && r.type !== 'local' && !overlapsVpnIpv6(r.dst)
    && !['fe80::/64', 'ff00::/8'].includes(r.dst)), 'ipv6_tunnel_route_present');
  return e;
}

export async function inspectBlockedTrialIpv6({ run, readState = readTrialIpv6State, scope = trialIpv6Scope }) {
  const state = readState();
  const read = async args => JSON.parse(await run('ip', ['-j', ...args]));
  const backend = /\((nf_tables|legacy)\)/.exec(await run('ip6tables', ['--version']))?.[1];
  const evidence = validateBlockedTrialIpv6({ state, scope: scope(), backend,
    links: await read(['address', 'show']), rules: await read(['-6', 'rule', 'show']),
    routes: await read(['-6', 'route', 'show', 'table', 'all']) });
  for (const op of ipv6Plan(state.config)) {
    if (op.kind === 'fw' || op.kind === 'chain') await run(op.file, op.check);
  }
  check(isDeepStrictEqual(state, readState()), 'ipv6_changed_during_trial_preflight');
  return evidence;
}

export function validateReleasedTrialIpv6({ report, rules, routes, links, filter, nat }, required) {
  check(report.mode === 'dry-run' && report.stage === 'released' && report.operations === 0 && report.tunnelRoute === false
    || !required && report.mode === 'no-journal' && report.operations === 0, 'ipv6_journal_not_released');
  check(!links.some(l => l.ifname === 'tun0'), 'ipv6_cleanup_requires_no_tun');
  check(!rules.some(ownedRule) && !routes.some(r => String(r.table) === IPV6_TABLE || overlapsVpnIpv6(r.dst))
    && !links.some(l => l.addr_info.some(a => a.family === 'inet6' && overlapsVpnIpv6(`${a.local}/${a.prefixlen}`)))
    && !/CV6_|clean-vpn-ipv6-/.test(filter + '\n' + nat), 'ipv6_cleanup_incomplete');
}

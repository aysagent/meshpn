/** IPv4 gateway selection by ingress interface; no host OUTPUT/default-route changes. */
import { execFileSync } from 'node:child_process';

export const INGRESS_TABLE = 19999;
export const INGRESS_PRIORITY = 10999;
export const INGRESS_BYPASS = Object.freeze([
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
]);
const CHAIN = 'CVPN-INGRESS';
const TAG = 'clean-vpn-from-tun';
const nativeRun = (file, args) => execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

export function validateFromTun(options) {
  const name = options.fromTun;
  if (name == null) return;
  if (typeof name !== 'string' || !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/.test(name) || name === 'lo') {
    throw new Error('--from-tun: нужен интерфейс Linux (1..15 символов), не lo');
  }
  if (options.role !== 'client') throw new Error('--from-tun только для --role=client');
  for (const [key, flag] of [['splitDefault', '--split-default'], ['clientLanSubnet', '--client-lan-subnet'],
    ['transparentTlsLanBind', '--transparent-tls-lan-bind']]) {
    if (options[key] != null && options[key] !== false) throw new Error(`--from-tun несовместим с ${flag}`);
  }
  if (['combo-tls', 'transparent-tls'].includes(options.type) && options.tunnelPeer) {
    throw new Error('--from-tun несовместим с тестовым --tunnel-peer для HTTPS relay');
  }
}

/** Read-only preflight. Reserved table/priority must be unused; never adopt stale state. */
export function inspectIngress(name, { run = nativeRun } = {}) {
  validateFromTun({ fromTun: name, role: 'client' });
  const links = JSON.parse(run('ip', ['-j', 'link', 'show', 'dev', name]));
  if (links.length !== 1 || !links[0].flags.includes('UP')) throw new Error('--from-tun: входной интерфейс должен существовать и быть UP');
  if (run('sysctl', ['-n', 'net.ipv4.ip_forward']) !== '1') {
    throw new Error('--from-tun: требуется уже настроенный шлюз с net.ipv4.ip_forward=1 (глобальный forwarding автоматически не меняется)');
  }
  const rules = JSON.parse(run('ip', ['-j', '-4', 'rule', 'show']));
  if (rules.filter((r) => Number(r.priority) === 0).length !== 1
    || !rules.some((r) => Number(r.priority) === 0 && (r.table === 'local' || r.table === 255))) {
    throw new Error('--from-tun: требуется стандартное priority 0 lookup local');
  }
  // Earlier custom policies may divert ingress before our lookup. Fail rather than guess.
  if (rules.some((r) => Number(r.priority) > 0 && Number(r.priority) <= INGRESS_PRIORITY)
    || rules.some((r) => String(r.table) === String(INGRESS_TABLE))) {
    throw new Error('--from-tun: конфликт policy routing (priority <= 10999 / table 19999); нужна отдельная проверка');
  }
  const routes = JSON.parse(run('ip', ['-j', '-4', 'route', 'show', 'table', 'all']));
  if (routes.some((r) => String(r.table) === String(INGRESS_TABLE))) throw new Error('--from-tun: table 19999 занята, возможно осталась после аварии');
  for (const binary of ['iptables', 'ip6tables']) {
    const state = run(binary, ['-w', '5', '-t', 'filter', '-S']);
    if (state.includes(CHAIN)) throw new Error(`--from-tun: ${CHAIN} уже существует; сначала проверьте оставшиеся правила`);
  }
  // Explicitly connected IPv4 destinations (including public LAN prefixes) stay on their existing path.
  const connected = routes.filter((r) => (!r.table || r.table === 'main' || r.table === 254)
    && r.protocol === 'kernel' && r.scope === 'link' && r.dst && r.dst !== 'default' && !r.gateway).map((r) => r.dst);
  return { name, bypass: [...new Set([...INGRESS_BYPASS, ...connected])] };
}

/** Transactions delete only successfully installed, exact rules; cleanup errors are not swallowed. */
export function installIngressRouting({ ingress, tun, address = '10.99.0.2', tag = TAG }, { run = nativeRun, transaction } = {}) {
  if (ingress.name === tun) throw new Error('incoming interface must differ from clean-vpn TUN');
  const undo = [];
  let closed = false;
  const apply = (file, args, remove) => {
    if (transaction) transaction.apply({ file, args, remove }); else run(file, args);
    undo.unshift(() => run(file, remove));
  };
  const ip = (args, remove) => apply('ip', args, remove);
  const rule = (binary, table, chain, spec, first = false) => {
    spec = spec.map((s) => s === TAG ? tag : s);
    if (tag !== TAG && !spec.includes('--comment')) spec = ['-m', 'comment', '--comment', tag, ...spec];
    apply(binary,
    ['-w', '5', '-t', table, first ? '-I' : '-A', chain, ...(first ? ['1'] : []), ...spec],
    ['-w', '5', '-t', table, '-D', chain, ...spec]);
  };
  const chain = (binary) => apply(binary, ['-w', '5', '-N', CHAIN], ['-w', '5', '-X', CHAIN]);
  const close = () => {
    if (closed) return;
    if (transaction) { transaction.close(); closed = true; return; }
    const errors = [];
    // Do not remove the safety rules if route/NAT cleanup has failed.
    while (undo.length) {
      try { undo[0](); undo.shift(); } catch (error) { errors.push(error); break; }
    }
    if (errors.length) throw new AggregateError(errors, '--from-tun: cleanup failed; remaining guard/rules retained for inspection');
    closed = true;
  };
  try {
    // Safety chains are attached before routes or ACCEPTs. On SIGKILL they remain.
    chain('iptables');
    for (const destination of ingress.bypass) rule('iptables', 'filter', CHAIN, ['-d', destination, '-j', 'RETURN']);
    rule('iptables', 'filter', CHAIN, ['-j', 'DROP']);
    rule('iptables', 'filter', 'FORWARD', ['-i', ingress.name, '-m', 'comment', '--comment', TAG, '-j', CHAIN], true);
    chain('ip6tables');
    rule('ip6tables', 'filter', CHAIN, ['-j', 'DROP']);
    rule('ip6tables', 'filter', 'FORWARD', ['-i', ingress.name, '-m', 'comment', '--comment', TAG, '-j', CHAIN], true);

    // The unreachable fallback survives disappearance of TUN's connected/default routes.
    ip(['-4', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', String(INGRESS_TABLE)],
      ['-4', 'route', 'del', 'unreachable', 'default', 'metric', '32767', 'table', String(INGRESS_TABLE)]);
    for (const destination of ingress.bypass) ip(['-4', 'route', 'add', 'throw', destination, 'table', String(INGRESS_TABLE)],
      ['-4', 'route', 'del', 'throw', destination, 'table', String(INGRESS_TABLE)]);
    ip(['-4', 'route', 'add', 'default', 'dev', tun, 'metric', '10', 'table', String(INGRESS_TABLE)],
      ['-4', 'route', 'del', 'default', 'dev', tun, 'metric', '10', 'table', String(INGRESS_TABLE)]);
    ip(['-4', 'rule', 'add', 'priority', String(INGRESS_PRIORITY), 'iif', ingress.name, 'lookup', String(INGRESS_TABLE)],
      ['-4', 'rule', 'del', 'priority', String(INGRESS_PRIORITY), 'iif', ingress.name, 'lookup', String(INGRESS_TABLE)]);
    for (const iface of [ingress.name, tun]) {
      // Slash syntax preserves dots inside interface names (e.g. wg0.100).
      const key = `net/ipv4/conf/${iface}/rp_filter`;
      const previous = run('sysctl', ['-n', key]);
      apply('sysctl', ['-w', `${key}=2`], ['-w', `${key}=${previous}`]);
      if (run('sysctl', ['-n', key]) !== '2') throw new Error(`--from-tun: не удалось изменить ${key}`);
    }
    // This is our private, newly created TUN, never wg0. No SNAT on the host uplink.
    rule('iptables', 'nat', 'POSTROUTING', ['-o', tun, '-m', 'comment', '--comment', TAG, '-j', 'SNAT', '--to-source', address], true);
    rule('iptables', 'filter', 'FORWARD', ['!', '-i', ingress.name, '-o', tun, '-m', 'comment', '--comment', TAG, '-j', 'DROP'], true);
    rule('iptables', 'filter', 'FORWARD', ['-i', tun, '-o', ingress.name, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED',
      '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'], true);
    rule('iptables', 'filter', CHAIN, ['-o', tun, '-j', 'ACCEPT'], true);
  } catch (error) {
    try { close(); } catch (cleanupError) { throw new AggregateError([error, cleanupError], '--from-tun: setup and rollback failed'); }
    throw error;
  }
  return {
    close,
    /** Call only after the relay is listening on the private TUN IPv4 address. */
    installHttpsRedirect(port) {
      if (closed || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid ingress HTTPS redirect');
      transaction?.https(port);
      // A dedicated chain gives both routing and interception identical bypass semantics.
      const natChain = `${CHAIN}-HTTPS`;
      // After TUN disappears, old conntrack DNAT entries must not escape via the private-net bypass.
      rule('iptables', 'filter', CHAIN, ['-d', address, '-p', 'tcp', '--dport', String(port),
        '-m', 'conntrack', '--ctstate', 'DNAT', '-j', 'DROP'], true);
      apply('iptables', ['-w', '5', '-t', 'nat', '-N', natChain], ['-w', '5', '-t', 'nat', '-X', natChain]);
      rule('iptables', 'nat', natChain, ['-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'RETURN']);
      for (const destination of ingress.bypass) rule('iptables', 'nat', natChain, ['-d', destination, '-j', 'RETURN']);
      rule('iptables', 'nat', natChain, ['-p', 'tcp', '--dport', '443', '-j', 'DNAT', '--to-destination', `${address}:${port}`]);
      // Restrict the listener to DNATed HTTPS from this ingress (not arbitrary external access).
      rule('iptables', 'filter', 'INPUT', ['-d', address, '-p', 'tcp', '--dport', String(port), '-m', 'comment', '--comment', TAG, '-j', 'DROP'], true);
      rule('iptables', 'filter', 'INPUT', ['-i', ingress.name, '-d', address, '-p', 'tcp', '--dport', String(port),
        '-m', 'conntrack', '--ctstate', 'DNAT', '--ctorigdstport', '443', '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'], true);
      rule('iptables', 'nat', 'PREROUTING', ['-i', ingress.name, '-p', 'tcp', '--dport', '443', '-m', 'comment', '--comment', TAG, '-j', natChain], true);
    },
  };
}

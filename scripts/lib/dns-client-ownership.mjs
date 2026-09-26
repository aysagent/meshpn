/** Read-only, filtered evidence. Never executes config, starts services, or grants takeover authority. */
import assert from 'node:assert/strict';
import { lstat, readlink, realpath, readdir } from 'node:fs/promises';
import { isIP } from 'node:net';
import { isDeepStrictEqual } from 'node:util';
import { boundedInspectRead } from './dns-inspect.mjs';
import { DIAGNOSTIC_ENV, filterDiagnosticIni } from './dns-diagnostic.mjs';
import { filterDnsmasqDiagnostic } from './dnsmasq-config.mjs';
import { runCommand } from './transparent-acceptance.mjs';

const UNIT_NAMES = ['dnsmasq.service', 'systemd-resolved.service', 'systemd-networkd.service'];
const UNIT_FIELDS = ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID',
  'FragmentPath', 'SourcePath', 'DropInPaths', 'ControlGroup', 'NeedDaemonReload', 'Type', 'User', 'Group',
  'DynamicUser', 'RootDirectory', 'RootImage', 'PrivateNetwork', 'NetworkNamespacePath'];
const SAFE_ERRORS = new Set(['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM', 'ESRCH', 'ELOOP', 'EINVAL']);
const unavailable = (e) => ({ status: 'unavailable', reason: SAFE_ERRORS.has(e?.code) ? e.code : 'unsupported-or-changing-evidence' });
const simplePath = (s) => typeof s === 'string' && s.length <= 512 && /^\/(?:[A-Za-z0-9_.@+-]+\/)*[A-Za-z0-9_.@+-]+$/.test(s)
  && s.split('/').every((p) => p !== '.' && p !== '..');
export const dnsmasqConfigPath = (s) => simplePath(s) && (s === '/etc/dnsmasq.conf' || s.startsWith('/etc/dnsmasq.d/'));
export const networkConfigPath = (s) => simplePath(s) && /^\/(?:etc|run|usr\/lib|lib)\/systemd\/network\/[\w.-]+\.network$/.test(s);
const unitPath = (s) => simplePath(s) && (/^\/(?:etc|run|usr\/lib|lib)\/systemd\//.test(s) || s === '/etc/init.d/dnsmasq');

export function parseOwnershipUnit(text, expected) {
  assert.ok(UNIT_NAMES.includes(expected));
  const fields = {};
  for (const line of text.trim().split('\n')) {
    const i = line.indexOf('='); if (i < 0) continue;
    const key = line.slice(0, i), value = line.slice(i + 1);
    if (!UNIT_FIELDS.includes(key)) continue;
    assert.ok(!Object.hasOwn(fields, key), 'duplicate unit field');
    if (key === 'MainPID') { assert.match(value, /^\d{1,10}$/); fields[key] = Number(value); }
    else if (key === 'InvocationID') { assert.ok(value === '' || /^[a-f0-9]{32}$/.test(value)); fields[key] = value; }
    else if (key === 'DropInPaths') {
      const paths = value ? value.split(' ') : []; assert.ok(paths.length <= 16);
      fields[key] = paths.map((p) => unitPath(p) ? p : '[unsupported-path]');
    } else if (['FragmentPath', 'SourcePath'].includes(key)) fields[key] = value === '' || unitPath(value) ? value : '[unsupported-path]';
    else if (['RootDirectory', 'RootImage', 'NetworkNamespacePath'].includes(key)) fields[key] = value === '' ? '' : '[configured]';
    else if (key === 'ControlGroup') fields[key] = /^\/(?:[\w@.-]+\/)*[\w@.-]+$/.test(value) && value.length <= 512 ? value : '[unsupported]';
    else fields[key] = value === '' || /^[\w@.-]{1,128}$/.test(value) ? value : '[unsupported]';
  }
  assert.equal(fields.Id, expected); assert.ok(typeof fields.LoadState === 'string');
  return fields;
}

export function dnsmasqSource(key, value) {
  if (key === 'conf-file') return value === '' ? { key, disabled: true } : dnsmasqConfigPath(value) ? { key, path: value } : { key, unsupported: true };
  if (key !== 'conf-dir') return null;
  const [path, ...suffixes] = value.split(',');
  if (!(path === '/etc/dnsmasq.d' || dnsmasqConfigPath(path)) || suffixes.length > 8
    || suffixes.some((s) => !/^\*?\.[A-Za-z0-9_.-]{1,48}$/.test(s))) return { key, unsupported: true };
  // Mixed positive/negative suffix rules need full dnsmasq parser review.
  if (suffixes.some((s) => s.startsWith('*')) && suffixes.some((s) => !s.startsWith('*'))) return { key, unsupported: true };
  return { key, path, suffixes };
}
const ARG_VALUE = new Map([['C', 'conf-file'], ['7', 'conf-dir'], ['r', 'resolv-file'], ['S', 'server'], ['i', 'interface'],
  ['I', 'except-interface'], ['a', 'listen-address'], ['p', 'port'], ['x', 'pid-file'], ['u', 'user'], ['g', 'group']]);
const ARG_FLAG = new Map([['k', 'keep-in-foreground'], ['d', 'no-daemon'], ['R', 'no-resolv'], ['h', 'no-hosts'], ['z', 'bind-interfaces']]);
const LONG_VALUES = new Set([...ARG_VALUE.values(), 'servers-file', 'conf-script', 'dhcp-script', 'dhcp-option', 'dhcp-range']);
const LONG_FLAGS = new Set([...ARG_FLAG.values(), 'bind-dynamic', 'no-poll', 'local-service', 'strict-order', 'domain-needed', 'bogus-priv']);

export function filterDnsmasqArgv(text) {
  assert.ok(Buffer.byteLength(text) <= 16384 && text.endsWith('\0'), 'bounded NUL argv required');
  const args = text.slice(0, -1).split('\0'); assert.ok(args.length > 0 && args.length <= 128);
  assert.ok(/(?:^|\/)dnsmasq$/.test(args[0]), 'unexpected argv0');
  const result = { argumentCount: args.length - 1, options: [], sources: [], omitted: 0, hooksObserved: false,
    additionalSourcesObserved: false, defaultConfigCandidate: true };
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]; let key, value;
    const long = /^--([a-z][a-z0-9-]*)(?:=(.*))?$/.exec(arg), short = /^-([A-Za-z0-9])(.*)$/.exec(arg);
    if (long) { key = long[1]; value = long[2]; }
    else if (short && ARG_VALUE.has(short[1])) { key = ARG_VALUE.get(short[1]); value = short[2] || undefined; }
    else if (short && ARG_FLAG.has(short[1]) && !short[2]) key = ARG_FLAG.get(short[1]);
    else { result.omitted++; continue; }
    if (LONG_VALUES.has(key) && value === undefined && i + 1 < args.length && !args[i + 1].startsWith('-')) value = args[++i];
    if (key === 'conf-file' || key === 'conf-dir') {
      if (key === 'conf-file') result.defaultConfigCandidate = false;
      result.sources.push(value === undefined ? { key, unsupported: true } : dnsmasqSource(key, value)); continue;
    }
    if (key === 'conf-script' || key === 'dhcp-script') { result.hooksObserved = true; result.omitted++; continue; }
    if (key === 'servers-file' || key === 'resolv-file') { result.additionalSourcesObserved = true; result.omitted++; continue; }
    if (['pid-file', 'user', 'group'].includes(key)) { result.options.push({ key, value: '[not-collected]' }); continue; }
    if (LONG_FLAGS.has(key) && value === undefined) { result.options.push({ key }); continue; }
    const filtered = filterDnsmasqDiagnostic(`${key}${value === undefined ? '' : `=${value}`}`);
    if (filtered.entries.length === 1 && !filtered.omitted && !filtered.unparsed) result.options.push(filtered.entries[0]);
    else result.omitted++;
  }
  if (result.defaultConfigCandidate) result.sources.unshift({ key: 'conf-file', path: '/etc/dnsmasq.conf', implicit: true });
  return result;
}

export function filterNetworkdState(text) {
  const result = {}, fields = ['NETWORK_FILE', 'ADMIN_STATE', 'OPER_STATE', 'DNS', 'DOMAINS', 'ROUTE_DOMAINS'];
  for (const line of text.split('\n')) {
    const i = line.indexOf('='); if (i < 0) continue;
    const key = line.slice(0, i), value = line.slice(i + 1); if (!fields.includes(key)) continue;
    assert.ok(!Object.hasOwn(result, key), 'duplicate networkd state');
    if (key === 'NETWORK_FILE') result[key] = networkConfigPath(value) ? value : '[unsupported-path]';
    else if (key === 'DNS') result[key] = value === '' ? [] : value.split(' ').map((s) => isIP(s) ? s : '[unsupported]');
    else if (key === 'DOMAINS' || key === 'ROUTE_DOMAINS') result[key] = value === '' ? [] : value.split(' ').map((s) => /^~?[a-zA-Z0-9.-]{1,253}$/.test(s) ? s : '[unsupported]');
    else result[key] = /^[a-z-]{1,32}$/.test(value) ? value : '[unsupported]';
  }
  return result;
}
function processToken(text, pid) {
  assert.ok(text.startsWith(`${pid} (`)); const end = text.lastIndexOf(')'); assert.ok(end > 0);
  const fields = text.slice(end + 2).trim().split(' '); assert.match(fields[19], /^\d+$/);
  assert.ok(!['Z', 'X', 'x'].includes(fields[0]), 'process exited'); return fields[19];
}

export async function collectDnsClientOwnership(diagnostic, {
  read = boundedInspectRead, link = readlink, canonical = realpath, stat = lstat, list = readdir,
  run = runCommand, budgetMs = 30000,
} = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), budgetMs);
  const report = { schema: 1, kind: 'clean-vpn-dns-ownership-evidence', mode: 'read-only', systemSettingsChanged: false,
    units: {}, networkd: [], dnsmasq: {}, takeoverAuthorized: false, effectiveConfigProven: false,
    limitations: ['point-in-time-not-ownership-authority', 'disk-config-not-proof-of-loaded-config',
      'no-unit-or-hook-execution', 'filtered-dnsmasq-argv-not-raw-argv', 'networkd-runtime-file-is-version-dependent',
      'no-ACL-xattr-capability-or-manager-lock-proof', 'no-live-installer', 'no-firewall-or-VPN-pilot-proof'] };
  const budget = () => assert.equal(controller.signal.aborted, false, 'collection deadline');
  const unit = async (name) => {
    budget();
    const r = await run('/usr/bin/systemctl', ['--system', '--no-pager', 'show', name, ...UNIT_FIELDS.flatMap((p) => ['-p', p])],
      { env: { ...DIAGNOSTIC_ENV }, timeoutMs: 3000, maxBytes: 16384, signal: controller.signal });
    assert.ok(!r.reason && [0, 4].includes(r.code), 'unit unavailable');
    return parseOwnershipUnit(r.stdout, name); // Never copy raw stdout/stderr (may contain paths/argv).
  };
  const config = async (path, allowed, filter) => {
    budget(); assert.ok(allowed(path)); const resolved = await canonical(path); assert.ok(allowed(resolved), 'config target outside supported roots');
    const before = await stat(path, { bigint: true }); assert.ok(before.isFile() && before.nlink === 1n, 'regular unlinked config required');
    const data = filter(await read(path, 32768));
    const after = await stat(path, { bigint: true });
    for (const k of ['dev', 'ino', 'ctimeNs', 'size', 'mode', 'uid', 'gid']) assert.equal(after[k], before[k], 'config changed during inspection');
    assert.equal(await canonical(path), resolved); assert.ok(Buffer.byteLength(JSON.stringify(data)) <= 16384);
    return { status: 'ok', metadata: { identity: `${before.dev}:${before.ino}`, uid: Number(before.uid), gid: Number(before.gid),
      mode: Number(before.mode & 0o7777n), writableByGroupOrOther: Boolean(before.mode & 0o022n) }, data };
  };
  try {
    if (diagnostic.inspection?.environment?.pid1 !== 'systemd') { report.status = 'not-probed-non-systemd'; return report; }
    for (const name of UNIT_NAMES) {
      try { report.units[name] = { status: 'ok', fields: await unit(name) }; } catch (e) { report.units[name] = unavailable(e); }
    }
    // Use the runtime-selected NETWORK_FILE, not alphabetical guesses about netplan precedence.
    let links = [];
    try {
      assert.equal(diagnostic.commands.links.status, 'ok');
      links = JSON.parse(diagnostic.commands.links.stdout).filter((l) => Number.isSafeInteger(l.ifindex) && l.ifindex > 1 && l.ifindex <= 2147483647
        && typeof l.ifname === 'string' && /^[\w.-]{1,15}$/.test(l.ifname));
    } catch { report.networkdLinkListUnavailable = true; }
    report.networkdLinksTruncated = links.length > 8;
    if (report.units['systemd-networkd.service'].fields?.ActiveState === 'active') for (const l of links.slice(0, 8)) {
      const entry = { ifindex: l.ifindex, name: l.ifname }; report.networkd.push(entry);
      try {
        budget(); const path = `/run/systemd/netif/links/${l.ifindex}`, before = await read(path, 32768);
        entry.state = filterNetworkdState(before);
        const chosen = entry.state.NETWORK_FILE;
        if (chosen && networkConfigPath(chosen)) {
          try { entry.selectedConfig = await config(chosen, networkConfigPath, filterDiagnosticIni); }
          catch (e) { entry.selectedConfig = unavailable(e); }
        }
        entry.stable = before === await read(path, 32768); entry.status = entry.stable ? 'ok' : 'changed';
      } catch (e) { Object.assign(entry, unavailable(e)); }
    }
    const first = report.units['dnsmasq.service'].fields;
    if (!first || first.ActiveState !== 'active' || !first.MainPID || !first.InvocationID) report.dnsmasq.status = 'no-active-main-pid';
    else {
      try {
        budget(); const pid = first.MainPID, base = `/proc/${pid}`, token = processToken(await read(`${base}/stat`, 8192), pid);
        const exe = await link(`${base}/exe`);
        assert.ok(['/usr/sbin/dnsmasq', '/sbin/dnsmasq', '/usr/local/sbin/dnsmasq'].includes(exe), 'unreviewed executable');
        const namespacesMatch = {};
        for (const key of ['net', 'mnt', 'pid']) namespacesMatch[key] = await link(`${base}/ns/${key}`) === await link(`/proc/self/ns/${key}`);
        const cgroups = (await read(`${base}/cgroup`, 16384)).split('\n').map((s) => s.split(':')[2]);
        const cgroupMatchesUnit = first.ControlGroup !== '[unsupported]' && cgroups.includes(first.ControlGroup);
        const argv = filterDnsmasqArgv(await read(`${base}/cmdline`, 16384));
        assert.equal(processToken(await read(`${base}/stat`, 8192), pid), token, 'PID reused');
        assert.ok(isDeepStrictEqual(await unit('dnsmasq.service'), first), 'service changed');
        report.dnsmasq = { status: 'ok', pid, startTimeTicks: token, executable: exe, namespacesMatch, cgroupMatchesUnit, argv,
          configs: {}, directories: [], sourceGraphComplete: true, loadedConfigProven: false };
        const queue = argv.sources.map((s) => ({ ...s, depth: 0 })), seen = new Set();
        let count = 0;
        while (queue.length && count++ < 48) {
          budget(); const s = queue.shift();
          if (s.disabled) continue;
          if (s.unsupported || s.depth > 4) { report.dnsmasq.sourceGraphComplete = false; continue; }
          const id = JSON.stringify([s.key, s.path, s.suffixes ?? []]);
          if (seen.has(id)) { report.dnsmasq.sourceGraphComplete = false; continue; } seen.add(id);
          if (s.key === 'conf-dir') {
            const dir = { path: s.path, suffixes: s.suffixes }; report.dnsmasq.directories.push(dir);
            try {
              assert.equal(await canonical(s.path), s.path); const st = await stat(s.path); assert.ok(st.isDirectory());
              const names = await list(s.path), selected = names.filter((n) => !n.startsWith('.') && !n.endsWith('~') && !(n.startsWith('#') && n.endsWith('#'))
                && (!s.suffixes.length || (s.suffixes[0].startsWith('*') ? s.suffixes.some((x) => n.endsWith(x.slice(1))) : !s.suffixes.some((x) => n.endsWith(x))))).sort();
              dir.count = selected.length; dir.truncated = selected.length > 32;
              if (dir.truncated) report.dnsmasq.sourceGraphComplete = false;
              for (const n of selected.slice(0, 32)) {
                if (!/^[\w.-]+$/.test(n) || !dnsmasqConfigPath(`${s.path}/${n}`)) { report.dnsmasq.sourceGraphComplete = false; continue; }
                queue.push({ key: 'conf-file', path: `${s.path}/${n}`, depth: s.depth + 1 });
              }
              dir.status = 'ok';
            } catch (e) { Object.assign(dir, unavailable(e)); report.dnsmasq.sourceGraphComplete = false; }
          } else {
            try {
              const r = await config(s.path, dnsmasqConfigPath, (text) => {
                const sources = [];
                for (const line of text.split('\n')) {
                  const m = /^\s*(conf-file|conf-dir)=(.*?)\s*$/.exec(line);
                  if (m) sources.push(dnsmasqSource(m[1], m[2]));
                }
                return { ...filterDnsmasqDiagnostic(text), sources };
              });
              report.dnsmasq.configs[s.path] = r;
              for (const source of r.data.sources) queue.push({ ...source, depth: s.depth + 1 });
              if (r.data.omitted || r.data.unparsed || r.data.entries.some((e) => ['servers-file', 'resolv-file'].includes(e.key))) report.dnsmasq.sourceGraphComplete = false;
            } catch (e) { report.dnsmasq.configs[s.path] = unavailable(e); report.dnsmasq.sourceGraphComplete = false; }
          }
        }
        if (queue.length || argv.omitted || argv.hooksObserved || argv.additionalSourcesObserved) report.dnsmasq.sourceGraphComplete = false;
        assert.equal(processToken(await read(`${base}/stat`, 8192), pid), token, 'PID changed during config inventory');
        assert.ok(isDeepStrictEqual(await unit('dnsmasq.service'), first), 'service changed during inventory');
      } catch (e) { report.dnsmasq = unavailable(e); }
    }
    report.status = 'collected'; return report;
  } finally { report.deadlineExceeded = controller.signal.aborted; clearTimeout(timer); }
}

/** Distinct fresh and released deployment observations. Read-only, no implicit
 * service stop, guard release, state adoption or uninstall authority. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, readFile, readlink, readdir, open } from 'node:fs/promises';
import { assertDnsSystemCommands, inspectDnsSystemExecutable } from './dns-system-command.mjs';
import { requireDnsBootGuardLock, readDnsBootNamespaceAnchor } from './dns-boot-guard.mjs';
import { compileDnsClientGuard, inspectDnsClientGuard } from './dns-client-guard.mjs';
import { readReleasedDnsHistory } from './dns-released-history.mjs';
import { createDnsSystemBus } from './dns-system-bus.mjs';
import { validateVps2DnsUnit, validateReleasedDnsManagerUnit } from './dns-installed-vps2.mjs';

const units = new Set(['clean-vpn-dns-guard.service', 'clean-vpn-dns-adapter.service',
  'clean-vpn-dns-client.service', 'clean-vpn-dns-disable.service']);
const related = (name) => name.startsWith('clean-vpn-dns-') || ['systemd-resolved.service', 'systemd-networkd.service'].includes(name);
const managerPath = '/org/freedesktop/systemd1', managerInterface = 'org.freedesktop.systemd1.Manager';
const busArgs = ['--address=unix:path=/run/dbus/system_bus_socket', '--timeout=5s',
  '--auto-start=no', '--allow-interactive-authorization=no', '--json=short'];
const objectPath = (s) => assert.match(s, /^\/(?:[a-zA-Z0-9_]+(?:\/[a-zA-Z0-9_]+)*)?$/);
function typed(text, signature) {
  assert.equal(typeof text, 'string'); assert.ok(Buffer.byteLength(text) <= 262144);
  const v = JSON.parse(text); assert.ok(v && typeof v === 'object');
  assert.deepEqual(Object.keys(v).sort(), ['data', 'type']); assert.equal(v.type, signature); return v.data;
}
export function parseDnsDeploymentUnits(text, { allowExitedGuard = false } = {}) {
  assert.equal(typeof allowExitedGuard, 'boolean');
  const tuple = typed(text, 'a(ssssssouso)'); assert.ok(Array.isArray(tuple) && tuple.length === 1);
  const rows = tuple[0]; assert.ok(Array.isArray(rows) && rows.length <= 16); const names = new Set();
  for (const row of rows) {
    assert.ok(Array.isArray(row) && row.length === 10);
    for (const i of [0, 1, 2, 3, 4, 5, 6, 8, 9]) assert.equal(typeof row[i], 'string');
    assert.ok(units.has(row[0]) && !names.has(row[0]), 'unknown or duplicate DNS service'); names.add(row[0]);
    assert.ok(['loaded', 'not-found'].includes(row[2]));
    const exitedGuard = allowExitedGuard && row[0] === 'clean-vpn-dns-guard.service' && row[2] === 'loaded' && row[3] === 'active' && row[4] === 'exited';
    if (!exitedGuard) { assert.equal(row[3], 'inactive', 'DNS service is not inactive'); assert.equal(row[4], 'dead'); }
    assert.equal(row[5], '', 'aliased DNS service'); assert.equal(row[7], 0, 'pending DNS job'); assert.equal(row[8], '');
    assert.match(row[6], /^\/org\/freedesktop\/systemd1\/unit\/[a-zA-Z0-9_]+$/); objectPath(row[9]);
  }
  return rows.map((v) => ({ name: v[0], path: v[6], ...(v[3] === 'active' ? { exitedGuard: true } : {}) }));
}
export function assertQuiescentDnsGuardProperties(text) {
  // systemctl's custom Exec* formatter omits empty arrays even with --all.
  // Read the five ordered, typed D-Bus properties instead. Unlike a missing
  // printed field, an explicit empty array proves there are no loaded hooks.
  try {
    assert.equal(typeof text, 'string'); assert.ok(Buffer.byteLength(text) <= 8192);
    const lines = text.trim().split('\n'); assert.equal(lines.length, 5);
    const expected = [['s', 'oneshot'], ['b', true], ['s', 'no'],
      ['a(sasbttttuii)', []], ['a(sasbttttuii)', []]];
    for (let i = 0; i < expected.length; i++) {
      const value = typed(lines[i], expected[i][0]);
      assert.ok(i < 3 ? value === expected[i][1] : Array.isArray(value) && value.length === 0);
    }
  } catch {
    // Hook argv and malformed JSON can contain secrets. Do not expose the
    // parser error, actual/expected payload or an Error cause.
    throw new Error('DNS_DEPLOYMENT_EXITED_GUARD_PROPERTIES_REFUSED');
  }
}
export function assertNoDnsDeploymentJobs(text) {
  const tuple = typed(text, 'a(usssoo)'); assert.ok(Array.isArray(tuple) && tuple.length === 1);
  assert.ok(Array.isArray(tuple[0]) && tuple[0].length <= 4096);
  for (const row of tuple[0]) {
    assert.ok(Array.isArray(row) && row.length === 6 && Number.isInteger(row[0]) && row[0] > 0);
    for (const value of row.slice(1)) assert.equal(typeof value, 'string');
    objectPath(row[4]); objectPath(row[5]); assert.equal(related(row[1]), false, 'DNS/manager job in flight');
  }
}
export function assertNoDnsDeploymentProcesses(pids, processes) {
  const lines = pids.trim().split('\n'); assert.equal(lines.length, 2);
  for (const line of lines) assert.equal(typed(line, 'u'), 0, 'DNS service still has a PID');
  const tuple = typed(processes, 'a(sus)'); assert.ok(Array.isArray(tuple) && tuple.length === 1);
  assert.ok(Array.isArray(tuple[0]));
  // GetUnitProcesses includes command strings. Do not attach them to an
  // AssertionError's actual/expected payload or its rendered stack.
  assert.equal(tuple[0].length, 0, 'DNS service cgroup is not empty');
}
export function assertNoDnsDeploymentLinks(text) {
  assert.equal(typeof text, 'string'); assert.ok(Buffer.byteLength(text) <= 262144);
  const links = JSON.parse(text); assert.ok(Array.isArray(links) && links.length <= 64);
  const names = new Set(), indexes = new Set();
  for (const link of links) {
    assert.equal(typeof link.ifname, 'string'); assert.ok(!link.ifname.startsWith('cvdns'), 'DNS link remains');
    assert.ok(Number.isInteger(link.ifindex) && link.ifindex > 0 && !indexes.has(link.ifindex));
    assert.ok(!names.has(link.ifname)); names.add(link.ifname); indexes.add(link.ifindex);
    assert.ok(Array.isArray(link.addr_info) && link.addr_info.length <= 64);
    for (const address of link.addr_info) {
      assert.equal(typeof address.local, 'string'); assert.notEqual(address.local, '192.0.2.1', 'reserved DNS address remains');
    }
  }
}
export function assertNoManualDnsDeploymentProcess(bytes) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length <= 65536);
  for (const name of ['dns-client.mjs', 'dns-exit-adapter.mjs', 'dns-boot-guard.mjs']) {
    const path = Buffer.from(`/opt/clean-vpn/scripts/${name}`);
    for (let at = bytes.indexOf(path); at !== -1; at = bytes.indexOf(path, at + 1))
      assert.ok(!((at === 0 || bytes[at - 1] === 0) && (at + path.length === bytes.length || bytes[at + path.length] === 0)), 'installed DNS process still exists');
  }
}
async function noManualProcesses() {
  const pids = (await readdir('/proc')).filter((name) => /^[1-9][0-9]*$/.test(name));
  assert.ok(pids.length <= 4096, 'process inventory limit');
  for (const pid of pids) {
    let fd, bytes;
    try {
      fd = await open(`/proc/${pid}/cmdline`, 'r'); bytes = Buffer.alloc(65537);
      let used = 0;
      while (used < bytes.length) { const r = await fd.read(bytes, used, bytes.length - used, null); if (!r.bytesRead) break; used += r.bytesRead; }
      assertNoManualDnsDeploymentProcess(bytes.subarray(0, used));
    } catch (e) { if (!['ENOENT', 'ESRCH'].includes(e.code)) throw e; }
    finally { bytes?.fill(0); await fd?.close(); }
  }
}
async function noRuntimeHistory() {
  for (const path of ['/var', '/var/lib', '/var/lib/clean-vpn']) {
    let s; try { s = await lstat(path); } catch (e) { if (e.code === 'ENOENT' && path === '/var/lib/clean-vpn') break; throw e; }
    assert.ok(s.isDirectory() && s.uid === 0 && !(s.mode & 0o022), 'untrusted DNS state parent');
  }
  for (const path of ['/var/lib/clean-vpn/dns-v1', '/run/clean-vpn-dns-guard/namespace.json']) {
    let missing = false; try { await lstat(path); } catch (e) { if (e.code !== 'ENOENT') throw e; missing = true; }
    assert.equal(missing, true, 'DNS runtime history requires explicit recovery/uninstall');
  }
}

/** Genuine pinned commands only. The installer must additionally prove its
 * own reviewed code/profile and validate prospective DNS ownership before
 * activation. This check can be repeated even while opt-in files are absent. */
export const inspectFreshDnsDeployment = (options) => inspectDnsDeployment(options, 'fresh');
/** Separate post-disable observation. Retains all journals and requires their
 * current boot/bus/manager binding. NOT an uninstall or reactivation command. */
export const inspectReleasedDnsDeployment = (options) => inspectDnsDeployment(options, 'released');
/** Transitional observation only: no running DNS worker, but the guard oneshot
 * may remain active/exited until its owned manager dependencies are detached. */
export const inspectQuiescentDnsDeployment = (options) => inspectDnsDeployment(options, 'quiescent');
async function inspectDnsDeployment({ commands, input, firewallBackend }, mode) {
  const released = mode !== 'fresh', quiescent = mode === 'quiescent';
  assertDnsSystemCommands(commands); input = structuredClone(input); const plan = compileDnsClientGuard(input);
  assert.equal(input.client, 'vps2', 'installed Radxa lifecycle is not covered by this check');
  assert.ok(['legacy', 'nf_tables'].includes(firewallBackend));
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  const run = async (tool, args, step) => {
    try { return await commands.run(tool, args); }
    catch (error) { throw new Error(`DNS_DEPLOYMENT_READ_FAILED:${step}`, { cause: error }); }
  };
  const context = async () => {
    assert.equal((await readFile('/proc/1/comm', 'utf8')).trim(), 'systemd');
    for (const name of ['mnt', 'net', 'pid']) assert.equal(await readlink(`/proc/self/ns/${name}`), await readlink(`/proc/1/ns/${name}`));
    await requireDnsBootGuardLock();
    // Runtime journals cannot be interpreted as fresh or silently retired.
    // Released journals need the separate, explicit uninstall protocol too.
    if (!released) await noRuntimeHistory();
  };
  const call = async (args, signature) => {
    const { stdout } = await run('busctl', [...busArgs, ...args], args[4]); return typed(stdout, signature);
  };
  const tuple = (v) => { assert.ok(Array.isArray(v) && v.length === 1); return v[0]; };
  const busContext = async () => {
    const address = ['call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus'];
    const id = tuple(await call([...address, 'GetId'], 's')); assert.match(id, /^[a-f0-9]{32}$/);
    const owner = tuple(await call([...address, 'GetNameOwner', 's', 'org.freedesktop.systemd1'], 's')); assert.match(owner, /^:\d+\.\d+$/);
    assert.equal(tuple(await call([...address, 'GetConnectionUnixProcessID', 's', owner], 'u')), 1);
    assert.equal(tuple(await call([...address, 'GetConnectionUnixUser', 's', owner], 'u')), 0);
    return { id, owner };
  };
  await context(); const bus = await busContext();
  const releasedSnapshot = async () => {
    const scope = {};
    for (const name of ['mnt', 'net', 'pid']) scope[name] = await readlink(`/proc/self/ns/${name}`);
    const bootId = (await readFile('/proc/sys/kernel/random/boot_id', 'utf8')).trim();
    const resolveBus = createDnsSystemBus((tool, args) => run(tool, args, 'released-resolved'));
    const owner = await resolveBus.owner(), pid = await resolveBus.ownerPid(owner), uid = await resolveBus.ownerUid(owner);
    const fields = ['Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'NeedDaemonReload'];
    const unit = (quiescent ? validateReleasedDnsManagerUnit : validateVps2DnsUnit)((await run('systemctl', ['show', 'systemd-resolved.service',
      ...fields.map((f) => `--property=${f}`)], 'released-resolved-unit')).stdout, 'systemd-resolved', pid);
    const executable = await inspectDnsSystemExecutable(await readlink(`/proc/${pid}/exe`));
    assert.ok(['/usr/lib/systemd/systemd-resolved', '/lib/systemd/systemd-resolved'].includes(executable.actual));
    assert.equal(await readlink(`/proc/${pid}/ns/net`), scope.net);
    let anchor = null;
    // Missing anchor is legal for a root CLI guard that did not need the
    // capability-limited unit's attestation. A present stale anchor is not.
    try { anchor = await readDnsBootNamespaceAnchor(); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (anchor) assert.deepEqual(anchor, { schema: 1, bootId, netns: scope.net });
    const history = await readReleasedDnsHistory({ directory: '/var/lib/clean-vpn/dns-v1', input,
      context: { scope, bootId, busId: bus.id, owner }, firewallBackend });
    return { history, anchor, manager: { owner, pid, uid, unit, executable } };
  };
  const history = released ? await releasedSnapshot() : null;
  const rawCall = async (method, ...args) => (await run('busctl', [...busArgs,
    'call', bus.owner, managerPath, managerInterface, method, ...args], method)).stdout;
  const services = async () => {
    assertNoDnsDeploymentJobs(await rawCall('ListJobs'));
    const rows = parseDnsDeploymentUnits(await rawCall('ListUnitsByPatterns', 'asas', '0', '1', 'clean-vpn-dns-*'), { allowExitedGuard: quiescent });
    for (const { name, path, exitedGuard } of rows) {
      const { stdout } = await run('busctl', [...busArgs, 'get-property', bus.owner, path,
        'org.freedesktop.systemd1.Service', 'MainPID', 'ControlPID'], 'service-pids');
      assertNoDnsDeploymentProcesses(stdout, await rawCall('GetUnitProcesses', 's', name));
      if (exitedGuard) assertQuiescentDnsGuardProperties((await run('busctl', [...busArgs, 'get-property', bus.owner, path,
        'org.freedesktop.systemd1.Service', 'Type', 'RemainAfterExit', 'Restart', 'ExecStop', 'ExecStopPost'], 'exited-guard-properties')).stdout);
    }
    assertNoDnsDeploymentJobs(await rawCall('ListJobs')); return rows;
  };
  const before = await services();
  await noManualProcesses();
  assertNoDnsDeploymentLinks((await run('ip', ['-j', 'address', 'show'], 'addresses')).stdout);
  for (const [family, tool] of [[4, 'iptables'], [6, 'ip6tables']]) {
    const { stdout } = await run(tool, ['--version'], `${tool}-version`);
    assert.match(stdout, new RegExp(`^${tool} v[0-9.]+ \\(${firewallBackend}\\)\\n?$`), 'firewall backend differs');
    assert.equal(inspectDnsClientGuard(plan, family, (await run(tool, ['-w', '5', '-S'], `${tool}-rules`)).stdout), 'absent', 'DNS guard remains');
  }
  assert.deepEqual(await services(), before, 'DNS service set changed');
  if (released) assert.deepEqual(await releasedSnapshot(), history, 'released DNS evidence changed');
  assert.deepEqual(await busContext(), bus, 'system manager changed'); await context();
  if (released) return { schema: 1, kind: quiescent ? 'clean-vpn-dns-quiescent-deployment-check' : 'clean-vpn-dns-released-deployment-check',
    releasedInactive: !quiescent, ...(quiescent ? { releasedQuiescent: true, guardUnitActiveExited: before.some((v) => v.exitedGuard === true),
      managerNeedsReload: history.manager.unit.NeedDaemonReload === 'yes' } : {}),
    historySha256: createHash('sha256').update(JSON.stringify(history.history)).digest('hex'),
    systemSettingsChanged: false, dnsQueriesSent: 0, activationAuthorized: false, uninstallAuthorized: false,
    limitations: ['not-a-baseline-health-proof', 'not-a-file-ownership-or-uninstall-authority',
      'same-boot-and-resolved-owner-only', 'runtime-history-retained',
      'point-in-time-under-cooperative-lock', 'no-renamed-or-arbitrary-script-process-detection'] };
  return { schema: 1, kind: 'clean-vpn-dns-fresh-deployment-check', freshInactive: true,
    systemSettingsChanged: false, dnsQueriesSent: 0, activationAuthorized: false,
    limitations: ['not-a-DNS-ownership-or-readiness-proof', 'not-a-restore-proof',
      'no-post-activation-uninstall', 'point-in-time-under-cooperative-lock', 'no-renamed-or-arbitrary-script-process-detection'] };
}

/** Scoped transient exit network owner. Never flushes or replaces host tables. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { isIPv4 } from 'node:net';

const C = fs.constants, LIMIT = 16384;
const currentScope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
  net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
export const nativeExitTrialStateDirectory = () => `/run/clean-vpn-native-exit-trial-${currentScope().net.match(/\d+/)[0]}`;
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
function trustedOwner(uid) {
  if (uid === 0 || uid === process.getuid()) return true;
  const overflow = Number(fs.readFileSync('/proc/sys/kernel/overflowuid', 'utf8'));
  if (uid !== overflow) return false;
  return !fs.readFileSync('/proc/self/uid_map', 'utf8').trim().split('\n').some(line => {
    const [start, , size] = line.trim().split(/\s+/).map(Number); return uid >= start && uid < start + size;
  });
}
function privateFile(fd) {
  const stat = fs.fstatSync(fd);
  assert.ok(stat.isFile() && stat.nlink === 1 && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600,
    'unsafe exit trial journal');
}
function validateConfig(c) {
  exactKeys(c, ['endpoint', 'uplink', 'port']);
  assert.ok(isIPv4(c.endpoint) && !/^(?:0|127|169\.254)\./.test(c.endpoint));
  assert.match(c.uplink, /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/); assert.notEqual(c.uplink, 'lo');
  assert.ok(Number.isInteger(c.port) && c.port >= 1 && c.port <= 65535); return c;
}
function plan(value) {
  const tag = `clean-vpn-native-exit-${value.id}`, tun = `cvne${value.id.slice(0, 10)}`;
  const rule = (table, chain, spec) => ({ kind: 'iptables', table,
    add: ['-w', '5', '-t', table, '-I', chain, '1', ...spec], remove: ['-w', '5', '-t', table, '-D', chain, ...spec] });
  const ops = [
    { kind: 'tun', add: ['tuntap', 'add', 'dev', tun, 'mode', 'tun'], remove: ['tuntap', 'del', 'dev', tun, 'mode', 'tun'] },
    { kind: 'address', add: ['address', 'add', '10.99.0.1/24', 'dev', tun], remove: ['address', 'del', '10.99.0.1/24', 'dev', tun] },
    { kind: 'link', add: ['link', 'set', 'dev', tun, 'mtu', '1400', 'up'], remove: ['link', 'set', 'dev', tun, 'down'] },
    ...(value.forwarding_before === '0' ? [{ kind: 'forwarding', add: ['-w', 'net.ipv4.ip_forward=1'], remove: ['-w', 'net.ipv4.ip_forward=0'] }] : []),
    rule('filter', 'FORWARD', ['-i', tun, '-s', '10.99.0.0/24', '-o', value.config.uplink,
      '-m', 'comment', '--comment', tag, '-j', 'ACCEPT']),
    rule('filter', 'FORWARD', ['-i', value.config.uplink, '-o', tun, '-d', '10.99.0.0/24',
      '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-m', 'comment', '--comment', tag, '-j', 'ACCEPT']),
    rule('nat', 'POSTROUTING', ['-s', '10.99.0.0/24', '-o', value.config.uplink,
      '-m', 'comment', '--comment', tag, '-j', 'MASQUERADE']),
  ];
  return { tun, tag, operations: ops };
}
function validate(value) {
  exactKeys(value, ['schema', 'id', 'scope', 'config', 'forwarding_before', 'firewall', 'count', 'stage']);
  assert.equal(value.schema, 1); assert.match(value.id, /^[a-f0-9]{24}$/); validateConfig(value.config);
  exactKeys(value.scope, ['boot', 'net', 'user']); assert.match(value.scope.boot, /^[a-f0-9-]{36}$/);
  for (const key of ['net', 'user']) assert.match(value.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  assert.ok(['0', '1'].includes(value.forwarding_before)); assert.ok(['nf_tables', 'legacy'].includes(value.firewall));
  assert.ok(['prepared', 'installing', 'active', 'restoring', 'released'].includes(value.stage));
  assert.ok(Number.isInteger(value.count) && value.count >= 0 && value.count <= plan(value).operations.length);
  if (value.stage === 'active') assert.equal(value.count, plan(value).operations.length);
  if (value.stage === 'prepared' || value.stage === 'released') assert.equal(value.count, 0);
  return value;
}
function canonical(tokens) {
  const normalized = tokens.join(' ').replace(/"/g, '').replace(/ -m (tcp|udp)(?= |$)/g, '')
    .replace(/--ctstate ([A-Z,]+)/g, (_, states) => `--ctstate ${states.split(',').sort().join(',')}`);
  const words = normalized.split(/\s+/), pairs = [];
  for (let i = 0; i < words.length; i += 2) pairs.push(`${words[i]} ${words[i + 1] ?? ''}`);
  return pairs.sort().join(' ');
}
const expectedRule = op => canonical(['-A', op.remove[op.remove.indexOf('-D') + 1], ...op.remove.slice(op.remove.indexOf('-D') + 2)]);

export function openNativeExitTrialNetwork(directory = nativeExitTrialStateDirectory(), {
  run: injectedRun, stateScope = currentScope, checkpoint = () => {}, trustedAncestor = trustedOwner,
} = {}) {
  assert.ok(isAbsolute(directory) && resolve(directory) === directory, 'absolute normalized state directory required');
  for (let parent = dirname(directory); ; parent = dirname(parent)) {
    const stat = fs.lstatSync(parent);
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && trustedAncestor(stat.uid), 'unsafe state ancestor');
    assert.ok(!(stat.mode & 0o022) || (stat.mode & 0o1000), 'writable non-sticky state ancestor');
    if (parent === '/') break;
  }
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const dirfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW), base = `/proc/self/fd/${dirfd}`;
  let lockfd, value = null, closed = false;
  const release = () => { if (closed) return; closed = true; if (lockfd !== undefined) fs.closeSync(lockfd); fs.closeSync(dirfd); };
  const run = injectedRun ?? ((file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 10000,
    killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe', lockfd] }).trim());
  try {
    const stat = fs.fstatSync(dirfd); assert.ok(stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700);
    lockfd = fs.openSync(join(base, 'lock'), C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lockfd);
    execFileSync('flock', ['--exclusive', '--nonblock', '3'], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe', lockfd] });
    fs.fsyncSync(dirfd);
    let fd; try { fd = fs.openSync(join(base, 'journal.json'), C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (fd !== undefined) try {
      privateFile(fd); const stat = fs.fstatSync(fd); assert.ok(stat.size > 0 && stat.size <= LIMIT);
      const bytes = Buffer.alloc(LIMIT + 1), count = fs.readSync(fd, bytes, 0, bytes.length, 0); assert.equal(count, stat.size);
      value = validate(JSON.parse(bytes.subarray(0, count).toString('utf8')));
    } finally { fs.closeSync(fd); }
  } catch (error) { release(); throw error; }
  const save = () => {
    validate(value); const body = JSON.stringify(value), temp = join(base, `journal-${randomBytes(12).toString('hex')}.tmp`);
    assert.ok(Buffer.byteLength(body) <= LIMIT); const fd = fs.openSync(temp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    checkpoint('file-synced', structuredClone(value)); fs.renameSync(temp, join(base, 'journal.json'));
    checkpoint('renamed', structuredClone(value)); fs.fsyncSync(dirfd); checkpoint('dir-synced', structuredClone(value));
  };
  const scopeCheck = () => assert.deepEqual(value.scope, stateScope(), 'journal belongs to another boot/namespace');
  const links = () => JSON.parse(run('ip', ['-j', '-d', 'link', 'show']));
  const link = () => links().find(item => item.ifname === plan(value).tun);
  const relevant = table => run('iptables', ['-w', '5', '-t', table, '-S']).split('\n').filter(line => line.includes('clean-vpn-native-exit-')).map(line => canonical([line]));
  const isPresent = op => {
    if (op.kind === 'tun') return !!link();
    if (op.kind === 'address') return !!link() && JSON.parse(run('ip', ['-j', 'address', 'show', 'dev', plan(value).tun]))
      .some(item => item.addr_info?.some(a => a.family === 'inet' && a.local === '10.99.0.1' && a.prefixlen === 24));
    if (op.kind === 'link') { const item = link(); return !!item && item.mtu === 1400 && item.flags?.includes('UP'); }
    if (op.kind === 'forwarding') return run('sysctl', ['-n', 'net.ipv4.ip_forward']) === '1';
    return relevant(op.table).filter(line => line === expectedRule(op)).length === 1;
  };
  const audit = ({ requireAll = value.stage === 'active' } = {}) => {
    scopeCheck(); const p = plan(value), intended = p.operations.slice(0, value.count);
    assert.equal(run('iptables', ['--version']).match(/\((nf_tables|legacy)\)/)?.[1], value.firewall, 'firewall backend changed');
    const item = link();
    if (item) assert.equal(item.linkinfo?.info_kind, 'tun', 'trial interface type changed');
    for (const table of ['filter', 'nat']) {
      const allowed = intended.filter(op => op.kind === 'iptables' && op.table === table).map(expectedRule), actual = relevant(table);
      assert.ok(actual.every(line => allowed.includes(line)), `foreign exit trial state: ${table}`);
      assert.equal(new Set(actual).size, actual.length, `duplicate exit trial state: ${table}`);
    }
    if (requireAll) intended.forEach(op => assert.ok(isPresent(op), `missing exit trial operation: ${op.kind}`));
    return { stage: value.stage, operations: value.count, tun: p.tun };
  };
  return {
    release,
    get state() { return value ? structuredClone(value) : null; },
    assertAvailable() {
      assert.ok(!value || value.stage === 'released', 'unfinished exit trial journal; explicit recovery required');
      for (const table of ['filter', 'nat']) assert.equal(relevant(table).length, 0, 'unowned exit trial firewall state');
    },
    prepare(config) {
      this.assertAvailable(); validateConfig(config);
      const forwarding = run('sysctl', ['-n', 'net.ipv4.ip_forward']); assert.ok(['0', '1'].includes(forwarding));
      const firewall = run('iptables', ['--version']).match(/\((nf_tables|legacy)\)/)?.[1]; assert.ok(firewall, 'unknown firewall backend');
      value = { schema: 1, id: randomBytes(12).toString('hex'), scope: stateScope(), config: structuredClone(config),
        forwarding_before: forwarding, firewall, count: 0, stage: 'prepared' }; save();
      assert.ok(!link(), 'random trial TUN collision'); return { tun: plan(value).tun };
    },
    install() {
      assert.equal(value?.stage, 'prepared'); scopeCheck(); value.stage = 'installing'; save();
      const p = plan(value);
      for (const op of p.operations) {
        value.count++; save();
        run(op.kind === 'iptables' ? 'iptables' : op.kind === 'forwarding' ? 'sysctl' : 'ip', op.add);
        assert.ok(isPresent(op), `exit trial operation read-back failed: ${op.kind}${op.kind === 'iptables'
          ? ` expected=${expectedRule(op)} actual=${relevant(op.table).join('|')}` : ''}`); checkpoint('applied', structuredClone(value));
      }
      value.stage = 'active'; save(); audit(); return { tun: p.tun, operations: value.count };
    },
    audit,
    restore({ apply = true } = {}) {
      assert.ok(value); scopeCheck(); audit({ requireAll: false });
      if (!apply) return { mode: 'dry-run', stage: value.stage, operations: value.count, tun: plan(value).tun };
      value.stage = 'restoring'; save(); const p = plan(value), total = value.count;
      while (value.count > 0) {
        const op = p.operations[value.count - 1];
        if (isPresent(op)) run(op.kind === 'iptables' ? 'iptables' : op.kind === 'forwarding' ? 'sysctl' : 'ip', op.remove);
        assert.equal(isPresent(op), false, `exit trial undo read-back failed: ${op.kind}`);
        value.count--; save(); checkpoint('removed', structuredClone(value));
      }
      value.stage = 'released'; save(); return { mode: 'restored', operations: total, tun: p.tun };
    },
  };
}

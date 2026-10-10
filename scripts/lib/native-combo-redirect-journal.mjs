/** Same-boot durable owner for the direct-trial HTTPS interception overlay. */
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { nativeComboRedirectPlan, validateNativeComboRedirectConfig } from './native-combo-redirect-plan.mjs';

const C = fs.constants, LIMIT = 16384;
const scope = () => ({ boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
  net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') });
export const nativeComboRedirectStateDirectory = () => `/run/clean-vpn-native-combo-redirect-${scope().net.match(/\d+/)[0]}`;
const keys = (value, expected) => assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), 'unexpected redirect journal fields');
const linkIdentity = (run, name) => {
  const links = JSON.parse(run('ip', ['-j', 'link', 'show'])), link = links.find(item => item.ifname === name);
  return link ? { ifindex: link.ifindex, address: link.address ?? '', type: link.link_type } : null;
};
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
    'unsafe redirect journal file'); return stat;
}
export function validateNativeComboRedirectJournal(value) {
  keys(value, ['schema', 'id', 'scope', 'config', 'link', 'firewall', 'count', 'stage']);
  assert.equal(value.schema, 1); assert.match(value.id, /^[a-f0-9]{24}$/);
  keys(value.scope, ['boot', 'net', 'user']); assert.match(value.scope.boot, /^[a-f0-9-]{36}$/);
  for (const key of ['net', 'user']) assert.match(value.scope[key], new RegExp(`^${key}:\\[\\d+\\]$`));
  validateNativeComboRedirectConfig(value.config);
  keys(value.link, ['ifindex', 'address', 'type']); assert.ok(Number.isSafeInteger(value.link.ifindex) && value.link.ifindex > 0);
  assert.ok(typeof value.link.address === 'string' && typeof value.link.type === 'string');
  assert.ok(['nf_tables', 'legacy'].includes(value.firewall));
  const total = nativeComboRedirectPlan(value.config, value.id).operations.length;
  assert.ok(Number.isInteger(value.count) && value.count >= 0 && value.count <= total);
  assert.ok(['installing', 'active', 'restoring', 'released'].includes(value.stage));
  if (value.stage === 'active') assert.equal(value.count, total);
  if (value.stage === 'released') assert.equal(value.count, 0);
  return value;
}
function canonical(tokens) {
  const words = tokens.join(' ').replace(/"/g, '').replace(/ -m (tcp|udp)(?= |$)/g, '')
    .replace(/\b(\d+\.\d+\.\d+\.\d+)\/32\b/g, '$1').split(/\s+/);
  const pairs = [];
  for (let index = 0; index < words.length; index += 2) {
    if (words[index] === '!') { pairs.push(`! ${words[index + 1]} ${words[index + 2]}`); index++; }
    else pairs.push(`${words[index]} ${words[index + 1] ?? ''}`);
  }
  return pairs.sort().join(' ');
}
function expected(op) {
  const at = op.remove.findIndex(value => value === '-D' || value === '-X');
  return canonical([op.remove[at] === '-D' ? '-A' : '-N', ...op.remove.slice(at + 1)]);
}
function tableOf(op) { return op.args[op.args.indexOf('-t') + 1]; }
function relevantLines(run, table) {
  return run('iptables', ['-w', '5', '-t', table, '-S']).split('\n').filter(Boolean)
    .map(line => canonical([line])).filter(line => /CVPN-CT-|clean-vpn-native-combo-/.test(line));
}
function present(op, run) {
  const matches = relevantLines(run, tableOf(op)).filter(line => line === expected(op));
  assert.ok(matches.length <= 1, 'duplicate owned redirect state'); return matches.length === 1;
}
function audit(value, run) {
  const version = run('iptables', ['--version']).match(/\((nf_tables|legacy)\)/)?.[1];
  assert.equal(version, value.firewall, 'firewall backend changed');
  const plan = nativeComboRedirectPlan(value.config, value.id).operations.slice(0, value.count);
  for (const table of ['filter', 'nat']) {
    const allowed = plan.filter(op => tableOf(op) === table).map(expected), actual = relevantLines(run, table);
    assert.ok(actual.every(line => allowed.includes(line)), `foreign redirect state: ${table}`);
    assert.equal(new Set(actual).size, actual.length, `duplicate redirect state: ${table}`);
  }
  const link = linkIdentity(run, value.config.interface); assert.ok(link, `interface disappeared: ${value.config.interface}`);
  assert.deepEqual(link, value.link, `interface replaced: ${value.config.interface}`);
}

export function openNativeComboRedirectJournal(directory = nativeComboRedirectStateDirectory(), {
  run: customRun, checkpoint = () => {}, stateScope = scope, trustedAncestor = trustedOwner,
} = {}) {
  assert.ok(isAbsolute(directory) && resolve(directory) === directory, 'absolute normalized redirect state directory required');
  for (let parent = dirname(directory); ; parent = dirname(parent)) {
    const stat = fs.lstatSync(parent);
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && trustedAncestor(stat.uid), `unsafe redirect state ancestor: ${parent}:${stat.uid}`);
    assert.ok(!(stat.mode & 0o022) || (stat.mode & 0o1000), 'writable non-sticky redirect state ancestor');
    if (parent === '/') break;
  }
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const dirfd = fs.openSync(directory, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW), base = `/proc/self/fd/${dirfd}`;
  let lockfd, value = null, closed = false;
  const release = () => { if (closed) return; closed = true; if (lockfd !== undefined) fs.closeSync(lockfd); fs.closeSync(dirfd); };
  const run = customRun ?? ((file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 10000,
    killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe', lockfd] }).trim());
  try {
    const stat = fs.fstatSync(dirfd); assert.ok(stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700);
    lockfd = fs.openSync(join(base, 'lock'), C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lockfd);
    execFileSync('flock', ['--exclusive', '--nonblock', '3'], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe', lockfd] });
    fs.fsyncSync(dirfd);
    let fd; try { fd = fs.openSync(join(base, 'journal.json'), C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (fd !== undefined) try {
      const stat = privateFile(fd); assert.ok(stat.size > 0 && stat.size <= LIMIT);
      const bytes = Buffer.alloc(LIMIT + 1), count = fs.readSync(fd, bytes, 0, bytes.length, 0); assert.equal(count, stat.size);
      value = validateNativeComboRedirectJournal(JSON.parse(bytes.subarray(0, count).toString('utf8')));
    } finally { fs.closeSync(fd); }
  } catch (error) { release(); throw error; }
  const save = () => {
    validateNativeComboRedirectJournal(value); const body = JSON.stringify(value); assert.ok(Buffer.byteLength(body) <= LIMIT);
    const temporary = join(base, `journal-${randomBytes(12).toString('hex')}.tmp`);
    const fd = fs.openSync(temporary, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, body); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    checkpoint('file-synced', structuredClone(value)); fs.renameSync(temporary, join(base, 'journal.json'));
    checkpoint('renamed', structuredClone(value)); fs.fsyncSync(dirfd); checkpoint('dir-synced', structuredClone(value));
  };
  const assertScope = () => assert.deepEqual(value.scope, stateScope(), 'redirect journal belongs to another boot/namespace');
  const restore = ({ apply = true } = {}) => {
    assert.ok(value, 'no redirect journal'); assertScope(); audit(value, run);
    if (!apply) return { mode: 'dry-run', stage: value.stage, operations: value.count };
    const plan = nativeComboRedirectPlan(value.config, value.id).operations, count = value.count;
    value.stage = 'restoring'; save();
    while (value.count > 0) {
      const op = plan[value.count - 1];
      if (present(op, run)) run(op.file, op.remove);
      assert.equal(present(op, run), false, 'redirect undo read-back failed');
      value.count--; save(); checkpoint('removed', structuredClone(value));
    }
    value.stage = 'released'; save(); return { mode: 'restored', operations: count };
  };
  return {
    release,
    get state() { return value ? structuredClone(value) : null; },
    assertAvailable() {
      assert.ok(!value || value.stage === 'released', 'unfinished combo redirect journal; explicit recovery required');
      for (const table of ['filter', 'nat']) assert.equal(relevantLines(run, table).length, 0, 'unowned combo redirect state');
    },
    install(config) {
      this.assertAvailable(); validateNativeComboRedirectConfig(config);
      const link = linkIdentity(run, config.interface); assert.ok(link, `missing interface ${config.interface}`);
      const version = run('iptables', ['--version']).match(/\((nf_tables|legacy)\)/)?.[1]; assert.ok(version, 'unknown firewall backend');
      value = { schema: 1, id: randomBytes(12).toString('hex'), scope: stateScope(), config: structuredClone(config),
        link, firewall: version, count: 0, stage: 'installing' }; save();
      const plan = nativeComboRedirectPlan(value.config, value.id).operations;
      for (const op of plan) {
        value.count++; save(); // durable intent precedes every mutation
        run(op.file, op.args); assert.ok(present(op, run), 'redirect mutation read-back failed');
        checkpoint('applied', structuredClone(value));
      }
      value.stage = 'active'; save(); audit(value, run);
      return { tag: nativeComboRedirectPlan(value.config, value.id).tag, operations: value.count };
    },
    audit() { assert.ok(value); assertScope(); audit(value, run); return { stage: value.stage, operations: value.count }; },
    restore,
  };
}

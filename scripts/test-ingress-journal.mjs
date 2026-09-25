import assert from 'node:assert/strict';
import test from 'node:test';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { openIngressJournal as openJournal } from './lib/ingress-journal.mjs';
import { recoverIngress } from './clean-vpn-recover.mjs';
const openIngressJournal = (directory, options = {}) => openJournal(directory, { ...options, coordinate: false });

function fixture(t) {
  const directory = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), 'meshpn-ingress-journal-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const run = (file, args) => {
    if (file === 'ip' && args.includes('link')) return JSON.stringify([
      { ifname: 'wg0', ifindex: 10, address: '', link_type: 'none' }, { ifname: 'tun0', ifindex: 11, address: '', link_type: 'none' },
    ]);
    if (file === 'sysctl' && args[0] === '-n') return '1';
    throw new Error('network mutation forbidden in storage unit tests');
  };
  const config = { ingress: { name: 'wg0', bypass: ['10.0.0.0/8'] }, tun: 'tun0', address: '10.99.0.2' };
  const journal = openIngressJournal(directory, { run }); journal.begin(config); journal.release();
  return { directory, path: join(directory, 'journal.json') };
}

test('journal records original values and identity, never serialized executable commands', (t) => {
  const { directory, path } = fixture(t); const v = JSON.parse(fs.readFileSync(path));
  assert.equal(v.count, 0); assert.equal(v.original.wg0, '1'); assert.equal(v.links.tun0.ifindex, 11);
  assert.equal(fs.statSync(path).mode & 0o777, 0o600);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.ok(!JSON.stringify(v).includes('iptables'));
  const journal = openIngressJournal(directory);
  try { assert.throws(() => journal.assertAvailable(), /unfinished journal/); } finally { journal.release(); }
});

for (const [name, modify] of [
  ['unknown field', (v) => { v.command = ['iptables', '-F']; }],
  ['bad schema', (v) => { v.schema = 999; }],
  ['bad interface', (v) => { v.config.tun = '../../all'; }],
  ['bad bypass', (v) => { v.config.ingress.bypass = ['--help']; }],
  ['bad sysctl', (v) => { v.original.wg0 = '3'; }],
  ['unbounded cursor', (v) => { v.count = 99999; }],
  ['bad port', (v) => { v.port = 65536; }],
  ['wrong stage', (v) => { v.stage = 'execute'; }],
]) test(`journal rejects ${name} before network access`, (t) => {
  const { directory, path } = fixture(t); const v = JSON.parse(fs.readFileSync(path)); modify(v);
  fs.writeFileSync(path, JSON.stringify(v)); assert.throws(() => openIngressJournal(directory));
});

test('symlink/hardlink/oversized journal and insecure directory are rejected', (t) => {
  const { directory, path } = fixture(t); const backup = join(directory, 'saved'); fs.renameSync(path, backup);
  fs.symlinkSync(backup, path); assert.throws(() => openIngressJournal(directory)); fs.unlinkSync(path);
  fs.linkSync(backup, path); assert.throws(() => openIngressJournal(directory)); fs.unlinkSync(path);
  fs.writeFileSync(path, ' '.repeat(65537), { mode: 0o600 }); assert.throws(() => openIngressJournal(directory), /size limit/);
  fs.chmodSync(directory, 0o755); assert.throws(() => openIngressJournal(directory), /0700/);
});

test('lifetime lock works across processes and releases on process death', (t) => {
  const { directory } = fixture(t); const journal = openIngressJournal(directory);
  const code = `import {openIngressJournal} from './scripts/lib/ingress-journal.mjs';
    const j=openIngressJournal(${JSON.stringify(directory)}, {coordinate:false}); process.kill(process.pid,'SIGKILL');`;
  const locked = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout: 5000 });
  assert.equal(locked.status, 1); assert.match(locked.stderr, /locked/); journal.release();
  const crashed = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', timeout: 5000 });
  assert.equal(crashed.signal, 'SIGKILL'); openIngressJournal(directory).release();
});

test('recovery CLI requires explicit scope and rejects unknown/duplicate flags', () => {
  for (const argv of [[], ['--from-tun=lo'], ['--from-tun=wg0', '--apply', '--apply'],
    ['--from-tun=wg0', '--command=anything'], ['--from-tun=wg0', '--state-dir=relative']]) {
    assert.throws(() => recoverIngress(argv));
  }
});

test('an in-flight command keeps the lock after the owner closes its descriptors', async (t) => {
  const { directory } = fixture(t); const journal = openIngressJournal(directory);
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], {
    stdio: ['ignore', 'ignore', 'ignore', ...journal.lockDescriptors],
  });
  const ended = once(child, 'exit');
  try {
    journal.release(); assert.throws(() => openIngressJournal(directory), /locked/);
  } finally { child.kill('SIGKILL'); await ended; journal.release(); }
  openIngressJournal(directory).release();
});

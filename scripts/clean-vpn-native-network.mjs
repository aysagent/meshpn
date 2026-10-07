#!/usr/bin/env node
// Explicit fresh dedicated network profile. Never removes protection on stop.
import fs from 'node:fs';
import pathModule from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { applyNativeNetworkProfile } from './lib/native-network-apply.mjs';
const C = fs.constants;
let dfd, lock, operation = 'config';
try {
  if (process.getuid() !== 0 || process.argv.length !== 4 || !['--apply', '--activate-links'].includes(process.argv[2]) || !/^--config=\/[\w./-]+$/.test(process.argv[3])) throw Error();
  const privateFile = fd => { const s = fs.fstatSync(fd); if (!s.isFile() || s.uid !== 0 || s.nlink !== 1 || (s.mode & 0o777) !== 0o600 || s.size > 65536) throw Error(); };
  const readJson = p => { const fd = fs.openSync(p, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK); try { privateFile(fd); return JSON.parse(fs.readFileSync(fd)); } finally { fs.closeSync(fd); } };
  const path = process.argv[3].slice(9); if (fs.realpathSync(path) !== path) throw Error();
  for (let parent = pathModule.dirname(path); ; parent = pathModule.dirname(parent)) {
    const s = fs.lstatSync(parent);
    if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o022)) throw Error();
    if (parent === '/') break;
  }
  const config = readJson(path), scope = { boot: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(), net: fs.readlinkSync('/proc/self/ns/net'), user: fs.readlinkSync('/proc/self/ns/user') };
  const runtime = fs.lstatSync('/run'); if (!runtime.isDirectory() || runtime.uid !== 0 || (runtime.mode & 0o022)) throw Error();
  const dir = '/run/clean-vpn-native-network-' + scope.net.match(/\d+/)[0];
  try { fs.mkdirSync(dir, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  dfd = fs.openSync(dir, C.O_RDONLY | C.O_DIRECTORY | C.O_NOFOLLOW);
  const ds = fs.fstatSync(dfd); if (ds.uid !== 0 || (ds.mode & 0o777) !== 0o700) throw Error();
  const base = `/proc/self/fd/${dfd}`;
  lock = fs.openSync(base + '/lock', C.O_RDWR | C.O_CREAT | C.O_NOFOLLOW | C.O_NONBLOCK, 0o600); privateFile(lock);
  const run = (bin, args, input) => {
    operation = bin + ':' + args[0];
    return execFileSync(bin, args, { input, encoding: 'utf8', timeout: 10000,
      maxBuffer: 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe', lock] });
  };
  run('flock', ['--exclusive', '--nonblock', '3']);
  const read = () => { try { return readJson(base + '/journal.json'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } };
  const save = state => {
    const name = base + '/prepared-' + randomBytes(12).toString('hex');
    const fd = fs.openSync(name, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(name, base + '/journal.json'); fs.fsyncSync(dfd);
  };
  if (process.argv[2] === '--activate-links' && read() === null) throw Error();
  const result = applyNativeNetworkProfile(config, { run, read, save, scope });
  if (process.argv[2] === '--activate-links') {
    for (const link of [config.uplink, ...(config.lan ? [config.lan.interface] : [])]) run('ip', ['link', 'set', link, 'up']);
    console.log(JSON.stringify({ status: 'links-activated', addressesAndDefaults: 'external-link-owner' }));
  } else console.log(JSON.stringify(result));
} catch {
  console.error('native-network: refused at ' + operation + '; existing protection and journal retained; no automatic cleanup'); process.exitCode = 1;
} finally { if (lock !== undefined) fs.closeSync(lock); if (dfd !== undefined) fs.closeSync(dfd); }

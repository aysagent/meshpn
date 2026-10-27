#!/usr/bin/env node
// Offline provisioning only. No service, network or container commands.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runtimePlan } from './lib/native-runtime-plan.mjs';

const defaultProfile = fileURLToPath(new URL('../fixtures/native-tls-profiles/chromium-156-bounded-cold.json', import.meta.url));
export function parseRuntimeConfig(args) {
  const { values: v, positionals } = parseArgs({ args, allowPositionals: true, options: {
    help: { type: 'boolean' }, ...Object.fromEntries(['directory', 'mode', 'endpoint', 'exit-address', 'server-name', 'clients', 'days', 'profile'].map(k => [k, { type: 'string' }])) } });
  if (v.help) return { help: true };
  assert.deepEqual(positionals, ['create'], 'create required');
  // parseArgs accepts duplicate options; credentials must never depend on the
  // order of duplicate input. Refuse them rather than silently choosing last.
  const flags = args.filter(a => a.startsWith('--')).map(a => a.split('=')[0]);
  assert.equal(new Set(flags).size, flags.length, 'duplicate_option');
  assert.ok(v.directory && path.isAbsolute(v.directory) && path.normalize(v.directory) === v.directory, 'absolute_new_directory_required');
  assert.ok(['container', 'standalone'].includes(v.mode), 'explicit_mode_required');
  assert.match(v['server-name'] ?? '', /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/, 'dns_server_name_required');
  assert.ok(v['server-name'].split('.').every(label => label.length <= 63), 'dns_label_too_long');
  for (const key of ['clients', 'days']) if (v[key] !== undefined) assert.match(v[key], /^[1-9][0-9]*$/);
  const clients = Number(v.clients ?? 1), days = Number(v.days ?? 90);
  assert.ok(Number.isInteger(clients) && clients >= 1 && clients <= 32, 'clients_1_to_32');
  assert.ok(Number.isInteger(days) && days >= 1 && days <= 365, 'days_1_to_365');
  const common = { version: 1, tun: 'cvpn0', port: 443 };
  runtimePlan({ ...common, role: 'client', address: v.endpoint, dns: true });
  runtimePlan({ ...common, role: 'exit', address: v['exit-address'] });
  const profile = fs.readFileSync(v.profile ?? defaultProfile);
  assert.ok(profile.length <= 16384); JSON.parse(profile);
  return { directory: v.directory, mode: v.mode, endpoint: v.endpoint, exitAddress: v['exit-address'], serverName: v['server-name'], clients, days, profile };
}

export function createRuntimeConfig(o) {
  // Parent must already exist; never follow an unexpected symlink when
  // publishing keys. /tmp's sticky bit is allowed, arbitrary writable parents aren't.
  const uid = process.getuid();
  for (let p = path.dirname(o.directory); ; p = path.dirname(p)) {
    const s = fs.lstatSync(p);
    assert.ok(s.isDirectory() && !s.isSymbolicLink() && [0, uid].includes(s.uid), 'unsafe_parent');
    assert.ok(!(s.mode & 0o022) || (s.mode & 0o1000), 'writable_parent');
    if (p === '/') break;
  }
  fs.mkdirSync(o.directory, { mode: 0o700 }); // EEXIST: no rotation/overwrite.
  const write = (f, b) => fs.writeFileSync(path.join(o.directory, f), b, { mode: 0o600, flag: 'wx' });
  const json = (f, v) => write(f, JSON.stringify(v, null, 2) + '\n');
  const openssl = args => execFileSync('openssl', args, { cwd: o.directory, timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] });
  const oldMask = process.umask(0o077);
  try {
    for (const dir of ['authority', 'exit', ...Array.from({ length: o.clients }, (_, i) => `client-${i + 1}`)]) fs.mkdirSync(path.join(o.directory, dir), { mode: 0o700 });
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', String(o.days), '-subj', '/CN=clean-vpn private CA',
      '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', 'authority/ca.key', '-out', 'authority/ca.pem']);
    openssl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + o.serverName, '-keyout', 'exit/key.pem', '-out', 'authority/exit.csr']);
    write('authority/extensions.cnf', `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${o.serverName}\n`);
    openssl(['x509', '-req', '-in', 'authority/exit.csr', '-CA', 'authority/ca.pem', '-CAkey', 'authority/ca.key',
      '-set_serial', '0x' + randomBytes(16).toString('hex'), '-days', String(o.days), '-extfile', 'authority/extensions.cnf', '-out', 'exit/cert.pem']);
    openssl(['verify', '-purpose', 'sslserver', '-verify_hostname', o.serverName, '-CAfile', 'authority/ca.pem', 'exit/cert.pem']);
    const at = (role, name) => o.mode === 'container' ? '/config/' + name : path.join(o.directory, role, name);
    const peers = [], clients = [];
    for (let i = 1; i <= o.clients; i++) {
      const role = `client-${i}`, peer = `10.99.0.${i + 1}`, secret = randomBytes(32);
      write(`${role}/psk`, secret); write(`exit/peer-${i}.psk`, secret);
      write(`${role}/ca.pem`, fs.readFileSync(path.join(o.directory, 'authority/ca.pem')));
      write(`${role}/profile.json`, o.profile);
      json(`${role}/engine.json`, { version: 1, role: 'client', tun: 'cvpn0', address: o.endpoint, port: 443,
        dns: true, peer_ipv4: peer, server_name: o.serverName, ca: at(role, 'ca.pem'), secret_path: at(role, 'psk'), tls_profile_path: at(role, 'profile.json') });
      peers.push({ ipv4: peer, secret_path: at('exit', `peer-${i}.psk`) }); clients.push({ directory: role, ipv4: peer });
    }
    json('exit/engine.json', { version: 1, role: 'exit', tun: 'cvpn0', address: o.exitAddress, port: 443, alps: true,
      cert: at('exit', 'cert.pem'), key: at('exit', 'key.pem'), peers });
    const manifest = { schema: 1, kind: 'native-runtime-config', mode: o.mode, endpoint: o.endpoint, exitAddress: o.exitAddress,
      serverName: o.serverName, clients, certificateDays: o.days, profileSha256: createHash('sha256').update(o.profile).digest('hex'),
      networkChanged: false, nativeValidation: 'required-on-target-before-start',
      distribution: 'Each client gets only its client-N directory. Exit gets only exit/. Keep authority/ offline; never mount the whole bundle.' };
    json('manifest.json', manifest); return manifest;
  } finally { process.umask(oldMask); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const o = parseRuntimeConfig(process.argv.slice(2));
    if (o.help) console.log('Usage: node scripts/clean-vpn-native-runtime-config.mjs create --directory=/NEW/private/bundle --mode=container|standalone --endpoint=EXIT_IPV4 --exit-address=EXIT_NAMESPACE_IPV4 --server-name=vpn.example.net [--clients=1..32] [--days=1..365] [--profile=/profile.json]\nOffline only; creates private CA, unique per-client PSKs and Chromium subset profiles. Existing directory is never overwritten. Container files use /config paths; standalone files use the new absolute directory. Copy only the intended role directory; Linux runtime requires root-owned credentials.');
    else console.log(JSON.stringify(createRuntimeConfig(o), null, 2));
  } catch (error) { console.error('NATIVE_CONFIG=failed: ' + (error.code ?? error.message) + '\nNo network or service settings changed. Any incomplete new directory is retained for inspection.'); process.exitCode = 1; }
}

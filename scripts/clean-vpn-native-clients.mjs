#!/usr/bin/env node
// Offline provisioning: one exit and private per-client bundles. No OS setters.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, X509Certificate, createPrivateKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { nativeNetworkPlan } from './lib/native-network-profile.mjs';

const fields = (object, allowed) => {
  assert.ok(object && typeof object === 'object' && !Array.isArray(object));
  for (const key of Object.keys(object)) assert.ok(allowed.includes(key), `unknown field: ${key}`);
};
const absolute = p => {
  assert.ok(typeof p === 'string' && /^\/[A-Za-z0-9_./-]+$/.test(p) && path.normalize(p) === p && p !== '/', 'safe absolute path required');
  return p;
};
const hostname = s => typeof s === 'string' && s.length <= 253 && s.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
export function planNativeClients(input) {
  fields(input, ['version', 'transport', 'endpoint', 'port', 'server_name', 'public_name', 'cert', 'key', 'ca', 'deploy_root', 'exit', 'clients', 'deny_ipv4']);
  assert.equal(input.version, 1);
  assert.ok(['boring-tls', 'combo-tls'].includes(input.transport));
  assert.ok(hostname(input.server_name), 'server_name required');
  const combo = input.transport === 'combo-tls';
  if (combo) assert.ok(hostname(input.public_name), 'public_name required');
  else assert.ok(input.public_name === undefined && input.deny_ipv4 === undefined, 'relay fields require combo-tls');
  for (const key of ['cert', 'key', 'ca', 'deploy_root']) absolute(input[key]);
  assert.ok(Array.isArray(input.clients) && input.clients.length >= 1 && input.clients.length <= 32, '1..32 clients required');
  const names = new Set(), ips = new Set();
  const root = input.deploy_root, peers = [];
  const site = (owner, role, address) => {
    fields(owner, role === 'exit' ? ['uplink', 'link_unit'] : ['name', 'ipv4', 'uplink', 'link_unit', 'lan']);
    assert.match(owner.link_unit ?? '', /^[a-z][a-z0-9-]{0,63}\.service$/);
    const profile = { version: 1, role, tun: 'tun0', tun_address: address, mtu: 1400,
      uplink: owner.uplink, endpoint: input.endpoint, port: input.port,
      lan: role === 'exit' ? null : owner.lan ?? null,
      ...(combo ? { transport: 'combo-tls', listen_port: role === 'exit' ? input.port : 33002, deny_ipv4: input.deny_ipv4 ?? [] } : {}) };
    nativeNetworkPlan(profile);
    return { link_unit: owner.link_unit, profile };
  };
  const relay = role => ({ version: 1, transport: 'transparent-tls', role, public_name: input.public_name,
    secret_path: root + '/relay.psk', destination_policy: { mode: 'public-https', deny_ipv4: input.deny_ipv4 ?? [] },
    listen: { ipv4: role === 'exit' ? input.endpoint : '0.0.0.0', port: role === 'exit' ? input.port : 33002 },
    ...(role === 'exit' ? { replay_directory: root + '/replay' } : { exit: { ipv4: input.endpoint, port: input.port } }) });
  const wrap = packet => combo ? { version: 1, transport: 'combo-tls', role: packet.role, boring: packet, transparent: relay(packet.role) } : packet;
  const common = { version: 1, tun: 'tun0', address: input.endpoint, port: input.port };
  const clients = input.clients.map(client => {
    assert.match(client.name ?? '', /^[a-z][a-z0-9-]{0,31}$/);
    assert.ok(!names.has(client.name), 'duplicate client name'); names.add(client.name);
    assert.match(client.ipv4 ?? '', /^10\.99\.0\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$/);
    assert.ok(!ips.has(client.ipv4), 'duplicate client address'); ips.add(client.ipv4);
    peers.push({ ipv4: client.ipv4, secret_path: `${root}/peers/${client.name}.psk` });
    return { name: client.name, ipv4: client.ipv4, site: site(client, 'client', client.ipv4 + '/32'),
      config: wrap({ ...common, role: 'client', peer_ipv4: client.ipv4, dns: true,
        secret_path: root + '/packet.psk', ca: root + '/ca.pem', server_name: input.server_name,
        ...(combo ? { sni: input.public_name } : {}) }) };
  });
  return { transport: input.transport, deployRoot: root,
    exit: { site: site(input.exit, 'exit', '10.99.0.1/24'),
      config: wrap({ ...common, role: 'exit', cert: root + '/cert.pem', key: root + '/key.pem', peers }) }, clients };
}

function readInput(file, secret = false) {
  absolute(file);
  assert.equal(fs.realpathSync(file), file, 'symlink input refused');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const s = fs.fstatSync(fd);
    assert.ok(s.isFile() && s.nlink === 1 && s.size > 0 && s.size <= 1024 * 1024 && !(s.mode & 0o022), 'unsafe input');
    if (secret) assert.ok(s.uid === process.getuid() && !(s.mode & 0o077), 'private key must be owner-only');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}
export function prepareNativeClients(input, directory) {
  const plan = planNativeClients(input); absolute(directory);
  // Validate all data before creating an exclusive destination. Never overwrite
  // previous credentials or silently rotate keys on a second invocation.
  const cert = readInput(input.cert), ca = readInput(input.ca), key = readInput(input.key, true);
  try {
    const leaf = new X509Certificate(cert);
    assert.ok(leaf.checkPrivateKey(createPrivateKey(key)), 'certificate/key mismatch');
    assert.ok(leaf.checkHost(input.server_name), 'certificate hostname mismatch');
    new X509Certificate(ca);
    for (let parent = path.dirname(directory); ; parent = path.dirname(parent)) {
      const s = fs.lstatSync(parent);
      assert.ok(s.isDirectory() && !s.isSymbolicLink() && [0, process.getuid()].includes(s.uid)
        && (!(s.mode & 0o022) || (s.mode & 0o1000)), 'unsafe output ancestor');
      if (parent === '/') break;
    }
    fs.mkdirSync(directory, { mode: 0o700 });
    const write = (relative, bytes) => fs.writeFileSync(path.join(directory, relative), bytes, { flag: 'wx', mode: 0o600 });
    const json = (relative, value) => write(relative, JSON.stringify(value, null, 2) + '\n');
    fs.mkdirSync(directory + '/exit', { mode: 0o700 });
    fs.mkdirSync(directory + '/exit/peers', { mode: 0o700 });
    fs.mkdirSync(directory + '/clients', { mode: 0o700 });
    const relayKey = plan.transport === 'combo-tls' ? randomBytes(32) : null;
    try {
      write('exit/cert.pem', cert); write('exit/key.pem', key);
      json('exit/config.json', plan.exit.config); json('exit/site.json', plan.exit.site);
      if (relayKey) write('exit/relay.psk', relayKey);
      for (const client of plan.clients) {
        const sub = `clients/${client.name}`;
        fs.mkdirSync(directory + '/' + sub, { mode: 0o700 });
        const packetKey = randomBytes(32);
        try { write(`exit/peers/${client.name}.psk`, packetKey); write(sub + '/packet.psk', packetKey); }
        finally { packetKey.fill(0); }
        write(sub + '/ca.pem', ca); if (relayKey) write(sub + '/relay.psk', relayKey);
        json(sub + '/config.json', client.config); json(sub + '/site.json', client.site);
      }
      const report = { schema: 1, status: 'prepared', transport: plan.transport, clients: plan.clients.map(c => ({ name: c.name, ipv4: c.ipv4 })),
        deployRoot: plan.deployRoot, systemSettingsChanged: false, replayInitialized: false,
        relayAuthentication: relayKey ? 'shared-group-key; no per-client relay revocation' : 'not-used',
        next: 'Copy only the matching host bundle to deployRoot; validate with engine --check-config; review site before installation. CA chain trust still requires a real TLS handshake.' };
      json('manifest.json', report); return report;
    } finally { relayKey?.fill(0); }
  } finally { key.fill(0); }
}

function main(args) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: node scripts/clean-vpn-native-clients.mjs --manifest=/absolute/clients.json --directory=/absolute/NEW-directory\nOffline native boring-tls/combo-tls bundles for 1..32 clients. No network/service changes. See scripts/clean-vpn-native-clients.md.'); return;
  }
  const options = new Map();
  for (const arg of args) { const m = /^--(manifest|directory)=(.+)$/.exec(arg); assert.ok(m && !options.has(m[1]), 'invalid option'); options.set(m[1], absolute(m[2])); }
  assert.equal(options.size, 2, 'manifest and directory required');
  console.log(JSON.stringify(prepareNativeClients(JSON.parse(readInput(options.get('manifest'))), options.get('directory')), null, 2));
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch { console.error('native-clients: preparation refused; any partial private directory is retained for review; no system settings changed'); process.exitCode = 1; }
}

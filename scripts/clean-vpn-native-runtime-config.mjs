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
import { tcpPort } from './lib/native-port.mjs';

const defaultProfile = fileURLToPath(new URL('../fixtures/native-tls-profiles/chromium-156-bounded-cold.json', import.meta.url));
export function parseRuntimeConfig(args) {
  const { values: v, positionals } = parseArgs({ args, allowPositionals: true, options: {
    help: { type: 'boolean' }, 'private-peer-dns': { type: 'boolean' }, ...Object.fromEntries(['directory', 'mode', 'endpoint', 'exit-address', 'port', 'exit-port', 'server-name', 'clients', 'days', 'profile', 'transport', 'public-name', 'relay-port', 'relay-sessions', 'relay-per-client'].map(k => [k, { type: 'string' }])) } });
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
  const port = tcpPort(v.port ?? 443), exitPort = tcpPort(v['exit-port'] ?? port);
  const transport=v.transport??'boring-tls';assert.ok(['boring-tls','combo-tls'].includes(transport),'supported_transport_required');
  const publicName=v['public-name'],relayPort=tcpPort(v['relay-port']??10443);
  for(const key of ['relay-sessions','relay-per-client'])if(v[key]!==undefined)assert.match(v[key],/^[1-9][0-9]*$/);
  const relaySessions=Number(v['relay-sessions']??128),relayPerClient=Number(v['relay-per-client']??64);
  assert.ok(relaySessions>=2&&relaySessions<=256&&relayPerClient>=1&&relayPerClient<relaySessions,'relay_quota_bounds');
  if(transport==='combo-tls'){
    assert.match(publicName??'',/^(?=.{1,100}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/,'public_name_required');
    assert.ok(publicName.split('.').every(l=>l.length<=63));
    assert.ok(![1053,2222].includes(relayPort),'relay_reserved_port');
  }else assert.ok(publicName===undefined&&v['relay-port']===undefined&&v['relay-sessions']===undefined&&v['relay-per-client']===undefined,'combo_options_only');
  const common = { version: 1, tun: 'cvpn0', port };
  runtimePlan({ ...common, role: 'client', address: v.endpoint, dns: true });
  runtimePlan({ ...common, port: exitPort, role: 'exit', address: v['exit-address'] });
  const profile = fs.readFileSync(v.profile ?? defaultProfile);
  assert.ok(profile.length <= 16384); JSON.parse(profile);
  return { privatePeerDns: v['private-peer-dns']??false, transport, publicName, relayPort, relaySessions, relayPerClient, directory: v.directory, mode: v.mode, endpoint: v.endpoint, port, exitPort, exitAddress: v['exit-address'], serverName: v['server-name'], clients, days, profile };
}

export function createRuntimeConfig(o) {
  if(o.privatePeerDns!==undefined)assert.equal(typeof o.privatePeerDns,'boolean');
  const port = tcpPort(o.port ?? 443), exitPort = tcpPort(o.exitPort ?? port);
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
    const combo=o.transport==='combo-tls',relayPeers=[];
    const relayLimits={sessions:o.relaySessions??128,per_client:o.relayPerClient??64};
    const wrap=(role,packet,directory=role)=>combo?{version:1,transport:'combo-tls',role,boring:packet,transparent:{
      version:1,transport:'transparent-tls',role,public_name:o.publicName,...(role==='client'?{secret_path:at(directory,'relay.psk')}:{peers:relayPeers}),limits:relayLimits,
      destination_policy:{mode:'public-https',deny_ipv4:[]},
      listen:{ipv4:role==='client'?'0.0.0.0':o.exitAddress,port:role==='client'?o.relayPort:exitPort},
      ...(role==='client'?{exit:{ipv4:o.endpoint,port}}:{replay_directory:o.mode==='container'?'/replay/state':path.join(o.directory,'exit','replay')})}}:packet;
    const peers = [], clients = [];
    for (let i = 1; i <= o.clients; i++) {
      const role = `client-${i}`, peer = `10.99.0.${i + 1}`, secret = randomBytes(32);
      write(`${role}/psk`, secret); write(`exit/peer-${i}.psk`, secret);
      write(`${role}/ca.pem`, fs.readFileSync(path.join(o.directory, 'authority/ca.pem')));
      write(`${role}/profile.json`, o.profile);
      if(combo){const relaySecret=randomBytes(32);write(`${role}/relay.psk`,relaySecret);write(`exit/relay-${i}.psk`,relaySecret);relayPeers.push({id:`client-${i}`,secret_path:at('exit',`relay-${i}.psk`)});}
      const packet={ version: 1, role: 'client', tun: 'cvpn0', address: o.endpoint, port,
        dns: true, peer_ipv4: peer, server_name: o.serverName, ca: at(role, 'ca.pem'), secret_path: at(role, 'psk'), tls_profile_path: at(role, 'profile.json'),...(combo?{sni:o.publicName}:{}) };
      const config=wrap('client',packet,role);
      json(`${role}/engine.json`,config);
      peers.push({ ipv4: peer, secret_path: at('exit', `peer-${i}.psk`) }); clients.push({ directory: role, ipv4: peer });
    }
    json('exit/engine.json', wrap('exit', { version: 1, role: 'exit', tun: 'cvpn0', address: o.exitAddress, port: exitPort, alps: true,
      cert: at('exit', 'cert.pem'), key: at('exit', 'key.pem'), peers, ...(o.privatePeerDns?{private_peer_dns:true}:{}) }));
    const manifest = { schema: 1, kind: 'native-runtime-config', transport:o.transport??'boring-tls', ...(combo?{publicName:o.publicName,relayPort:o.relayPort,relayIdentity:'unique-relay-and-packet-PSKs-per-client',relayLimits,replay:'explicit-init-on-target; never reset on restart'}:{}), mode: o.mode, endpoint: o.endpoint, port, exitPort, exitAddress: o.exitAddress,
      serverName: o.serverName, clients, certificateDays: o.days, profileSha256: createHash('sha256').update(o.profile).digest('hex'),
      privatePeerDns:o.privatePeerDns===true, privatePeerDnsResolver:'separate registry resolver on exit loopback:1055 required; never public DNS fallback for .mpn',
      networkChanged: false, nativeValidation: 'required-on-target-before-start',
      distribution: 'Each client gets only its client-N directory. Exit gets only exit/. Keep authority/ offline; never mount the whole bundle.' };
    json('manifest.json', manifest); return manifest;
  } finally { process.umask(oldMask); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const o = parseRuntimeConfig(process.argv.slice(2));
    if (o.help) console.log('Usage: node scripts/clean-vpn-native-runtime-config.mjs create --directory=/NEW/private/bundle --mode=container|standalone --endpoint=EXIT_IPV4 --exit-address=EXIT_NAMESPACE_IPV4 --server-name=vpn.example.net [--port=443] [--exit-port=PORT] [--clients=1..32] [--private-peer-dns] [--days=1..365] [--profile=/profile.json] [--transport=boring-tls|combo-tls] [--public-name=relay.example --relay-port=10443 --relay-sessions=128 --relay-per-client=64]\nCombo requires --public-name, explicit LAN at launch and a separately initialized exit replay volume. Offline only; creates private CA, unique per-client PSKs and Chromium subset profiles. --port is the client destination port; --exit-port defaults to it and sets the exit listener (use a different value only with explicit port mapping). Existing directory is never overwritten. Container files use /config paths; standalone files use the new absolute directory. Copy only the intended role directory; Linux runtime requires root-owned credentials.');
    else console.log(JSON.stringify(createRuntimeConfig(o), null, 2));
  } catch (error) { console.error('NATIVE_CONFIG=failed: ' + (error.code ?? error.message) + '\nNo network or service settings changed. Any incomplete new directory is retained for inspection.'); process.exitCode = 1; }
}

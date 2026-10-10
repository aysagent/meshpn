#!/usr/bin/env node
/** Explicit local preparation for the bounded Radxa <-> VPS combo trial. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { fileURLToPath } from 'node:url';
import { directExitLegacyContext, validateDirectExitConfig } from './clean-vpn-native-exit-trial.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const ENGINE = path.join(ROOT, 'native/clean_vpn/build/clean-vpn-engine');
const safePath = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value
  && /^\/[A-Za-z0-9_./-]+$/.test(value);
function canonicalIpv4Cidr(value) {
  const [address, prefixText, extra] = value.split('/');
  if (extra !== undefined || !isIPv4(address) || !/^(?:[0-9]|[12][0-9]|3[0-2])$/.test(prefixText ?? '')) return false;
  const prefix = Number(prefixText), numeric = address.split('.').reduce((result, octet) => (result * 256 + Number(octet)) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((numeric & mask) >>> 0) === numeric;
}
function safeCreationParent(directory, owner) {
  for (let current = path.dirname(directory); ; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && (stat.uid === 0 || stat.uid === owner), 'unsafe creation ancestor');
    assert.ok(!(stat.mode & 0o022) || (stat.mode & 0o1000), 'writable non-sticky creation ancestor');
    if (current === '/') return;
  }
}
export function parseDirectConfigArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  assert.equal(args[0], '--create-exit'); const values = new Map();
  for (const arg of args.slice(1)) { const match = /^--(directory|endpoint|uplink|client-relay-path|deny-ipv4)=(.*)$/.exec(arg);
    assert.ok(match && !values.has(match[1]), 'invalid or duplicate option'); values.set(match[1], match[2]); }
  const directory = values.get('directory'), endpoint = values.get('endpoint'), uplink = values.get('uplink') ?? 'eth0';
  const clientRelayPath = values.get('client-relay-path'), denyIpv4 = values.get('deny-ipv4') ? values.get('deny-ipv4').split(',') : [];
  assert.ok(safePath(directory) && safePath(clientRelayPath), 'absolute safe directories required');
  assert.ok(isIPv4(endpoint) && /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(uplink), 'invalid endpoint or uplink');
  assert.ok(denyIpv4.length <= 64 && denyIpv4.every(canonicalIpv4Cidr), 'invalid deny list');
  return { directory, endpoint, uplink, clientRelayPath, denyIpv4 };
}
function privateWrite(file, value) { fs.writeFileSync(file, value, { mode: 0o600, flag: 'wx' }); }
export async function prepareDirectExit(options, { context = directExitLegacyContext,
  execute = (file, args) => execFileSync(file, args, { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] }),
  uid = () => process.getuid?.(), requireRoot = true } = {}) {
  const owner = uid(); if (requireRoot) assert.equal(owner, 0, 'root required');
  const legacy = await context(options.endpoint, options.uplink);
  safeCreationParent(options.directory, owner);
  fs.mkdirSync(options.directory, { mode: 0o700 });
  const stat = fs.lstatSync(options.directory); assert.ok(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === owner && (stat.mode & 0o777) === 0o700);
  const relay = path.join(options.directory, 'relay.psk'), replay = path.join(options.directory, 'replay');
  fs.mkdirSync(replay, { mode: 0o700 }); privateWrite(relay, randomBytes(32));
  const boring = { version: 1, role: 'exit', address: options.endpoint, port: 443, tun: 'tun0',
    cert: legacy.legacy.cert, key: legacy.legacy.key,
    peers: [{ ipv4: '10.99.0.2', secret_path: legacy.legacy.secret }] };
  const transparent = { version: 1, transport: 'transparent-tls', role: 'exit', public_name: legacy.legacy.publicName,
    secret_path: relay, listen: { ipv4: options.endpoint, port: 443 },
    destination_policy: { mode: 'public-https', deny_ipv4: [...options.denyIpv4] }, replay_directory: replay };
  const exit = { version: 1, transport: 'combo-tls', role: 'exit', boring, transparent };
  validateDirectExitConfig(exit, { endpoint: options.endpoint, uplink: options.uplink, legacy: legacy.legacy });
  const exitFile = path.join(options.directory, 'exit.json'), clientFile = path.join(options.directory, 'client-profile.json');
  privateWrite(exitFile, JSON.stringify(exit, null, 2) + '\n');
  privateWrite(clientFile, JSON.stringify({ version: 1, public_name: legacy.legacy.publicName,
    relay_secret_path: options.clientRelayPath, listen_port: 33002, deny_ipv4: [...options.denyIpv4] }, null, 2) + '\n');
  try { execute(ENGINE, ['--check-config', exitFile]); execute(ENGINE, ['--init-transparent-replay', exitFile]); }
  catch { throw Error('native_exit_config_or_replay_initialization_failed'); }
  return { status: 'prepared', directory: options.directory, exitConfig: exitFile, clientProfileTemplate: clientFile,
    relaySecret: relay, replayDirectory: replay, publicName: legacy.legacy.publicName,
    next: 'copy relay.psk securely to the exact client relay_secret_path; copy client-profile.json to Radxa; then run exit --preflight' };
}
async function main(args = process.argv.slice(2)) {
  const options = parseDirectConfigArgs(args);
  if (options.help) { console.log('Usage on exit: sudo node scripts/clean-vpn-native-direct-config.mjs --create-exit --directory=/root/native-combo-trial --endpoint=154.62.226.216 --uplink=eth0 --client-relay-path=/root/native-combo-trial/relay.psk [--deny-ipv4=CIDR,...]\nCreates a new owner-only directory, random relay PSK, initialized replay journal, exit config and Radxa profile template. Never stops services or changes network/firewall.'); return; }
  console.log(JSON.stringify(await prepareDirectExit(options), null, 2));
}
const entry = import.meta.main === true || process.argv[1] && path.basename(process.argv[1]) === path.basename(fileURLToPath(import.meta.url));
if (entry) main().catch(error => { console.error(JSON.stringify({ status: 'failed', code: /^[a-z0-9_]+$/.test(error.message) ? error.message : 'direct_config_failed',
  note: 'The newly created private directory is retained for review; no service or network setting was changed.' })); process.exitCode = 1; });

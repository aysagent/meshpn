#!/usr/bin/env node
/** Bounded transient combo exit over the existing host; never an installer. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash, randomUUID } from 'node:crypto';
import { isIPv4 } from 'node:net';
import { openNativeExitTrialNetwork } from './lib/native-exit-trial-network.mjs';
import { trialServiceFingerprint } from './lib/native-trial-service.mjs';

const SELF = fileURLToPath(import.meta.url), ROOT = path.dirname(path.dirname(SELF));
const ENGINE = path.join(ROOT, 'native/clean_vpn/build/clean-vpn-engine');
const OLD = 'clean-vpn.service', UNIT = 'clean-vpn-native-exit-trial.service';
const REPORT_DIR = '/var/lib/clean-vpn-native-exit-trial', SCRATCH = '/run/clean-vpn-native-exit-trial-config';
const ENV = { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' };
const check = (ok, code) => { if (!ok) throw Error(code); };
const safe = error => /^[a-z0-9_]{1,100}$/.test(error?.message ?? '') ? error.message : 'operation_failed';
async function command(file, args, timeout = 15000) {
  return await new Promise(resolve => {
    const child = spawn(file, args, { cwd: ROOT, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', bytes = 0, reason = null;
    const timer = setTimeout(() => { reason = 'timeout'; child.kill('SIGKILL'); }, timeout);
    for (const [stream, retain] of [[child.stdout, true], [child.stderr, false]]) stream.on('data', chunk => {
      bytes += chunk.length; if (bytes > 1024 * 1024) { reason = 'output_limit'; child.kill('SIGKILL'); }
      else if (retain) stdout += chunk;
    });
    child.on('error', () => { reason = 'spawn_failed'; });
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, reason }); });
  });
}
async function run(file, args, timeout) {
  const result = await command(file, args, timeout);
  check(result.code === 0 && !result.reason, `command_${path.basename(file).replace(/[^a-z0-9_]/g, '_')}_failed`);
  return result.stdout.trim();
}
const system = (...args) => run('systemctl', args);
const property = (unit, name) => system('show', unit, `--property=${name}`, '--value');
async function unitState(unit) {
  const result = await command('systemctl', ['show', unit, '--property=LoadState,ActiveState,SubState,MainPID,InvocationID']);
  if (result.code === 4 && !result.reason) return { LoadState: 'not-found', ActiveState: 'inactive', SubState: 'dead', MainPID: '0', InvocationID: '' };
  check(result.code === 0 && !result.reason, 'unit_state_unavailable');
  return Object.fromEntries(result.stdout.trim().split('\n').map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
}
function privateDirectory(directory) {
  try { fs.mkdirSync(directory, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const stat = fs.lstatSync(directory); check(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === 0
    && (stat.mode & 0o777) === 0o700, 'unsafe_exit_trial_directory');
}
function privateJson(file) {
  check(path.isAbsolute(file) && path.normalize(file) === file, 'absolute_exit_config_required');
  const stat = fs.lstatSync(file); check(stat.isFile() && !stat.isSymbolicLink() && fs.realpathSync(file) === file
    && stat.uid === 0 && (stat.mode & 0o077) === 0 && stat.size > 0 && stat.size <= 16384, 'unsafe_exit_config');
  const bytes = fs.readFileSync(file); check(bytes.length === stat.size, 'short_exit_config'); return JSON.parse(bytes);
}
function privateOwnedDirectory(directory) {
  check(path.isAbsolute(directory) && path.normalize(directory) === directory, 'absolute_private_directory_required');
  const stat = fs.lstatSync(directory); check(stat.isDirectory() && !stat.isSymbolicLink() && fs.realpathSync(directory) === directory
    && stat.uid === 0 && (stat.mode & 0o077) === 0, 'unsafe_private_directory'); return directory;
}
function flags(argv, cwd) {
  const result = new Map();
  check(argv.length >= 3 && path.resolve(cwd, argv[1]) === path.join(ROOT, 'scripts/clean-vpn.js'),
    'unsupported_exit_service_command');
  for (const arg of argv.slice(2)) {
    check(arg.startsWith('--'), 'unsupported_exit_service_arguments'); const at = arg.indexOf('='), key = at < 0 ? arg : arg.slice(0, at);
    check(!result.has(key), 'duplicate_exit_service_option'); result.set(key, at < 0 ? true : arg.slice(at + 1));
  }
  return result;
}
export function validateDirectExitConfig(config, { endpoint, uplink, legacy }) {
  check(config?.version === 1 && config.transport === 'combo-tls' && config.role === 'exit', 'combo_exit_config_required');
  const boring = config.boring, relay = config.transparent;
  check(boring?.version === 1 && boring.role === 'exit' && boring.address === endpoint && boring.port === 443,
    'exit_packet_endpoint_mismatch');
  check(typeof boring.tun === 'string' && boring.peers?.length === 1 && boring.peers[0].ipv4 === '10.99.0.2', 'exit_packet_peer_mismatch');
  check(boring.cert === legacy.cert && boring.key === legacy.key && boring.peers[0].secret_path === legacy.secret,
    'exit_legacy_material_mismatch');
  check(relay?.version === 1 && relay.transport === 'transparent-tls' && relay.role === 'exit'
    && relay.public_name === legacy.publicName && relay.public_name === relay.public_name.toLowerCase(), 'exit_public_name_mismatch');
  check(JSON.stringify(relay.listen) === JSON.stringify({ ipv4: endpoint, port: 443 }), 'exit_listener_mismatch');
  check(relay.destination_policy?.mode === 'public-https' && Array.isArray(relay.destination_policy.deny_ipv4), 'exit_policy_mismatch');
  check(path.isAbsolute(relay.secret_path) && path.isAbsolute(relay.replay_directory), 'exit_relay_paths_must_be_absolute');
  check(isIPv4(endpoint) && /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(uplink), 'invalid_exit_network');
  return structuredClone(config);
}
function writeStatus(value) {
  privateDirectory(REPORT_DIR); const temp = path.join(REPORT_DIR, `status-${randomUUID()}.tmp`);
  try { fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' }); fs.renameSync(temp, path.join(REPORT_DIR, 'status.json')); }
  finally { try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') throw error; } }
}
export async function directExitLegacyContext(endpoint, uplink) {
  check(await property(OLD, 'ActiveState') === 'active', 'legacy_exit_not_active');
  const pid = await property(OLD, 'MainPID'); check(/^[1-9]\d*$/.test(pid), 'legacy_exit_pid_missing');
  const argv = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean), cwd = fs.realpathSync(`/proc/${pid}/cwd`);
  check(cwd === fs.realpathSync(ROOT), 'exit_trial_requires_installed_checkout');
  const f = flags(argv, cwd), server = String(f.get('--server') ?? '');
  check(f.get('--role') === 'exit' && f.get('--type') === 'tls' && server === '0.0.0.0:443'
    && (f.get('--ext') ?? 'eth0') === uplink, 'reviewed_legacy_tls_exit_required');
  const certDir = path.resolve(cwd, f.get('--tls-cert-dir') || f.get('--quic-certs-dir') || path.join(ROOT, 'certs'));
  const le = fs.existsSync(path.join(certDir, 'fullchain.pem'));
  const cert = path.join(certDir, le ? 'fullchain.pem' : 'cert.pem'), key = path.join(certDir, le ? 'privkey.pem' : 'key.pem');
  const explicit = f.get('--shared-hmac-key') || f.get('--quic-ext-crypto-key');
  const modern = path.join(certDir, 'clean-vpn-hmac.key');
  const secret = explicit ? path.resolve(cwd, explicit) : fs.existsSync(modern) ? modern : path.join(certDir, 'quic-ext-hmac.key');
  const publicName = String(f.get('--tls-public-name') ?? '').split(',')[0].trim().toLowerCase();
  check(publicName && [cert, key, secret].every(fs.existsSync), 'legacy_exit_material_missing');
  check(endpoint !== '0.0.0.0', 'public_exit_endpoint_required');
  return { pid, argv, legacy: { cert, key, secret, publicName }, fingerprint: await trialServiceFingerprint({ run, root: ROOT }) };
}
function engineProcess(config) {
  const child = spawn(ENGINE, ['--config', config, '--service'], { cwd: ROOT, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
  let ended = false, code = null, signal = null, bytes = 0, broken = false;
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { bytes += chunk.length; if (bytes > 256 * 1024) { broken = true; child.kill('SIGTERM'); } });
  child.on('error', () => { broken = true; }); child.on('close', (c, s) => { ended = true; code = c; signal = s; });
  return { get ended() { return ended; }, healthy: () => !ended && !broken, summary: () => ({ code, signal, boundedOutput: !broken }),
    async stop() { if (!ended) child.kill('SIGTERM'); const deadline = performance.now() + 30000;
      while (!ended && performance.now() < deadline) await delay(100); check(ended, 'native_exit_stop_timeout'); } };
}
async function waitListener(endpoint, port, engine) {
  const deadline = performance.now() + 20000;
  while (performance.now() < deadline) {
    check(engine.healthy(), 'native_exit_start_failed');
    const listeners = await run('ss', ['-H', '-ltn', `sport = :${port}`]);
    if (listeners.split('\n').some(line => line.includes(`${endpoint}:${port}`))) return;
    await delay(200);
  }
  throw Error('native_exit_listener_timeout');
}
async function preflight(configFile, endpoint, uplink) {
  check(process.getuid?.() === 0 && fs.readFileSync('/proc/1/comm', 'utf8').trim() === 'systemd', 'root_systemd_required');
  const context = await directExitLegacyContext(endpoint, uplink);
  const config = validateDirectExitConfig(privateJson(configFile), { endpoint, uplink, legacy: context.legacy }), bytes = fs.readFileSync(configFile);
  const packet = fs.readFileSync(config.boring.peers[0].secret_path), relay = fs.readFileSync(config.transparent.secret_path);
  let distinct = false; try { distinct = packet.length === 32 && relay.length === 32 && !packet.equals(relay); }
  finally { packet.fill(0); relay.fill(0); }
  const capabilities = JSON.parse(await run(ENGINE, ['--capabilities']));
  await run(ENGINE, ['--check-config', configFile]);
  const links = JSON.parse(await run('ip', ['-j', 'address', 'show']));
  const routes = JSON.parse(await run('ip', ['-j', '-4', 'route', 'get', endpoint]));
  const listeners = await run('ss', ['-H', '-ltn', 'sport = :443']);
  const firewall = {};
  for (const [name, file, args] of [['filter', 'iptables-save', ['-t', 'filter']], ['nat', 'iptables-save', ['-t', 'nat']]])
    firewall[name] = createHash('sha256').update(await run(file, args)).digest('hex');
  const issues = [];
  if (!distinct) issues.push('relay-secret-not-distinct-32-byte');
  try { privateOwnedDirectory(config.transparent.replay_directory); } catch { issues.push('replay-directory-missing-or-unsafe'); }
  if (!links.find(item => item.ifname === uplink)?.addr_info?.some(a => a.family === 'inet' && a.local === endpoint))
    issues.push('endpoint-not-owned-by-uplink');
  if (routes.length !== 1 || routes[0].dev !== uplink) issues.push('endpoint-route-uplink-mismatch');
  if (!listeners) issues.push('legacy-listener-not-observed');
  if (capabilities?.experimental_transports?.['combo-tls']?.single_exit_listener !== true) issues.push('combo-capability-mismatch');
  const report = { schema: 1, kind: 'clean-vpn-native-exit-direct-preflight', timestamp: new Date().toISOString(),
    status: issues.length ? 'blocked' : 'ready-for-bounded-transient-trial', systemSettingsChanged: false, networkProbesSent: 0,
    endpoint, port: 443, uplink, configSha256: createHash('sha256').update(bytes).digest('hex'),
    engineSha256: createHash('sha256').update(fs.readFileSync(ENGINE)).digest('hex'), legacyFingerprint: context.fingerprint,
    relaySecret: distinct ? 'distinct-32-byte' : 'invalid', replayDirectory: issues.includes('replay-directory-missing-or-unsafe') ? 'missing-or-unsafe' : 'private',
    endpointOwned: !issues.includes('endpoint-not-owned-by-uplink'), endpointRoute: routes[0]?.dev ?? null,
    legacyListener: !!listeners, firewallSnapshotSha256: firewall, observedIssues: issues,
    limitations: ['point-in-time-state', 'no-WAN-probe', 'no-provider-firewall-or-console-proof', 'no-mutation-simulation'] };
  return report;
}
async function worker(configFile, endpoint, uplink, holdSeconds) {
  check(process.getuid?.() === 0 && fs.readFileSync('/proc/1/comm', 'utf8').trim() === 'systemd', 'root_systemd_required');
  check(await property(UNIT, 'MainPID') === String(process.pid), 'exit_worker_requires_transient_unit');
  const context = await directExitLegacyContext(endpoint, uplink), original = privateJson(configFile);
  const config = validateDirectExitConfig(original, { endpoint, uplink, legacy: context.legacy });
  const packetSecret = fs.readFileSync(config.boring.peers[0].secret_path), relaySecret = fs.readFileSync(config.transparent.secret_path);
  try { check(packetSecret.length === 32 && relaySecret.length === 32 && !packetSecret.equals(relaySecret), 'separate_exit_relay_secret_required'); }
  finally { packetSecret.fill(0); relaySecret.fill(0); }
  privateOwnedDirectory(config.transparent.replay_directory);
  const owner = openNativeExitTrialNetwork(); let stopped = false, engine, result = { schema: 1, kind: 'clean-vpn-native-exit-trial', status: 'starting' };
  const stop = { requested: false }; for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stop.requested = true; });
  try {
    owner.assertAvailable(); const prepared = owner.prepare({ endpoint, uplink, port: 443 });
    config.boring.tun = prepared.tun; privateDirectory(SCRATCH);
    fs.writeFileSync(path.join(SCRATCH, 'exit.json'), JSON.stringify(config), { mode: 0o600, flag: 'wx' });
    await run(ENGINE, ['--check-config', path.join(SCRATCH, 'exit.json')]);
    check(await trialServiceFingerprint({ run, root: ROOT }) === context.fingerprint, 'legacy_exit_changed_before_stop');
    await run('systemctl', ['stop', OLD], 480000); stopped = true;
    check(await property(OLD, 'ActiveState') === 'inactive' && await property(OLD, 'MainPID') === '0', 'legacy_exit_stop_failed');
    check(!JSON.parse(await run('ip', ['-j', 'link', 'show'])).some(link => link.ifname === 'tun0'), 'legacy_exit_tun_remains');
    check(!(await run('ss', ['-H', '-ltn', 'sport = :443'])).trim(), 'exit_port_still_busy');
    owner.install(); engine = engineProcess(path.join(SCRATCH, 'exit.json')); await waitListener(endpoint, 443, engine);
    result = { ...result, status: 'ready', endpoint, port: 443, uplink, tun: prepared.tun,
      deadline: new Date(Date.now() + holdSeconds * 1000).toISOString(), legacyStopped: true, foreignFirewallPreserved: true };
    writeStatus(result);
    const deadline = performance.now() + holdSeconds * 1000;
    while (!stop.requested && performance.now() < deadline) { check(engine.healthy(), 'native_exit_failed'); await delay(250); }
    result.stopReason = stop.requested ? 'requested' : 'deadline';
  } catch (error) { result = { ...result, status: 'failed', code: safe(error) }; }
  finally {
    try { await engine?.stop(); } catch (error) { result.status = 'failed'; result.cleanup = safe(error); }
    try { if (owner.state?.stage !== 'released') owner.restore(); } catch (error) { result.status = 'failed'; result.cleanup = safe(error); }
    owner.release();
    try { fs.unlinkSync(path.join(SCRATCH, 'exit.json')); fs.rmdirSync(SCRATCH); } catch (error) { if (error.code !== 'ENOENT') result.cleanup = 'scratch_cleanup_failed'; }
    if (stopped) try {
      check(await trialServiceFingerprint({ run, root: ROOT }) === context.fingerprint, 'legacy_exit_changed_during_trial');
      await run('systemctl', ['start', OLD], 90000); check(await property(OLD, 'ActiveState') === 'active', 'legacy_exit_restore_failed');
      result.legacyRestored = true;
    } catch (error) { result.status = 'failed'; result.legacyRestored = false; result.restore = safe(error); }
    if (result.status === 'ready') result.status = 'completed'; writeStatus({ ...result, engine: engine?.summary() ?? null });
  }
  process.exitCode = result.status === 'completed' ? 0 : 1;
}
async function recover() {
  check(process.getuid?.() === 0, 'root_required');
  const state = await unitState(UNIT);
  check(exitRecoveryAllowed(state, process.env.INVOCATION_ID), 'exit_trial_still_active');
  const owner = openNativeExitTrialNetwork();
  try { if (owner.state && owner.state.stage !== 'released') owner.restore(); else owner.assertAvailable(); }
  finally { owner.release(); }
  try { fs.unlinkSync(path.join(SCRATCH, 'exit.json')); fs.rmdirSync(SCRATCH); } catch (error) { if (error.code !== 'ENOENT' && error.code !== 'ENOTEMPTY') throw error; }
  if (await property(OLD, 'ActiveState') !== 'active') await run('systemctl', ['start', OLD], 90000);
  check(await property(OLD, 'ActiveState') === 'active', 'legacy_exit_recovery_failed');
}
export function exitRecoveryAllowed(state, invocationId = '') {
  // During ExecStopPost, systemd versions differ in whether ActiveState is
  // deactivating or failed.  SubState + the per-invocation credential is the
  // stable identity; manual recovery is allowed only after the unit is idle.
  const stopPost = state.SubState === 'stop-post' && state.MainPID === '0'
    && !!invocationId && invocationId === state.InvocationID;
  return stopPost || state.MainPID === '0' && ['inactive', 'failed'].includes(state.ActiveState);
}
export function exitTrialUnitArgs({ node, script, config, endpoint, uplink, holdSeconds }) {
  for (const value of [node, script, config]) check(path.isAbsolute(value) && !/\s/.test(value), 'safe_absolute_unit_path_required');
  return ['--quiet', '--collect', '--unit=clean-vpn-native-exit-trial', '--service-type=exec', '--property=KillMode=control-group',
    '--property=TimeoutStopSec=120', `--property=RuntimeMaxSec=${holdSeconds + 180}`,
    `--property=ExecStopPost=${node} ${script} --recover`, '--property=StandardOutput=null', '--property=StandardError=null',
    `--working-directory=${ROOT}`, node, script, '--worker', `--config=${config}`, `--endpoint=${endpoint}`, `--uplink=${uplink}`, `--hold-seconds=${holdSeconds}`];
}
async function main(args = process.argv.slice(2)) {
  if (args.length === 1 && args[0] === '--help') {
    console.log('Usage: sudo node scripts/clean-vpn-native-exit-trial.mjs --preflight|--apply --config=/absolute/private-combo-exit.json --endpoint=154.62.226.216 --uplink=eth0 [--hold-seconds=60..1800]\n       sudo node scripts/clean-vpn-native-exit-trial.mjs --status | --stop | --recover\nTransient only: stops/restores clean-vpn.service, owns a random TUN and exact scoped firewall rules; independent ExecStopPost recovery.'); return;
  }
  if (args.length === 1 && args[0] === '--status') { privateDirectory(REPORT_DIR); console.log(fs.readFileSync(path.join(REPORT_DIR, 'status.json'), 'utf8')); return; }
  if (args.length === 1 && args[0] === '--stop') { await run('systemctl', ['stop', UNIT], 150000); return; }
  if (args.length === 1 && args[0] === '--recover') return recover();
  const values = new Map(); for (const arg of args.slice(1)) { const match = /^--(config|endpoint|uplink|hold-seconds)=(.+)$/.exec(arg);
    check(match && !values.has(match[1]), 'invalid_exit_trial_option'); values.set(match[1], match[2]); }
  check(['--preflight', '--apply', '--worker'].includes(args[0]), 'invalid_exit_trial_mode');
  const config = values.get('config'), endpoint = values.get('endpoint'), uplink = values.get('uplink');
  const holdSeconds = Number(values.get('hold-seconds') ?? '900');
  check(path.isAbsolute(config ?? '') && isIPv4(endpoint ?? '') && /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(uplink ?? '')
    && Number.isInteger(holdSeconds) && holdSeconds >= 60 && holdSeconds <= 1800, 'invalid_exit_trial_arguments');
  if (args[0] === '--preflight') { console.log(JSON.stringify(await preflight(config, endpoint, uplink), null, 2)); return; }
  if (args[0] === '--worker') return worker(config, endpoint, uplink, holdSeconds);
  check(process.getuid?.() === 0, 'root_required');
  check(!['active', 'activating', 'deactivating', 'reloading'].includes((await unitState(UNIT)).ActiveState), 'exit_trial_already_running');
  const readiness = await preflight(config, endpoint, uplink);
  check(readiness.status === 'ready-for-bounded-transient-trial', 'exit_preflight_blocked');
  privateDirectory(REPORT_DIR); writeStatus({ schema: 1, kind: 'clean-vpn-native-exit-trial', status: 'launching' });
  await run('systemd-run', exitTrialUnitArgs({ node: process.execPath, script: SELF, config, endpoint, uplink, holdSeconds }));
  const deadline = performance.now() + 30000;
  while (performance.now() < deadline) {
    const status = JSON.parse(fs.readFileSync(path.join(REPORT_DIR, 'status.json'), 'utf8'));
    if (status.status === 'ready') { console.log(JSON.stringify(status, null, 2)); return; }
    if (status.status === 'failed') throw Error(status.code ?? 'exit_trial_failed'); await delay(250);
  }
  throw Error('exit_trial_start_timeout');
}
const entryFile = import.meta.main === true
  // Some test/container runtimes execute a copied module through a mount alias,
  // so import.meta.url is not guaranteed to retain the operator-facing name.
  || process.argv[1] && path.basename(process.argv[1]) === 'clean-vpn-native-exit-trial.mjs';
if (entryFile)
  main().catch(error => { console.error(JSON.stringify({ status: 'refused-or-incomplete', code: safe(error),
    note: 'Do not flush firewall or delete journals. Use --status; if the transient unit is inactive, use --recover.' })); process.exitCode = 1; });

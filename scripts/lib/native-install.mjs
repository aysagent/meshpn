// Fresh native-only installation. No activation, route/firewall changes or
// systemctl calls; activation is an explicit subsequent operation.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { nativeServiceUnit } from './native-service-unit.mjs';
import { nativeSitePlan, nativeSiteSources } from './native-site-plan.mjs';
import { fileURLToPath } from 'node:url';
const hash = b => createHash('sha256').update(b).digest('hex');
const need = (v, code) => { if (!v) throw Error(code); };
const safePath = p => need(typeof p === 'string' && /^\/[\w./-]*$/.test(p) && path.normalize(p) === p, 'unsafe_path');
function trustedParents(p) {
  // The filesystem root can have a mapped UID in a user namespace/sandbox.
  const rootOwner = fs.statSync('/').uid;
  for (let parent = path.dirname(p); ; parent = path.dirname(parent)) {
    const s = fs.lstatSync(parent);
    need(s.isDirectory() && !s.isSymbolicLink() && [rootOwner, process.getuid()].includes(s.uid) &&
      (!(s.mode & 0o022) || (s.mode & 0o1000)), 'unsafe_parent');
    if (parent === '/') break;
  }
}
function regular(p, limit, secret = false) {
  safePath(p); need(fs.realpathSync(p) === p, 'symlink_source');
  trustedParents(p);
  const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const s = fs.fstatSync(fd);
    need(s.isFile() && s.uid === process.getuid() && !(s.mode & (secret ? 0o077 : 0o022)) && s.size <= limit, 'unsafe_source');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}
function directory(p, create = false, boundary = p) {
  if (p !== boundary) directory(path.dirname(p), create, boundary);
  if (!fs.existsSync(p) && create) fs.mkdirSync(p, { mode: 0o755 });
  const s = fs.lstatSync(p);
  need(s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && !(s.mode & 0o022), 'unsafe_destination');
  need(fs.realpathSync(p) === p, 'symlink_destination');
}
const exists = p => { try { fs.lstatSync(p); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
function syncDirectory(p) { const fd = fs.openSync(p, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function exclusive(p, data, mode) {
  const fd = fs.openSync(p, 'wx', mode);
  try { fs.fchmodSync(fd, mode); fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
export function installNative({ root = '/', name, binary, config, networkUnit, guardUnit, siteProfile, apply = false }, { fault = () => {} } = {}) {
  need(typeof apply === 'boolean', 'invalid_apply');
  safePath(root);
  need(/^[a-z][a-z0-9-]{0,31}$/.test(name ?? ''), 'invalid_instance');
  directory(root); trustedParents(root);
  const target = '/opt/clean-vpn-native/' + name;
  const unitName = `native-${name}.service`;
  need(![networkUnit, guardUnit].includes(unitName), 'self_dependency');
  const engine = regular(binary, 64 * 1024 * 1024);
  const input = JSON.parse(regular(config, 16384));
  const transparent = input.transport === 'transparent-tls';
  const combo = input.transport === 'combo-tls', relay = combo ? input.transparent : input;
  need(!(transparent || combo) || siteProfile, combo ? 'combo_requires_bound_site_profile' : 'transparent_requires_bound_site_profile');
  if ((transparent || combo) && input.role === 'exit') {
    safePath(relay?.replay_directory);
    need(!exists(relay.replay_directory), 'fresh_replay_source_must_not_exist');
  }
  const capability = JSON.parse(execFileSync(binary, ['--capabilities'], { encoding: 'utf8', timeout: 5000, maxBuffer: 16384 }));
  need(capability.engine === 'clean-vpn-native-m1' && capability.packet_ipc === false && capability.service_mode === true, 'not_native_service_engine');
  execFileSync(binary, ['--check-config', config], { timeout: 10000, stdio: 'pipe', maxBuffer: 16384 });
  need(!siteProfile || (networkUnit === undefined && guardUnit === undefined), 'conflicting_site_dependencies');
  const site = siteProfile ? nativeSitePlan({ name, target, site: JSON.parse(regular(siteProfile, 16384, true)), engine: input, capability }) : null;
  const units = site?.units ?? new Map([[unitName, nativeServiceUnit({ binary: target + '/engine', config: target + '/config.json', networkUnit, guardUnit })]]);
  const unit = units.get(unitName);
  const at = p => path.join(root, p);
  const unitPath = at('/etc/systemd/system/' + unitName), bundle = at(target);
  const preparedUnit = at('/etc/systemd/system/.' + unitName + '.prepared');
  for (const published of units.keys()) {
    for (const dir of ['/etc/systemd/system', '/run/systemd/system', '/run/systemd/transient', '/run/systemd/generator', '/run/systemd/generator.early', '/run/systemd/generator.late', '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'])
      for (const suffix of ['', '.d']) need(!exists(at(dir + '/' + published + suffix)), 'instance_already_present');
    need(!exists(at('/etc/systemd/system/.' + published + '.prepared')), 'instance_already_present');
    need(!exists(at('/etc/systemd/system/multi-user.target.wants/' + published)), 'instance_already_present');
  }
  // Do not accept an already enabled/overridden/masked or partially installed instance.
  for (const p of [bundle, unitPath, preparedUnit, unitPath + '.d', at('/etc/systemd/system/multi-user.target.wants/' + unitName)])
    need(!exists(p), 'instance_already_present');
  // Do not shadow a vendor/runtime unit or inherit an existing instance override.
  for (const dir of ['/run/systemd/system', '/run/systemd/transient', '/run/systemd/generator',
    '/run/systemd/generator.early', '/run/systemd/generator.late', '/usr/local/lib/systemd/system',
    '/usr/lib/systemd/system', '/lib/systemd/system']) {
    for (const suffix of ['', '.d']) need(!exists(at(dir + '/' + unitName + suffix)), 'instance_already_present');
  }
  for (const p of ['/etc/systemd/system', '/opt']) directory(at(p), false, root);
  const dependencies = Object.fromEntries((site?.dependencies ?? [networkUnit, guardUnit]).map(dep =>
    [dep, hash(regular(at('/etc/systemd/system/' + dep), 65536))]));
  const files = new Map([['engine', { bytes: engine, mode: 0o755 }]]);
  const rewritten = structuredClone(input);
  const packetInput = combo ? input.boring : input, packetOutput = combo ? rewritten.boring : rewritten;
  const relayOutput = combo ? rewritten.transparent : rewritten;
  const copy = (source, name, secret) => {
    const bytes = regular(source, secret && name.endsWith('.psk') ? 32 : 1024 * 1024, secret);
    files.set(name, { bytes, mode: secret ? 0o600 : 0o644 }); return target + '/' + name;
  };
  if (!transparent) {
    if (input.role === 'client') packetOutput.ca = copy(packetInput.ca, 'ca.pem', false);
    else { packetOutput.cert = copy(packetInput.cert, 'cert.pem', false); packetOutput.key = copy(packetInput.key, 'private.pem', true); }
  }
  const replay = (transparent || combo) && input.role === 'exit';
  if (replay) relayOutput.replay_directory = target + '/replay';
  if (packetInput.secret_path) packetOutput.secret_path = copy(packetInput.secret_path, 'peer.psk', true);
  if (packetInput.peers) packetOutput.peers = packetInput.peers.map((peer, i) => ({ ipv4: peer.ipv4, secret_path: copy(peer.secret_path, `peer-${i}.psk`, true) }));
  if (combo) relayOutput.secret_path = copy(relay.secret_path, 'relay.psk', true);
  files.set('config.json', { bytes: Buffer.from(JSON.stringify(rewritten) + '\n'), mode: 0o600 });
  files.set('service.unit', { bytes: Buffer.from(unit), mode: 0o644 });
  if (site) {
    for (const [name, body] of site.files) files.set(name, { bytes: Buffer.from(body), mode: 0o600 });
    for (const name of nativeSiteSources) files.set('control/' + name, { bytes: regular(fileURLToPath(new URL('../' + name, import.meta.url)), 128 * 1024), mode: 0o644 });
    for (const [name, body] of units) files.set('units/' + name, { bytes: Buffer.from(body), mode: 0o644 });
  }
  const manifest = { schema: 1, kind: 'clean-vpn-native-install', name, role: input.role, unit: unitName,
    transport: combo ? 'combo-tls' : transparent ? 'transparent-tls' : 'boring-tls',
    mutableDirectories: replay ? [{ name: 'replay', mode: 0o700, purpose: 'durable-replay-no-automatic-reset' }] : [],
    networkUnit, guardUnit, dependencies, activation: site?.activation ?? unitName,
    units: [...units.keys()], files: [...files].map(([name, f]) => ({ name, mode: f.mode, sha256: hash(f.bytes) })) };
  if (!apply) return { status: 'eligible', unit: unitName, target, fileCount: files.size, activation: 'not-requested' };
  directory(at('/opt/clean-vpn-native'), true, root);
  fs.mkdirSync(bundle, { mode: 0o700 }); // exclusive ownership; incomplete bundles are retained, never adopted
  syncDirectory(path.dirname(bundle));
  exclusive(bundle + '/prepared.json', JSON.stringify(manifest) + '\n', 0o600);
  fault('prepared');
  for (const [name, f] of files) {
    fs.mkdirSync(path.dirname(bundle + '/' + name), { recursive: true, mode: 0o700 });
    exclusive(bundle + '/' + name, f.bytes, f.mode); syncDirectory(path.dirname(bundle + '/' + name));
  }
  syncDirectory(bundle); fault('files');
  if (replay) {
    // Fresh bundle only. Runtime NEVER initializes a missing replay journal.
    fs.mkdirSync(bundle + '/replay', { mode: 0o700 }); syncDirectory(bundle);
    const initPath = bundle + '/replay-init.json';
    // Alternate root is a test/install staging root, not a chroot. Use actual
    // owned paths for initialization; published config keeps deployment paths.
    const initConfig = structuredClone(rewritten), initRelay = combo ? initConfig.transparent : initConfig;
    initRelay.secret_path = at(initRelay.secret_path); initRelay.replay_directory = bundle + '/replay';
    if (combo) {
      for (const key of ['cert', 'key']) initConfig.boring[key] = at(initConfig.boring[key]);
      if (initConfig.boring.secret_path) initConfig.boring.secret_path = at(initConfig.boring.secret_path);
      if (initConfig.boring.peers) initConfig.boring.peers = initConfig.boring.peers.map(p => ({ ...p, secret_path: at(p.secret_path) }));
    }
    exclusive(initPath, JSON.stringify(initConfig), 0o600);
    syncDirectory(bundle); fault('replay-prepared');
    execFileSync(bundle + '/engine', ['--init-transparent-replay', initPath], { timeout: 10000, stdio: 'pipe', maxBuffer: 16384 });
    fault('replay-initialized');
    fs.unlinkSync(initPath); syncDirectory(bundle);
  }
  // Unit publication is a single no-replace link. All files precede it durably.
  // Dependencies publish first and the activation target last. All are disabled.
  // A crash leaves an inspectable partial bundle, never an adoptable install.
  for (const [published, body] of units) {
    const prepared = at('/etc/systemd/system/.' + published + '.prepared'), final = at('/etc/systemd/system/' + published);
    exclusive(prepared, body, 0o644); syncDirectory(path.dirname(final));
    fs.linkSync(prepared, final); syncDirectory(path.dirname(final));
    fault('unit:' + published);
  }
  fault('published');
  exclusive(bundle + '/installed.json', JSON.stringify(manifest) + '\n', 0o600); syncDirectory(bundle);
  return { status: 'installed-disabled', unit: unitName, target, activation: 'not-requested',
    activation: site?.activation ?? unitName,
    next: 'Review external network dependencies before explicit daemon-reload and enable/start of activation unit.' };
}

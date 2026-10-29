#!/usr/bin/env node
// Narrow rootful Docker/Podman launcher. Does not install an engine, alter host
// DNS/routes, stop legacy services, or accept arbitrary container-run flags.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { isIPv4 } from 'node:net';
import { publishedExitPort } from './lib/native-port.mjs';
const { values: v, positionals } = parseArgs({ allowPositionals: true, options: Object.fromEntries([
  'engine', 'connection', 'name', 'image', 'role', 'network', 'ip', 'publish', 'config-dir', 'config-volume', 'config-file', 'lan-network', 'lan-ip', 'lan-subnet', 'lab-owner'
].map(k => [k, { type: 'string' }])) });
const action = positionals[0];
assert.ok(positionals.length === 1 && ['start', 'status', 'stop', 'remove'].includes(action), 'start|status|stop|remove required');
assert.ok(['docker', 'podman'].includes(v.engine ?? 'podman'));
const cli = [v.engine ?? 'podman'];
if (v.connection) { assert.equal(cli[0], 'podman'); cli.push('--connection', v.connection); }
const p = args => execFileSync(cli[0], [...cli.slice(1), ...args], { encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
assert.match(v.name ?? '', /^cvpn(?:rt)?-[a-zA-Z0-9][a-zA-Z0-9_.-]{0,55}$/, 'name must start cvpn- or cvpnrt-');
const inspect = () => JSON.parse(p(['inspect', v.name]))[0];
const owned = () => { const c = inspect(); assert.equal(c.Config.Labels?.['org.meshpn.native-runtime'], '1', 'foreign_container_refused'); return c; };
if (action === 'start') {
  assert.ok(v.image && ['client', 'exit'].includes(v.role), '--image and --role required');
  assert.match(v.network ?? '', /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/);
  assert.ok(!['host', 'none'].includes(v.network), 'dedicated_bridge_required');
  assert.ok(Boolean(v['config-dir']) !== Boolean(v['config-volume']), 'one_config_source_required');
  if (v.ip) assert.ok(isIPv4(v.ip));
  if (v.publish) assert.ok(v.role === 'exit' && /^[1-9][0-9]{0,4}$/.test(v.publish) && Number(v.publish) <= 65535);
  const file = v['config-file'] ?? 'engine.json'; assert.match(file, /^[a-zA-Z0-9_-]+\.json$/);
  let mount, config;
  if (v['config-dir']) {
    const dir = fs.realpathSync(v['config-dir']); assert.ok(path.isAbsolute(dir) && !dir.includes(',') && !dir.includes(':'));
    config = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
    mount = `type=bind,src=${dir},dst=/config,readonly`;
  } else {
    assert.match(v['config-volume'], /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/);
    p(['volume', 'inspect', v['config-volume']]); mount = `type=volume,src=${v['config-volume']},dst=/config,readonly`;
  }
  const info = JSON.parse(p(['info', '--format={{json .}}']));
  assert.ok(cli[0] === 'podman' ? info.host?.security?.rootless === false : !(info.SecurityOptions ?? []).some(s => s.includes('rootless')), 'rootful_engine_required');
  config ??= JSON.parse(p(['run', '--rm', '--network=none', '--cap-drop=ALL', '--read-only',
    '--memory=32m', '--pids-limit=16', '--mount', mount, '--entrypoint=cat', v.image, '/config/' + file]));
  assert.equal(config.role, v.role, 'config_role_mismatch');
  const published = v.publish ? publishedExitPort(config, v.publish) : null;
  const parent = p(['run', '--rm', '--network=host', '--cap-drop=ALL', '--entrypoint=readlink', v.image, '/proc/self/ns/net']).trim();
  assert.match(parent, /^net:\[\d+\]$/);
  const lan = Boolean(v['lan-network'] || v['lan-ip'] || v['lan-subnet']);
  if (lan) {
    assert.equal(v.role, 'client'); assert.match(v['lan-network'] ?? '', /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/);
    assert.ok(!['host', 'none', v.network].includes(v['lan-network'])); assert.ok(isIPv4(v['lan-ip']));
    assert.match(v['lan-subnet'] ?? '', /^192\.168\.\d+\.\d+\/(?:1[6-9]|2[0-9]|30)$/);
  }
  const args = ['create', '--name', v.name, '--label=org.meshpn.native-runtime=1', '--restart=no', '--network', v.network,
    '--memory=256m', '--pids-limit=128',
    '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--cap-add=NET_BIND_SERVICE', '--device=/dev/net/tun',
    '--security-opt=no-new-privileges', '--read-only', '--tmpfs=/run:rw,nosuid,nodev,mode=755', '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777',
    '--mount', mount, '-e', `CVPN_PARENT_NETNS=${parent}`];
  if (v.ip) args.push('--ip', v.ip);
  if (v['lab-owner']) {
    assert.match(v['lab-owner'], /^cvpnrt-[a-f0-9]{16}$/); assert.ok(v.name.startsWith(v['lab-owner'] + '-'));
    args.push('--label', 'org.meshpn.native-runtime-lab=' + v['lab-owner']);
  }
  if (v.role === 'exit' || lan) args.push('--sysctl=net.ipv4.ip_forward=1');
  if (published) args.push('--publish', published);
  if (lan) args.push('-e', 'CVPN_UPLINK=auto', '-e', 'CVPN_LAN_INTERFACE=auto', '-e', `CVPN_LAN_SUBNET=${v['lan-subnet']}`);
  args.push(v.image, '/config/' + file);
  p(args);
  // A failed create/start leaves an owned stopped container for inspection.
  // Never remove a similarly named foreign container to make a retry work.
  if (lan) p(['network', 'connect', '--ip', v['lan-ip'], v['lan-network'], v.name]);
  const c = owned(); assert.equal(c.HostConfig.Privileged, false); assert.notEqual(c.HostConfig.NetworkMode, 'host');
  console.log(p(['start', v.name]).trim()); console.log('Started; wait for healthy before attaching applications.');
} else if (action === 'status') {
  const c = owned(); console.log(JSON.stringify({ name: v.name, running: c.State.Running, exitCode: c.State.ExitCode,
    health: c.State.Health?.Status ?? c.State.Healthcheck?.Status ?? 'unknown' }, null, 2));
} else {
  owned(); p(['stop', '--time=5', v.name]);
  if (action === 'remove') p(['rm', v.name]);
  console.log(`NATIVE_CONTAINER=${action}`);
}

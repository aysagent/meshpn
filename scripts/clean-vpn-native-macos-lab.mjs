#!/usr/bin/env node
/** Reproducible Linux x86-64 native lab entry point for Apple Silicon macOS. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  nativeMacLabContainerAction, nativeMacLabImageTag, nativeMacLabMachineInitArgs,
  parseNativeMacLabArgs,
} from './lib/native-macos-lab.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const containerfile = path.join(root, 'scripts/containers/clean-vpn-native-lab.Containerfile');
const machineConfig = path.join(root, 'scripts/containers/clean-vpn-native-lab-containers.conf');

function invoke(args, { capture = false, allowFailure = false, env = process.env } = {}) {
  const result = spawnSync('podman', args, {
    cwd: root,
    encoding: capture ? 'utf8' : undefined,
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    timeout: 45 * 60 * 1000,
    env,
  });
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) throw new Error(`podman command failed (${result.status}): ${args.slice(0, 4).join(' ')}`);
  return result;
}

function machines() {
  const result = invoke(['machine', 'list', '--format=json'], { capture: true });
  return JSON.parse(result.stdout);
}

function machineState(name) {
  const machine = machines().find(item => item.Name === name);
  return machine ? (machine.Running ? 'running' : machine.Starting ? 'starting' : 'stopped') : 'absent';
}

function waitForConnection(connection) {
  for (let attempt = 0; attempt < 30; attempt++) {
    const result = invoke(['--connection', connection, 'info', '--format={{.Host.OS}}/{{.Host.Arch}}'], { capture: true, allowFailure: true });
    if (result.status === 0 && result.stdout.trim() === 'linux/arm64') return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  throw new Error(`Podman connection did not become ready: ${connection}`);
}

function ensureMachine(name) {
  let state = machineState(name);
  if (state === 'absent') {
    console.error(`Creating dedicated Podman machine ${name} (6 CPUs, 6 GiB RAM, 100 GiB sparse disk)`);
    invoke(nativeMacLabMachineInitArgs(name), { env: { ...process.env, CONTAINERS_CONF: machineConfig } });
    state = 'stopped';
  }
  if (state !== 'running') {
    console.error(`Starting Podman machine ${name}`);
    let result = invoke(['machine', 'start', name], { allowFailure: true });
    // Podman itself removes a stale gvproxy socket after this specific failed
    // start. A single normal retry is safer than deleting runtime files here.
    if (result.status !== 0) result = invoke(['machine', 'start', name], { allowFailure: true });
    assert.equal(result.status, 0, `unable to start Podman machine ${name}`);
  }
  const connection = `${name}-root`;
  waitForConnection(connection);
  const amd64 = invoke(['--connection', connection, 'run', '--rm', '--platform=linux/amd64',
    'docker.io/library/ubuntu:24.04', '/bin/sh', '-c', 'test "$(uname -m)" = x86_64 && printf amd64-shell-ok'],
  { capture: true, allowFailure: true });
  assert.ok(amd64.status === 0 && amd64.stdout.includes('amd64-shell-ok'),
    `Podman machine ${name} cannot execute amd64 Linux binaries`);
  return connection;
}

function usage() {
  console.log(`Usage:
  npm run lab:native:mac -- --prepare
  npm run lab:native:mac -- --multi-clients
  npm run lab:native:mac -- --native-combo-boot
  npm run lab:native:mac -- --native-combo-network
  npm run lab:native:mac -- --native-combo-load
  npm run lab:native:mac -- --native-combo-benchmark
  npm run lab:native:mac -- --status | --stop

Options: --machine=NAME, --rebuild-image, --refresh-base
The first run creates a dedicated Podman VM and cached Linux x86-64 toolchain.
All QEMU guests are NIC-less; no host TUN, route or firewall is changed.`);
}

function main() {
  assert.equal(process.platform, 'darwin', 'this wrapper is only for macOS; run clean-vpn-native-lab.mjs directly on Linux');
  const options = parseNativeMacLabArgs(process.argv.slice(2));
  if (options.action === '--help') { usage(); return; }
  const state = machineState(options.machine);
  if (options.action === '--stop') {
    if (state === 'running' || state === 'starting') invoke(['machine', 'stop', options.machine]);
    console.log(JSON.stringify({ status: 'stopped', machine: options.machine }));
    return;
  }
  if (options.action === '--status' && state !== 'running') {
    console.log(JSON.stringify({ status: 'unavailable', machine: options.machine, machineState: state, note: 'status does not start the VM' }, null, 2));
    return;
  }

  const connection = ensureMachine(options.machine);
  const recipe = fs.readFileSync(containerfile);
  const image = nativeMacLabImageTag(recipe);
  if (options.rebuildImage || invoke(['--connection', connection, 'image', 'exists', image], { allowFailure: true }).status !== 0) {
    console.error(`Building ${image} for linux/amd64 (first run only)`);
    invoke(['--connection', connection, 'build', '--platform=linux/amd64', '--file', containerfile, '--tag', image,
      path.dirname(containerfile)]);
  }

  const exportRoot = path.join(os.homedir(), 'Library/Caches/meshpn-clean-vpn-lab/results');
  fs.mkdirSync(exportRoot, { recursive: true, mode: 0o700 });
  const volume = 'meshpn-clean-vpn-lab-cache';
  const args = ['--connection', connection, 'run', '--rm', '--platform=linux/amd64',
    '--volume', `${root}:/source:ro`, '--volume', `${volume}:/lab`, '--volume', `${exportRoot}:/export`,
    '--env', `CVPN_REFRESH_BASE=${options.refreshBase ? '1' : '0'}`, image,
    'bash', '/source/scripts/clean-vpn-native-container-lab.sh', ...nativeMacLabContainerAction(options.action)];
  invoke(args);
}

try { main(); }
catch (error) {
  console.error(JSON.stringify({ status: 'failed', code: 'native_macos_lab_failed', message: error.message }));
  process.exitCode = 1;
}

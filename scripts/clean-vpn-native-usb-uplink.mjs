#!/usr/bin/env node
// Fault owner lives in its OWN transient systemd unit, not the trial cgroup.
// systemd also executes networkctl up via ExecStopPost even after SIGKILL.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const faultUnit = directory => `clean-vpn-native-usb-uplink-${path.basename(directory)}.service`;
export function faultUnitArgs(directory, node, script) {
  return ['--quiet', '--collect', `--unit=${faultUnit(directory)}`, '--service-type=exec',
    '--property=KillMode=control-group', '--property=RuntimeMaxSec=30', '--property=TimeoutStopSec=15',
    '--property=ExecStopPost=/usr/bin/networkctl up wlan0',
    '--property=StandardOutput=null', '--property=StandardError=null', node, script, directory];
}
async function command(file, args) {
  return await new Promise((resolve, reject) => {
    const child = spawn(file, args, { stdio: ['ignore', 'pipe', 'ignore'] });
    let out = '', failed = false;
    const timer = setTimeout(() => { failed = true; child.kill('SIGKILL'); }, 8000);
    child.stdout.on('data', b => { out += b; if (out.length > 4096) { failed = true; child.kill('SIGKILL'); } });
    child.on('error', () => { failed = true; });
    child.on('close', code => { clearTimeout(timer); if (failed || code !== 0) reject(Error('uplink_command_failed')); else resolve(out.trim()); });
  });
}
export async function runFault(directory, { run = command, hold = ms => new Promise(resolve => {
  const done = () => { clearTimeout(timer); process.off('SIGTERM', done); process.off('SIGINT', done); resolve(); };
  const timer = setTimeout(done, ms); process.once('SIGTERM', done); process.once('SIGINT', done);
}), mark = status => fs.writeFileSync(path.join(directory, 'uplink-fault.json'), JSON.stringify({ status }), { mode: 0o600 }) } = {}) {
  try { await run('/usr/bin/networkctl', ['down', 'wlan0']); mark('down'); await hold(20000); }
  finally { await run('/usr/bin/networkctl', ['up', 'wlan0']); mark('up'); }
}
async function main() {
  const directory = process.argv[2];
  if (process.argv.length !== 3 || process.getuid?.() !== 0 || path.dirname(directory) !== '/var/lib/clean-vpn-native-trial'
      || !/^run-[a-zA-Z0-9]+$/.test(path.basename(directory))) throw Error('invalid_fault_context');
  for (const dir of [path.dirname(directory), directory]) {
    const s = fs.lstatSync(dir);
    if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o777) !== 0o700) throw Error('invalid_fault_context');
  }
  if (await command('/usr/bin/systemctl', ['show', faultUnit(directory), '--property=MainPID', '--value']) !== String(process.pid))
    throw Error('fault_requires_owned_unit');
  await runFault(directory);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch(() => { process.exitCode = 1; });

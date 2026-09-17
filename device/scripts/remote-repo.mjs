#!/usr/bin/env node
// Server-side convenience command for the Mac checkout reached via -R tunnel.
import { spawn } from 'node:child_process';
import { quote } from './perf-lib.mjs';
import { inMacRepo, macUser, sshMacArgs } from './remote-mac.mjs';

const args = process.argv.slice(2);
if (!args.length) {
  console.error('Usage: npm run device:remote:repo -- COMMAND [ARG ...]  (Mac checkout: MESHPN_MAC_REPO_DIR)');
  process.exitCode = 2;
} else {
  try {
    const command = args.map(quote).join(' ');
    const child = spawn('ssh', [...sshMacArgs(macUser()), inMacRepo(command)], {stdio: 'inherit'});
    child.on('error', error => {console.error(error.message); process.exitCode = 1;});
    child.on('close', (code, signal) => {process.exitCode = signal ? 128 : code ?? 1;});
  } catch (error) { console.error(error.message); process.exitCode = 2; }
}

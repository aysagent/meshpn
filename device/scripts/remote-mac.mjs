import os from 'node:os';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { quote } from './perf-lib.mjs';

export const configFile = fileURLToPath(new URL('../.remote-mac.json', import.meta.url));
let config = {};
try { config = JSON.parse(readFileSync(configFile, 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw Error(`Invalid ${configFile}: ${error.message}`); }

export function macUser(value = process.env.MESHPN_MAC_SSH_USER || config.mac_user || os.userInfo().username) {
  if (!/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/.test(value)) throw Error('Invalid Mac SSH username');
  return value;
}
export function macRepo(value = process.env.MESHPN_MAC_REPO_DIR || config.repo_dir) {
  if (!value) return '"$HOME/dev/home/meshpn"';
  if (!value.startsWith('/') || /[\x00-\x1f]/.test(value)) throw Error('MESHPN_MAC_REPO_DIR must be an absolute path');
  return quote(value);
}
export function remotePort(value = process.env.MESHPN_REMOTE_PORT || config.port || '22022') {
  if (!/^\d+$/.test(value) || Number(value) < 1024 || Number(value) > 65535) throw Error('Invalid MESHPN_REMOTE_PORT');
  return value;
}
export function sshMacArgs(user = macUser()) {
  return ['-p', remotePort(), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
    '-o', 'ConnectionAttempts=1', '-o', 'HostKeyAlias=meshpn-mac-via-tunnel',
    '--', `${user}@127.0.0.1`];
}
export function inMacRepo(command) { return `cd -- ${macRepo()} && ${command}`; }
export function macJobParent() { return `${macRepo()}/device/perf-managed-results`; }
export function macJobDir(id) { return `${macJobParent()}/${id}`; }

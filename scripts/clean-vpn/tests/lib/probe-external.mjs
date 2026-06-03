import { execFileSync } from 'child_process';
import { PROBE_MARKER } from './probe-http.mjs';
import { findTunByLocalIp } from './tun-detect.mjs';

function execProbe(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 1024 * 1024 });
  } catch (e) {
    const err = /** @type {Error & { stderr?: string, stdout?: string }} */ (e);
    const detail = [err.stderr, err.stdout].filter(Boolean).join('\n').trim();
    throw new Error(detail ? `${err.message}\n${detail}` : err.message);
  }
}

/** @param {string} srcIp @param {string} dstIp */
export function probePing(srcIp, dstIp) {
  if (process.platform === 'darwin') {
    execProbe('ping', ['-c', '2', '-W', '5000', '-S', srcIp, dstIp]);
    return;
  }
  const tun = findTunByLocalIp(srcIp);
  if (!tun) throw new Error(`no TUN with local ${srcIp} for ping`);
  execProbe('ping', ['-I', tun, '-c', '3', '-W', '2', dstIp]);
}

/** @param {string} srcIp @param {string} host @param {number} port */
export function probeCurl(srcIp, host, port) {
  const url = `http://${host}:${port}/`;
  const args = ['-4', '--max-time', '8', '-fS', url];
  if (process.platform === 'darwin') {
    args.splice(1, 0, '--interface', srcIp);
  } else {
    const tun = findTunByLocalIp(srcIp);
    if (!tun) throw new Error(`no TUN with local ${srcIp} for curl`);
    args.splice(1, 0, '--interface', tun);
  }
  const body = execProbe('curl', args);
  if (!body.includes(PROBE_MARKER)) {
    throw new Error(`curl body missing marker from ${url}`);
  }
}

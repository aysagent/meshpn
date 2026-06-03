import { execFileSync } from 'node:child_process';
import http from 'node:http';
import { IP_CLIENT, IP_EXIT } from './clean-vpn-platform/constants.mjs';

export const PROBE_MARKER = 'clean-vpn-test-ok';
export const PROBE_EXIT_PORT = 18080;
export const PROBE_CLIENT_PORT = 18081;

/** @type {(() => void) | null} */
let clientWireReadyHook = null;
/** @type {(() => void) | null} */
let exitBridgeReadyHook = null;

/** @type {{ pingPeer?: (peerIp: string) => Promise<string>, httpGetPeer?: (peerIp: string, port: number) => Promise<string> } | null} */
let bridgeApi = null;

export function registerTransportTestBridgeApi(api) {
  bridgeApi = api;
}

export function setTransportTestClientWireHook(fn) {
  clientWireReadyHook = fn;
}

export function setTransportTestExitBridgeHook(fn) {
  exitBridgeReadyHook = fn;
}

export function notifyTransportTestClientWireReady() {
  clientWireReadyHook?.();
}

export function notifyTransportTestExitBridgeReady() {
  exitBridgeReadyHook?.();
}

/**
 * @param {string} host
 * @param {number} port
 */
export function startProbeHttpServer(_host, port) {
  const srv = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(PROBE_MARKER);
  });
  return new Promise((resolve, reject) => {
    srv.once('error', reject);
    // 0.0.0.0: in-process TCP-proxy ходит на 127.0.0.1 (10.99.0.x на utun с macOS не connect'ится).
    srv.listen(port, '0.0.0.0', () => resolve(srv));
  });
}

function execCapture(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 1024 * 1024 }).trim();
  } catch (e) {
    const err = /** @type {Error & { stderr?: string, stdout?: string }} */ (e);
    const detail = [err.stderr, err.stdout].filter(Boolean).join('\n').trim();
    throw new Error(detail ? `${err.message}\n${detail}` : err.message);
  }
}

/**
 * HTTP probe через TUN: curl привязан к utun/tun (не только localAddress).
 * @param {string} srcIp
 * @param {string} host
 * @param {number} port
 * @param {string} ifname
 */
export function probeHttpViaTun(srcIp, host, port, ifname) {
  const url = `http://${host}:${port}/`;
  /** @type {string[]} */
  const args = ['-4', '--max-time', '10', '-fS', '--interface', ifname, url];
  const body = execCapture('curl', args);
  if (!body.includes(PROBE_MARKER)) {
    throw new Error(`missing marker from ${url}`);
  }
  return `${srcIp}@${ifname} → ${url} (${PROBE_MARKER})`;
}

/** @param {string} pingOut */
function summarizePing(pingOut) {
  const lines = pingOut.trim().split('\n').filter(Boolean);
  const stats = lines.find((l) => /packets transmitted/i.test(l));
  const rtt = lines.find((l) => /round-trip|rtt/i.test(l));
  if (stats && rtt) return `${stats.trim()}; ${rtt.trim()}`;
  if (stats) return stats.trim();
  return lines.slice(-2).join(' ').trim() || 'ok';
}

/**
 * @param {string} srcIp
 * @param {string} dstIp
 * @param {string} ifname
 */
export function probePingViaTun(srcIp, dstIp, ifname) {
  /** @type {string[]} */
  let args;
  if (process.platform === 'darwin') {
    args = ['-c', '2', '-W', '5000', '-b', ifname, '-S', srcIp, dstIp];
  } else {
    args = ['-I', ifname, '-c', '3', '-W', '2', dstIp];
  }
  const out = execCapture('ping', args);
  return `${srcIp}@${ifname} → ${dstIp}: ${summarizePing(out)}`;
}

function dirLabel(dir) {
  return dir === 'c2e' ? 'client→exit' : 'exit→client';
}

/**
 * @param {'curl'|'ping'} kind
 * @param {'c2e'|'e2c'} dir
 * @param {string} detail
 */
export function logTransportTestOk(kind, dir, detail) {
  console.log(`[clean-vpn] transport-test OK ${kind} ${dirLabel(dir)}: ${detail}`);
}

/**
 * @param {'curl'|'ping'} kind
 * @param {'c2e'|'e2c'} dir
 * @param {Error} err
 * @param {string[]} completed
 */
export function logTransportTestFail(kind, dir, err, completed) {
  const done =
    completed.length > 0
      ? `уже OK: ${completed.join(', ')}`
      : 'до этой проверки ничего не прошло';
  console.error(
    `[clean-vpn] transport-test FAIL ${kind} ${dirLabel(dir)} — ${done}\n${err.message}`,
  );
}

/**
 * @param {'client'|'exit'} role
 * @param {string} ifname
 */
export function createTransportTestContext(role, ifname) {
  /** @type {import('http').Server|null} */
  let probeSrv = null;
  let c2eStarted = false;
  let e2cStarted = false;

  const srcIp = role === 'exit' ? IP_EXIT : IP_CLIENT;
  const peerIp = role === 'exit' ? IP_CLIENT : IP_EXIT;
  const probePort = role === 'exit' ? PROBE_EXIT_PORT : PROBE_CLIENT_PORT;
  const peerPort = role === 'exit' ? PROBE_CLIENT_PORT : PROBE_EXIT_PORT;

  return {
    async startProbeServer() {
      probeSrv = await startProbeHttpServer(srcIp, probePort);
    },
    close() {
      probeSrv?.close();
      probeSrv = null;
    },
    scheduleC2e() {
      if (role !== 'client' || c2eStarted) return;
      c2eStarted = true;
      setTimeout(() => {
        void runProbes('c2e', srcIp, peerIp, ifname, peerPort);
      }, 800).unref?.();
    },
    scheduleE2c() {
      if (role !== 'exit' || e2cStarted) return;
      e2cStarted = true;
      // client wire чуть позже exit accept — даём время поднять обратный мост
      setTimeout(() => {
        void runProbes('e2c', srcIp, peerIp, ifname, peerPort);
      }, 2200).unref?.();
    },
  };
}

async function probePingPreferred(srcIp, peerIp, ifname) {
  if (bridgeApi?.pingPeer) return bridgeApi.pingPeer(peerIp);
  return probePingViaTun(srcIp, peerIp, ifname);
}

async function probeHttpPreferred(srcIp, peerIp, port, ifname) {
  if (bridgeApi?.httpGetPeer) return bridgeApi.httpGetPeer(peerIp, port);
  return probeHttpViaTun(srcIp, peerIp, port, ifname);
}

/**
 * @param {'c2e'|'e2c'} dir
 * @param {string} srcIp
 * @param {string} peerIp
 * @param {string} ifname
 * @param {number} peerHttpPort
 */
async function runProbes(dir, srcIp, peerIp, ifname, peerHttpPort) {
  /** @type {string[]} */
  const completed = [];
  /** @type {'ping'|'curl'|null} */
  let failedKind = null;
  /** @type {Error|null} */
  let failedErr = null;

  const steps = [
    {
      kind: /** @type {const} */ ('ping'),
      run: () => probePingPreferred(srcIp, peerIp, ifname),
    },
    {
      kind: /** @type {const} */ ('curl'),
      run: () => probeHttpPreferred(srcIp, peerIp, peerHttpPort, ifname),
    },
  ];

  for (const step of steps) {
    try {
      const detail = await step.run();
      logTransportTestOk(step.kind, dir, detail);
      completed.push(`${step.kind} ${dirLabel(dir)}`);
    } catch (e) {
      failedKind = step.kind;
      failedErr = e instanceof Error ? e : new Error(String(e));
      break;
    }
  }

  if (failedKind && failedErr) {
    logTransportTestFail(failedKind, dir, failedErr, completed);
  }
}

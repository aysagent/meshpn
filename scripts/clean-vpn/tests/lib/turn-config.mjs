import { execFileSync } from 'child_process';

/**
 * @param {string} turnHostPort — IP:PORT
 * @param {{ user?: string, secret?: string }} [auth]
 */
export function buildTurnIceConfig(turnHostPort, auth = {}) {
  const [host, portStr] = turnHostPort.split(':');
  const port = parseInt(portStr, 10);
  const user = auth.user || process.env.CLEAN_VPN_TEST_TURN_USER || 'test';
  const secret = auth.secret || process.env.CLEAN_VPN_TEST_TURN_SECRET || 'test';
  return {
    iceServers: [
      {
        urls: `turn:${host}:${port}`,
        username: user,
        credential: secret,
      },
    ],
  };
}

/**
 * @param {string} turnHostPort
 */
export function turnReachableSync(turnHostPort) {
  const [host, portStr] = turnHostPort.split(':');
  const port = parseInt(portStr, 10);
  if (!host || !Number.isFinite(port)) return false;
  try {
    execFileSync('nc', ['-z', '-u', '-w', '2', host, String(port)], { stdio: 'ignore' });
    return true;
  } catch {
    try {
      execFileSync('nc', ['-z', '-w', '2', host, String(port)], { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  }
}

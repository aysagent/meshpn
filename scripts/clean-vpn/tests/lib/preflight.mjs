import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(__dirname, '../../../../');
const cleanVpnJs = path.join(repoRoot, 'scripts/clean-vpn.js');
const boringHelper = path.join(repoRoot, 'native/boring_tls/build/boring-tls-helper');
const utunHelper = path.join(repoRoot, 'helpers/utun-helper');
const tunLinuxNode = path.join(repoRoot, 'native/tun_linux/build/Release/tun_linux.node');

/**
 * @param {{ skipTier3?: boolean, turn?: string|null }} opts
 */
export async function runPreflight(opts = {}) {
  const errors = [];
  const warnings = [];

  if (process.platform !== 'linux' && process.platform !== 'darwin') {
    errors.push(`unsupported platform ${process.platform}`);
  }
  if (process.getuid && process.getuid() !== 0) {
    errors.push('need root (sudo) for TUN');
  }
  if (!fs.existsSync(cleanVpnJs)) {
    errors.push(`missing ${cleanVpnJs}`);
  }
  if (process.platform === 'linux' && !fs.existsSync(tunLinuxNode)) {
    errors.push('missing tun_linux.node — npm run build:tun-linux');
  }
  if (process.platform === 'darwin' && !fs.existsSync(utunHelper)) {
    errors.push('missing utun-helper — cd helpers && make');
  }

  try {
    execFileSync('curl', ['--version'], { encoding: 'utf8' });
    if (process.platform !== 'darwin') {
      const cv = execFileSync('curl', ['--version'], { encoding: 'utf8' });
      if (!/--interface/.test(cv)) warnings.push('curl may lack --interface');
    }
  } catch {
    errors.push('curl not found');
  }

  try {
    execFileSync('ping', ['-c', '1', '127.0.0.1'], { stdio: 'ignore' });
  } catch {
    errors.push('ping failed');
  }

  if (opts.skipTier3) {
    warnings.push('SKIP_TIER3=1 — skipping chrome/webrtc tier');
  }

  if (opts.turn) {
    const { turnReachableSync } = await import('./turn-config.mjs');
    if (!turnReachableSync(opts.turn)) {
      warnings.push(`TURN ${opts.turn} not reachable — relay cases will skip`);
    }
  }

  return { ok: errors.length === 0, errors, warnings, boringHelperExists: fs.existsSync(boringHelper) };
}

export function ensureTlsFixtureDir() {
  const dir = path.join(__dirname, '../fixtures/tls-test');
  fs.mkdirSync(dir, { recursive: true });
  const ca = path.join(dir, 'ca.pem');
  if (!fs.existsSync(ca)) {
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        path.join(dir, 'key.pem'),
        '-out',
        ca,
        '-days',
        '3650',
        '-nodes',
        '-subj',
        '/CN=clean-vpn-test',
      ],
      { stdio: 'ignore' },
    );
    fs.copyFileSync(ca, path.join(dir, 'cert.pem'));
  }
  const hmac = path.join(dir, 'clean-vpn-hmac.key');
  if (!fs.existsSync(hmac)) {
    fs.writeFileSync(hmac, Buffer.alloc(32, 0x42));
  }
  return dir;
}

export { cleanVpnJs, repoRoot, boringHelper };

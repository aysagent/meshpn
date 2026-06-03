import { execFileSync } from 'child_process';
import { IP_CLIENT } from './constants.mjs';
import { getDefaultRouteLinux } from './net-linux.mjs';

function getSysctlNum(key) {
  try {
    const v = execFileSync('sysctl', ['-n', key], { encoding: 'utf8' }).trim();
    const n = parseInt(v, 10);
    return Number.isNaN(n) ? null : n;
  } catch {
    return null;
  }
}

function sysctlForward(on) {
  try {
    execFileSync('sysctl', [`net.ipv4.ip_forward=${on ? 1 : 0}`], { stdio: 'inherit' });
  } catch {
    console.warn('[clean-vpn] sysctl ip_forward не применён');
  }
}

/**
 * @param {string} tunName
 * @param {string|null|undefined} extIface
 */
export function setupExitNatLinux(tunName, extIface) {
  const prevIpForward = getSysctlNum('net.ipv4.ip_forward');
  sysctlForward(true);
  const ext = extIface || getDefaultRouteLinux()?.dev;
  if (!ext) throw new Error('Укажите --ext=eth0 или настройте default route');
  console.log(`[clean-vpn] NAT: ${tunName} -> ${ext} (MASQUERADE)`);
  execFileSync(
    'iptables',
    ['-t', 'nat', '-A', 'POSTROUTING', '-s', `${IP_CLIENT}/32`, '-o', ext, '-j', 'MASQUERADE'],
    { stdio: 'inherit' },
  );
  execFileSync('iptables', ['-A', 'FORWARD', '-i', tunName, '-o', ext, '-j', 'ACCEPT'], {
    stdio: 'inherit',
  });
  execFileSync(
    'iptables',
    [
      '-A',
      'FORWARD',
      '-i',
      ext,
      '-o',
      tunName,
      '-m',
      'conntrack',
      '--ctstate',
      'RELATED,ESTABLISHED',
      '-j',
      'ACCEPT',
    ],
    { stdio: 'inherit' },
  );
  return { ext, tunName, prevIpForward, skipped: false };
}

/**
 * @param {{ tunName: string, ext: string, prevIpForward?: number|null, skipped?: boolean }} nat
 */
export function teardownExitNatLinux(nat) {
  if (nat?.skipped) return;
  const { tunName, ext } = nat;
  try {
    execFileSync(
      'iptables',
      ['-t', 'nat', '-D', 'POSTROUTING', '-s', `${IP_CLIENT}/32`, '-o', ext, '-j', 'MASQUERADE'],
      { stdio: 'inherit' },
    );
  } catch {
    /* ignore */
  }
  try {
    execFileSync('iptables', ['-D', 'FORWARD', '-i', tunName, '-o', ext, '-j', 'ACCEPT'], {
      stdio: 'inherit',
    });
  } catch {
    /* ignore */
  }
  try {
    execFileSync(
      'iptables',
      [
        '-D',
        'FORWARD',
        '-i',
        ext,
        '-o',
        tunName,
        '-m',
        'conntrack',
        '--ctstate',
        'RELATED,ESTABLISHED',
        '-j',
        'ACCEPT',
      ],
      { stdio: 'inherit' },
    );
  } catch {
    /* ignore */
  }
}

export function restoreExitSysctlLinux(prevIpForward) {
  if (prevIpForward == null) return;
  try {
    execFileSync('sysctl', [`net.ipv4.ip_forward=${prevIpForward}`], { stdio: 'inherit' });
    console.log('[clean-vpn] exit: net.ipv4.ip_forward восстановлен');
  } catch {
    /* ignore */
  }
}

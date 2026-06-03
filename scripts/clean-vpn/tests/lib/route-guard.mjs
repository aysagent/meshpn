import { execFileSync } from 'child_process';

/** @returns {string} */
export function snapshotRoutesText() {
  if (process.platform === 'linux') {
    try {
      return execFileSync('ip', ['-4', 'route', 'show'], { encoding: 'utf8' });
    } catch {
      return '';
    }
  }
  if (process.platform === 'darwin') {
    try {
      return execFileSync('netstat', ['-rn'], { encoding: 'utf8' });
    } catch {
      return '';
    }
  }
  return '';
}

/** @returns {string} */
export function snapshotFirewallText() {
  if (process.platform !== 'linux') return '';
  try {
    return execFileSync('iptables-save', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch {
    return '';
  }
}

/**
 * @param {string} beforeRoutes
 * @param {string} afterRoutes
 * @param {string} beforeFw
 * @param {string} afterFw
 */
export function assertNoRoutingMutation(beforeRoutes, afterRoutes, beforeFw, afterFw) {
  const errors = [];
  if (process.platform === 'linux') {
    for (const dst of ['0.0.0.0/1', '128.0.0.0/1']) {
      const had = beforeRoutes.includes(dst);
      const has = afterRoutes.includes(dst);
      if (!had && has) errors.push(`split-default route appeared: ${dst}`);
    }
    const fwBefore = (beforeFw.match(/clean-vpn-ttl:/g) || []).length;
    const fwAfter = (afterFw.match(/clean-vpn-ttl:/g) || []).length;
    if (fwAfter > fwBefore) errors.push('transparent-tls iptables rules appeared');
  }
  if (process.platform === 'darwin') {
    const defBefore = /default.*utun/.test(beforeRoutes);
    const defAfter = /default.*utun/.test(afterRoutes);
    if (!defBefore && defAfter) errors.push('default route via utun appeared');
  }
  if (errors.length) {
    throw new Error(`route guard: ${errors.join('; ')}`);
  }
}

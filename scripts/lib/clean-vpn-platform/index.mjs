import { IP_CLIENT, IP_EXIT, TUN_MTU } from './constants.mjs';
import {
  defaultLoopbackExtDarwin,
  findFreeUtunName,
  getDefaultRouteDarwin,
  setupTunIpDarwin,
} from './net-darwin.mjs';
import {
  defaultLoopbackExtLinux,
  findFreeTunNameLinux,
  getDefaultRouteLinux,
  setupTunIpLinux,
} from './net-linux.mjs';
import {
  restoreExitSysctlDarwin,
  setupExitNatDarwin,
  teardownExitNatDarwin,
} from './nat-darwin.mjs';
import {
  restoreExitSysctlLinux,
  setupExitNatLinux,
  teardownExitNatLinux,
} from './nat-linux.mjs';
import { openTunDarwin, originalDstIpv4FromFdDarwin } from './tun-darwin.mjs';
import { openTunLinux, originalDstIpv4FromFdLinux, loadTunLinuxAddon } from './tun-linux.mjs';
import {
  setupClientRoutesDarwin,
  teardownClientRoutesDarwin,
} from './routes-darwin.mjs';

export { IP_CLIENT, IP_EXIT, TUN_MTU };
export { loadTunLinuxAddon };

/** @returns {'linux'|'darwin'} */
export function detectPlatform() {
  if (process.platform === 'darwin') return 'darwin';
  if (process.platform === 'linux') return 'linux';
  throw new Error(`clean-vpn: неподдерживаемая платформа ${process.platform} (нужен Linux или macOS)`);
}

export function isLinux() {
  return process.platform === 'linux';
}

export function isDarwin() {
  return process.platform === 'darwin';
}

export function isFirewallLinux() {
  return isLinux();
}

/**
 * @param {string} [preferredName]
 * @returns {Promise<{ tun: object, name: string }>|{ tun: object, name: string }}
 */
export function openTun(preferredName) {
  if (isDarwin()) {
    return openTunDarwin(preferredName ?? findFreeUtunName());
  }
  return openTunLinux(preferredName ?? findFreeTunNameLinux());
}

export function findFreeTunName() {
  return isDarwin() ? findFreeUtunName() : findFreeTunNameLinux();
}

/**
 * @param {'exit'|'client'} role
 * @param {string} ifname
 */
export function setupTunIp(role, ifname) {
  if (isDarwin()) setupTunIpDarwin(role, ifname);
  else setupTunIpLinux(role, ifname);
}

export function getDefaultRoute() {
  return isDarwin() ? getDefaultRouteDarwin() : getDefaultRouteLinux();
}

export function defaultLoopbackExt() {
  return isDarwin() ? defaultLoopbackExtDarwin() : defaultLoopbackExtLinux();
}

/**
 * @param {string} tunName
 * @param {string|null|undefined} extIface
 */
export function setupExitNat(tunName, extIface) {
  return isDarwin() ? setupExitNatDarwin(tunName, extIface) : setupExitNatLinux(tunName, extIface);
}

/** @param {{ tunName: string, ext: string, prevIpForward?: number|null, skipped?: boolean }} nat */
export function teardownExitNat(nat) {
  if (isDarwin()) teardownExitNatDarwin(nat);
  else teardownExitNatLinux(nat);
}

export function restoreExitSysctl(prevIpForward) {
  if (isDarwin()) restoreExitSysctlDarwin(prevIpForward);
  else restoreExitSysctlLinux(prevIpForward);
}

/**
 * Darwin-only minimal routes; on Linux clean-vpn.js keeps full implementation.
 * @param {string} ifname
 * @param {string} serverHost
 * @param {boolean} splitDefault
 * @param {object} opts
 */
export async function setupClientRoutesDarwinAsync(ifname, serverHost, splitDefault, opts) {
  return setupClientRoutesDarwin(ifname, serverHost, splitDefault, opts);
}

export function teardownClientRoutesDarwinOnly(ctx) {
  teardownClientRoutesDarwin(ctx);
}

/** @param {number} fd */
export function originalDstIpv4FromFd(fd) {
  if (isDarwin()) return originalDstIpv4FromFdDarwin();
  return originalDstIpv4FromFdLinux(fd);
}

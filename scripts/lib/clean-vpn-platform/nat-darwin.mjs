/**
 * Transport smoke: probes идут на IP TUN peer, MASQUERADE не нужен.
 * @param {string} tunName
 * @param {string|null|undefined} extIface
 */
export function setupExitNatDarwin(tunName, extIface) {
  console.log(
    `[clean-vpn] NAT skipped (darwin transport mode): ${tunName} ext=${extIface || 'auto'}`,
  );
  return { ext: extIface || 'lo0', tunName, prevIpForward: null, skipped: true };
}

/** @param {{ skipped?: boolean }} nat */
export function teardownExitNatDarwin(_nat) {
  /* no-op */
}

export function restoreExitSysctlDarwin(_prevIpForward) {
  /* no-op */
}

import { getDefaultRouteDarwin } from './net-darwin.mjs';

/**
 * Минимальный routeCtx для client без split-default (harness / macOS dev).
 * @param {string} ifname
 * @param {object} [opts]
 */
export async function setupClientRoutesDarwin(ifname, _serverHost, splitDefault, opts = {}) {
  if (process.env.CLEAN_VPN_SKIP_CLIENT_ROUTES === '1') {
    console.log('[clean-vpn] CLEAN_VPN_SKIP_CLIENT_ROUTES=1 — маршруты client не настраиваются');
  } else if (splitDefault) {
    console.warn(
      '[clean-vpn] split-default на macOS в clean-vpn пока не реализован — используйте Linux или routing suite',
    );
  }
  const dr = getDefaultRouteDarwin();
  return {
    serverIp: null,
    peerIp: null,
    gw: dr?.gw ?? null,
    dev: dr?.dev ?? 'en0',
    splitDefault: Boolean(splitDefault),
    prevRpAll: null,
    snapHost: [],
    snapPeer: [],
    snap01: [],
    snap128: [],
    ifname,
    splitDefaultApplied: false,
    infraBypassApplied: false,
    snapInfra: [],
    infraBypassIps: [],
    iceConfigPath: opts.configPath ?? null,
    iceMode: opts.iceMode ?? null,
    iceInfraBypass: false,
  };
}

/** @param {object} ctx */
export function teardownClientRoutesDarwin(_ctx) {
  console.log('[clean-vpn] client: маршруты (darwin) — nothing to restore');
}

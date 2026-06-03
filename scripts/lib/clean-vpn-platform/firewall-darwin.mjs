export function installOutputRedirectHttpsToLocalIpv4Darwin() {
  throw new Error(
    '[clean-vpn] iptables OUTPUT REDIRECT для transparent-tls недоступен на macOS; используйте --tunnel-peer=IPv4:PORT',
  );
}

export function installPreroutingDnatForwardedHttpsLanToGatewayIpv4Darwin() {
  throw new Error('[clean-vpn] iptables PREROUTING DNAT недоступен на macOS');
}

export function installFilterInputAcceptTransparentTlsInterceptIpv4Darwin() {
  throw new Error('[clean-vpn] iptables INPUT для transparent-tls недоступен на macOS');
}

export function isFirewallLinux() {
  return false;
}

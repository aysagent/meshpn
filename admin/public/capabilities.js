export function adminControls(capabilities = {}, role = 'client') {
  role = capabilities.role ?? role;
  const client = role !== 'exit';
  return { wifi: client && capabilities.wifi !== false,
    guardToggle: client && capabilities.guardToggle !== false,
    hostnameChange: capabilities.hostnameChange !== false && client,
    observer: client && capabilities.observer !== false,
    profileImport: client && capabilities.profileImport !== false,
    vpnSettings: client && capabilities.vpnSettings !== false,
    clients: role === 'exit' && capabilities.clients === true,
    probes: client ? (capabilities.probes ?? (capabilities.containerManaged ? ['dns'] : ['exit', 'dns', 'internet'])) : [],
  };
}

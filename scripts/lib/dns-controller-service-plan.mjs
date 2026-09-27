/** Offline units only. Publication/reload/boot enable belong to the installer. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DNS_BOOT_LOCK } from './dns-boot-guard.mjs';

export function compileDnsControllerServicePlan(input) {
  assert.ok(input && typeof input === 'object' && !Array.isArray(input));
  assert.deepEqual(Object.keys(input).sort(), ['client', 'firewallBackend', 'schema']);
  assert.equal(input.schema, 1); assert.equal(input.client, 'vps2');
  assert.ok(['legacy', 'nf_tables'].includes(input.firewallBackend));
  const guard = 'clean-vpn-dns-guard.service', managers = 'systemd-resolved.service systemd-networkd.service';
  const start = 'clean-vpn-dns-client.service', disable = 'clean-vpn-dns-disable.service';
  const common = (command) => `[Service]
Type=oneshot
User=root
UMask=0077
ExecStart=/usr/bin/flock -n -E 75 -F ${DNS_BOOT_LOCK} /usr/bin/node --max-old-space-size=192 /opt/clean-vpn/scripts/dns-client.mjs --${command}
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE SSL_CERT_DIR NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA
Restart=no
TimeoutStartSec=180
TimeoutStopSec=15
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE${input.firewallBackend === 'legacy' ? ' CAP_NET_RAW' : ''}
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
LimitCORE=0
LimitNOFILE=256
TasksMax=64
StandardInput=null
StandardOutput=journal
StandardError=journal
`;
  // No mount/net/PID sandbox: installed authority requires PID1's namespaces
  // and access to the dynamic adapter's process/credential mount evidence.
  const startUnit = `[Unit]
Description=clean-vpn installed VPS2 DNS controller (stop retains protection)
BindsTo=${guard} clean-vpn-dns-adapter.service ${managers}
After=${guard} clean-vpn-dns-adapter.service ${managers}
Conflicts=${disable}

${common('start')}RemainAfterExit=yes
`;
  // Restoration must work without the adapter. Stop the start transaction
  // first; the same inherited flock also serializes any still-running helper.
  const disableUnit = `[Unit]
Description=clean-vpn explicit VPS2 DNS restore (current boot only)
Requires=${guard} ${managers}
After=${start} ${guard} ${managers}
Conflicts=${start}

${common('disable')}`;
  const files = [
    { path: `/etc/systemd/system/${start}`, contents: startUnit },
    { path: `/etc/systemd/system/${disable}`, contents: disableUnit },
    ...managers.split(' ').map((name) => ({ path: `/etc/systemd/system/${name}.d/60-clean-vpn-dns-guard.conf`,
      contents: `[Unit]\nRequires=${guard}\nAfter=${guard}\n` })),
  ].map((f) => ({ ...f, mode: '0644', sha256: createHash('sha256').update(f.contents).digest('hex') }));
  return { schema: 1, kind: 'clean-vpn-dns-controller-service-plan', mode: 'offline-render', files,
    installationAllowed: false, systemSettingsChanged: false, dnsQueriesSent: 0,
    limitations: ['no-automatic-enable', 'not-an-installer', 'not-a-live-ownership-proof',
      'disable-restores-current-boot-not-uninstall', 'service-plan-is-not-loaded-service-proof', 'vps2-only'] };
}

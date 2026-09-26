/** Offline deployment artifact only. No service, firewall or resolver mutation. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { compileDnsUpstream } from './dns-upstream-config.mjs';
import { compileDnsDomainPolicy } from './dns-domain-policy.mjs';
import { validateDnsReadyName } from './dns-adapter-ready.mjs';
import { isPublicRelayAddress } from './transparent-tls-destination.mjs';
import { encodeRelayHostname } from './transparent-tls-enc-sni.mjs';

const invalid = () => Object.assign(new Error('DNS_SERVICE_PLAN_INVALID'), { code: 'DNS_SERVICE_PLAN_INVALID' });
const hash = (text) => createHash('sha256').update(text).digest('hex');
export function compileDnsAdapterServicePlan(input) {
  try {
    assert.ok(input && typeof input === 'object' && !Array.isArray(input));
    assert.deepEqual(Object.keys(input).sort(), ['schema', 'exitIp', 'exitPort', 'publicName', 'listenPort', 'readyName', 'upstream', 'domainPolicy'].sort());
    assert.equal(input.schema, 1);
    assert.equal(typeof input.exitIp, 'string'); assert.match(input.exitIp, /^[0-9a-f:.]+$/i); assert.ok(isPublicRelayAddress(input.exitIp));
    for (const [key, min] of [['exitPort', 1], ['listenPort', 1024]]) {
      assert.ok(Number.isInteger(input[key]) && input[key] >= min && input[key] <= 65535);
    }
    const publicName = validateDnsReadyName(input.publicName);
    compileDnsDomainPolicy(input.domainPolicy);
    const readyName = validateDnsReadyName(input.readyName, input.domainPolicy);
    const profile = compileDnsUpstream(input.upstream);
    // Offline enc-SNI size validation, not an operational or generated PSK.
    encodeRelayHostname(Buffer.alloc(32), { hostname: profile.hostname, port: profile.port }, publicName);
    const credential = '${CREDENTIALS_DIRECTORY}'; // Available in systemd 249; no newer %d specifier.
    const unit = `[Unit]
Description=clean-vpn protected DNS adapter
Wants=network-online.target
BindsTo=clean-vpn-dns-guard.service
After=network-online.target clean-vpn-dns-guard.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
NotifyAccess=all
DynamicUser=yes
UMask=0077
LoadCredential=upstream.json:/etc/clean-vpn/dns/upstream.json
LoadCredential=domains.json:/etc/clean-vpn/dns/domains.json
LoadCredential=hmac.key:/etc/clean-vpn/dns/hmac.key
ExecStart=/usr/bin/node --max-old-space-size=192 /opt/clean-vpn/scripts/dns-exit-adapter.mjs --config=${credential}/upstream.json --domain-policy=${credential}/domains.json --shared-hmac-key=${credential}/hmac.key --exit-ip=${input.exitIp} --exit-port=${input.exitPort} --public-name=${publicName} --listen-port=${input.listenPort} --ready-name=${readyName} --systemd-notify
Environment=PATH=/usr/bin:/bin LC_ALL=C
UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT OPENSSL_CONF OPENSSL_MODULES SSL_CERT_FILE SSL_CERT_DIR NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
Restart=no
TimeoutStartSec=30
TimeoutStopSec=15
KillMode=control-group
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitCORE=0
LimitNOFILE=256
TasksMax=64
StandardInput=null
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clean-vpn-dns-adapter
`;
    const files = [
      { path: '/etc/systemd/system/clean-vpn-dns-adapter.service', mode: '0644', contents: unit },
      { path: '/etc/clean-vpn/dns/upstream.json', mode: '0600', contents: `${JSON.stringify(input.upstream)}\n` },
      { path: '/etc/clean-vpn/dns/domains.json', mode: '0600', contents: `${JSON.stringify(input.domainPolicy)}\n` },
    ].map((file) => ({ ...file, sha256: hash(file.contents) }));
    assert.ok(Buffer.byteLength(files[1].contents) <= 131072 && Buffer.byteLength(files[2].contents) <= 16384);
    return { schema: 1, kind: 'clean-vpn-dns-adapter-service-plan', mode: 'offline-render', installationAllowed: false,
      systemSettingsChanged: false, dnsQueriesSent: 0, files,
      externalRequirements: ['root-owned-reviewed-code-at-/opt/clean-vpn', 'compatible-node-at-/usr/bin/node',
        'existing-private-32-byte-PSK-at-/etc/clean-vpn/dns/hmac.key', 'reviewed-upstream-and-exit-pinned-route',
        'approved-client-domain-policy', 'independent-DNS-guard-and-journal-controller',
        'systemd-249-or-newer-with-credentials-and-sandbox-support', 'VM-validation-before-live-installation'],
      limitations: ['not-an-installer', 'no-PSK-read-or-generation', 'no-host-ownership-proof',
        'no-guard-implementation', 'no-system-DNS-switch', 'startup-readiness-not-ongoing-health',
        'no-automatic-restart-or-boot-enable', 'not-a-live-pilot'] };
  } catch { throw invalid(); }
}

export async function readDnsAdapterServicePlan(path) {
  let fd;
  try {
    fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await fd.stat({ bigint: true });
    assert.ok(before.isFile() && before.size > 0n && before.size <= 131072n);
    const bytes = Buffer.alloc(131073); let used = 0;
    while (used < bytes.length) {
      const { bytesRead } = await fd.read(bytes, used, bytes.length - used, null);
      if (!bytesRead) break; used += bytesRead;
    }
    assert.equal(BigInt(used), before.size);
    assert.equal((await fd.stat({ bigint: true })).ctimeNs, before.ctimeNs);
    return compileDnsAdapterServicePlan(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, used))));
  } catch { throw invalid(); } finally { await fd?.close(); }
}

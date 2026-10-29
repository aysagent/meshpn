#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { peerDnsZoneConfig, peerDnsZoneOperation } from './lib/native-peer-dns-zone.mjs';
import { createDnsSystemdNotifier } from './lib/dns-systemd-notify.mjs';

export function peerDnsZoneUnit({ directory, address, port, node = process.execPath, script = fileURLToPath(import.meta.url) }) {
  const c = peerDnsZoneConfig({ address, port });
  for (const p of [directory, node, script]) if (typeof p !== 'string' || !/^\/[A-Za-z0-9_./-]+$/.test(p) || path.normalize(p) !== p) throw Error('peer_dns_zone_unit_path');
  return `[Unit]\nDescription=clean-vpn private mpn DNS routing scope\nAfter=systemd-resolved.service\nWants=systemd-resolved.service\n\n[Service]\nType=notify\nNotifyAccess=all\nExecStart=${node} ${script} watch --directory=${directory} --address=${c.address} --port=${c.port}\nRestart=on-failure\nRestartSec=2\nTimeoutStartSec=30\nTimeoutStopSec=10\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=${directory}\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nCapabilityBoundingSet=CAP_NET_ADMIN\nRestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX\nTasksMax=32\nMemoryMax=128M\n\n[Install]\nWantedBy=multi-user.target\n`;
}
export async function peerDnsZoneMain(args) {
  const [action, ...rest] = args, values = {};
  if (!action || action === '--help') { console.log('Usage: clean-vpn-native-peer-dns-zone.mjs plan|unit|apply|watch|status|remove --directory=/private/zone-state [--address=169.254.255.53] [--port=1055]\napply/watch explicitly create one owned dummy DNS scope; remove deletes only that scope. watch/daemon stop preserves routing to fail closed. No global DNS or existing interface changes.'); return; }
  if (!['plan', 'unit', 'apply', 'watch', 'status', 'remove'].includes(action)) throw Error('peer_dns_zone_action');
  for (const arg of rest) { const m = /^--(directory|address|port)=(.+)$/.exec(arg); if (!m || values[m[1]] !== undefined) throw Error('peer_dns_zone_option'); values[m[1]] = m[2]; }
  if (!values.directory || !path.isAbsolute(values.directory)) throw Error('peer_dns_zone_directory');
  if (values.port !== undefined && !/^[1-9][0-9]{0,4}$/.test(values.port)) throw Error('peer_dns_zone_port');
  const config = peerDnsZoneConfig({ address: values.address, port: values.port === undefined ? undefined : Number(values.port) });
  if (action === 'plan') { console.log(JSON.stringify({ kind: 'clean-vpn-peer-dns-zone-plan', directory: values.directory, config, zones: ['mpn', '0.99.10.in-addr.arpa'], creates: 'owned dummy interface with /32', defaultDnsChanged: false, stopKeepsScope: true, removeExplicit: true })); return; }
  if (action === 'unit') { console.log(peerDnsZoneUnit({ directory: values.directory, ...config })); return; }
  let stopping = false; const stop = () => { stopping = true; };
  if (action === 'watch') { process.on('SIGINT', stop); process.on('SIGTERM', stop); }
  try {
    const result = await peerDnsZoneOperation({ directory: values.directory, config, operation: action === 'watch' ? 'apply' : action }); console.log(JSON.stringify(result));
    if (action !== 'watch') return;
    if (process.env.NOTIFY_SOCKET) await (await createDnsSystemdNotifier())();
    while (!stopping) { for (let i = 0; i < 50 && !stopping; i++) await delay(100); if (!stopping) await peerDnsZoneOperation({ directory: values.directory, config }); }
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) peerDnsZoneMain(process.argv.slice(2)).catch(error => { console.error('PEER_DNS_ZONE=failed: ' + (/^[a-z0-9_]{1,100}$/.test(error.message) ? error.message : error.code ?? 'operation_failed')); process.exitCode = 1; });

#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPeerDnsRegistry, startPeerDns, peerDnsUnit } from './lib/native-peer-dns.mjs';

export async function peerDnsMain(args) {
  const [action, ...rest] = args, values = {};
  if (action === '--help' || !action) {
    console.log('Usage: clean-vpn-native-peer-dns.mjs check|run|unit --registry=/private/clients/registry.json [--port=1055] [--node=/absolute/node --script=/absolute/clean-vpn-native-peer-dns.mjs]\nLoopback-only authoritative .mpn and 0.99.10.in-addr.arpa; no upstream. unit prints a systemd unit, installs nothing.'); return;
  }
  if (!['check', 'run', 'unit'].includes(action)) throw new Error('peer_dns_action');
  for (const arg of rest) {
    const match = /^--([a-z]+)=(.+)$/.exec(arg);
    if (!match || !['registry', 'port', 'node', 'script'].includes(match[1]) || values[match[1]] !== undefined) throw new Error('peer_dns_option');
    values[match[1]] = match[2];
  }
  if (!values.registry || !path.isAbsolute(values.registry)) throw new Error('peer_dns_registry_required');
  if (values.port !== undefined && !/^[1-9][0-9]{0,4}$/.test(values.port)) throw new Error('peer_dns_port');
  const port = Number(values.port ?? 1055);
  if (port < 1024 || port > 65535) throw new Error('peer_dns_high_port_required');
  if (action !== 'unit' && (values.node || values.script)) throw new Error('peer_dns_unit_options_only');
  if (action === 'unit') { console.log(peerDnsUnit({ registry: values.registry, port, node: values.node ?? process.execPath, script: values.script ?? fileURLToPath(import.meta.url) })); return; }
  const state = readPeerDnsRegistry(values.registry);
  if (action === 'check') { console.log(JSON.stringify({ valid: true, zone: 'mpn', clients: state.forward.size, revision: state.revision, systemDnsChanged: false })); return; }
  const server = await startPeerDns({ registry: values.registry, port });
  console.log(JSON.stringify({ kind: 'clean-vpn-peer-dns', state: 'listening', address: server.address, port: server.port, zone: 'mpn', revision: state.revision }));
  await new Promise(resolve => {
    let stopped = false;
    const stop = async error => { if (stopped) return; stopped = true; process.removeListener('SIGINT', signal); process.removeListener('SIGTERM', signal); await server.close(); if (error) { process.exitCode = 1; console.error('PEER_DNS=failed: ' + error); } resolve(); };
    const signal = () => void stop(); process.once('SIGINT', signal); process.once('SIGTERM', signal);
    server.failure.then(error => void stop(error));
  });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) peerDnsMain(process.argv.slice(2)).catch(error => { console.error('PEER_DNS=failed: ' + (error.code ?? error.message)); process.exitCode = 1; });

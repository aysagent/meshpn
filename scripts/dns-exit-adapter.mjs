#!/usr/bin/env node
/** Explicit opt-in, no TUN, routes, system DNS or resolver selection. */
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { readDnsUpstreamConfig } from './lib/dns-upstream-config-file.mjs';
import { startDnsExitAdapter } from './lib/dns-exit-adapter.mjs';

const fail = () => { throw new Error('DNS_EXIT_ADAPTER_INVALID'); };
export function parseDnsExitArgs(args) {
  if (args.length === 1 && args[0] === '--help') return { help: true };
  const values = {};
  for (const arg of args) {
    const match = /^--(config|exit-ip|exit-port|public-name|shared-hmac-key|listen-port)=(.+)$/.exec(arg);
    if (!match || Object.hasOwn(values, match[1])) fail(); values[match[1]] = match[2];
  }
  for (const key of ['config', 'exit-ip', 'exit-port', 'public-name', 'shared-hmac-key', 'listen-port']) if (!values[key]) fail();
  for (const [key, min] of [['exit-port', 1], ['listen-port', 1024]]) {
    if (!/^[1-9]\d{0,4}$/.test(values[key]) || Number(values[key]) < min || Number(values[key]) > 65535) fail();
    values[key] = Number(values[key]);
  }
  return values;
}
export async function readDnsExitSecret(path) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await file.stat();
    if (!info.isFile() || info.size !== 32 || (info.mode & 0o077)) fail();
    const bytes = Buffer.alloc(33); let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await file.read(bytes, length, bytes.length - length, null);
      if (!bytesRead) break; length += bytesRead;
    }
    if (length !== 32) { bytes.fill(0); fail(); }
    const secret = Buffer.from(bytes.subarray(0, 32)); bytes.fill(0); return secret;
  } catch { fail(); } finally { await file?.close(); }
}

async function main() {
  const options = parseDnsExitArgs(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: node scripts/dns-exit-adapter.mjs --config=/path/upstream.json --exit-ip=PUBLIC_IP --exit-port=443 --public-name=vpn.example.com --shared-hmac-key=/path/key --listen-port=1053\nExplicit 127.0.0.1 UDP/TCP DNS adapter (ordinary IN types), through enc-SNI exit. No TUN, system DNS, direct resolver or plaintext fallback. See scripts/dns-exit-adapter.md.'); return;
  }
  let adapter, secret, stopped = false, stop;
  const stopping = new Promise((resolve) => { stop = resolve; });
  const signal = () => { stopped = true; stop(); };
  process.on('SIGINT', signal); process.on('SIGTERM', signal);
  try {
    const profile = await readDnsUpstreamConfig(options.config);
    secret = await readDnsExitSecret(options['shared-hmac-key']);
    if (stopped) return;
    adapter = await startDnsExitAdapter({ profile, secret, exitAddress: options['exit-ip'], exitPort: options['exit-port'],
      publicName: options['public-name'], port: options['listen-port'] });
    secret.fill(0);
    if (!stopped) console.log(`DNS_EXIT_ADAPTER ${JSON.stringify({ status: 'listening', address: '127.0.0.1', port: adapter.port,
      systemDnsChanged: false })}`);
    await stopping;
  } finally {
    secret?.fill(0); await adapter?.close();
    process.off('SIGINT', signal); process.off('SIGTERM', signal);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { console.error('DNS_EXIT_ADAPTER_INVALID'); process.exitCode = 1; });
}

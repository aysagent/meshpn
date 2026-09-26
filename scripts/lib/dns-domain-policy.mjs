/** Explicit QNAME deny policy. Offline, bounded, independent of DHCP/resolved. */
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dnsError } from './lab-dns-wire.mjs';

export const DNS_DOMAIN_POLICY_MAX_BYTES = 16384;
const fail = () => { throw dnsError('DNS_DOMAIN_POLICY'); };
export function compileDnsDomainPolicy(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).sort().join(',') !== 'denySuffixes,schema' || input.schema !== 1
    || !Array.isArray(input.denySuffixes) || input.denySuffixes.length < 1 || input.denySuffixes.length > 128) fail();
  const keys = new Set();
  for (const value of input.denySuffixes) {
    if (typeof value !== 'string' || value.length > 254) fail();
    const domain = value.replace(/\.$/, '').toLowerCase();
    if (domain.length > 253 || !domain.split('.').every((label) => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label))) fail();
    // Match wire label boundaries, never a lossy presentation name with embedded dots.
    const key = domain.split('.').map((label) => Buffer.from(label, 'ascii').toString('hex')).join('.');
    if (keys.has(key)) fail(); keys.add(key);
  }
  return Object.freeze({ denies: (query) => {
    let key = query.nameKey;
    for (;;) {
      if (keys.has(key)) return true;
      const dot = key.indexOf('.'); if (dot < 0) return false;
      key = key.slice(dot + 1);
    }
  } });
}

export async function readDnsDomainPolicy(path) {
  let file;
  try {
    if (typeof path !== 'string' || !path || path.includes('\0')) fail();
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > DNS_DOMAIN_POLICY_MAX_BYTES) fail();
    const bytes = Buffer.alloc(DNS_DOMAIN_POLICY_MAX_BYTES + 1); let size = 0;
    while (size < bytes.length) {
      const { bytesRead } = await file.read(bytes, size, bytes.length - size, null);
      if (!bytesRead) break; size += bytesRead;
    }
    if (size > DNS_DOMAIN_POLICY_MAX_BYTES) fail();
    const config = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size)));
    compileDnsDomainPolicy(config); return config;
  } catch { fail(); } finally { await file?.close(); }
}

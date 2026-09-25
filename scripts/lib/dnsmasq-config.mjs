/** Read-only, deliberately incomplete dnsmasq inventory. Never a config writer. */
import { isIP } from 'node:net';

const flags = new Set(['no-resolv', 'no-poll', 'bind-interfaces', 'bind-dynamic',
  'domain-needed', 'bogus-priv', 'strict-order', 'all-servers']);
const interfaces = new Set(['interface', 'except-interface', 'no-dhcp-interface']);
const includes = new Set(['conf-file', 'conf-dir', 'servers-file', 'resolv-file']);
const addresses = (s) => s.split(',').every((v) => isIP(v) !== 0);

export function filterDnsmasqDiagnostic(text) {
  const entries = [];
  let omitted = 0, unparsed = 0;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([a-z][a-z0-9-]*)(?:=(.*))?$/.exec(line);
    if (!match) { unparsed++; continue; }
    const [, key, value] = match;
    if (includes.has(key)) { entries.push({ key, value: '[not-followed]' }); continue; }
    let safe = false;
    if (flags.has(key)) safe = value === undefined;
    if (interfaces.has(key)) safe = typeof value === 'string' && /^[a-zA-Z0-9_.*:-]{1,32}$/.test(value);
    if (key === 'listen-address') safe = !!value && addresses(value);
    if (key === 'port') safe = /^\d{1,5}$/.test(value ?? '') && Number(value) <= 65535;
    if (key === 'server') {
      // Only literal upstreams; never print arbitrary option contents.
      const parts = (value ?? '').split('#');
      safe = parts.length <= 2 && isIP(parts[0]) !== 0
        && (parts.length === 1 || /^\d{1,5}$/.test(parts[1]) && Number(parts[1]) > 0 && Number(parts[1]) <= 65535);
    }
    if (key === 'dhcp-option') {
      const option = /^(3|6|option:router|option:dns-server),(.+)$/.exec(value ?? '');
      safe = !!option && addresses(option[2]);
    }
    if (key === 'dhcp-range') {
      // The client's simple IPv4 range only; vendor/tag/boot fields stay private.
      const parts = (value ?? '').split(',');
      safe = parts.length === 4 && parts.slice(0, 3).every((v) => isIP(v) === 4)
        && /^\d{1,8}[smhdw]?$/.test(parts[3]);
    }
    if (safe) entries.push({ key, ...(value === undefined ? {} : { value }) });
    else omitted++;
  }
  return { entries, omitted, unparsed };
}

export function summarizeDnsmasqDiagnostic(inventory) {
  const files = Object.values(inventory.configs);
  const entries = files.filter((f) => f.status === 'ok').flatMap((f) => f.data.entries);
  const dnsOptions = entries.filter((e) => e.key === 'dhcp-option' && /^(6|option:dns-server),/.test(e.value));
  const reasons = ['inventory-is-not-effective-config', 'daemon-arguments-and-include-selection-unknown'];
  if (files.some((f) => f.status !== 'ok')) reasons.push('config-read-incomplete');
  if (inventory.directory.status === 'unavailable' && inventory.directory.reason !== 'ENOENT') reasons.push('directory-read-incomplete');
  if (inventory.directory.truncated) reasons.push('config-inventory-truncated');
  if (files.some((f) => f.data?.omitted || f.data?.unparsed)) reasons.push('unreported-or-unparsed-options');
  if (entries.some((e) => includes.has(e.key))) reasons.push('additional-config-sources-not-followed');
  if (dnsOptions.length > 1) reasons.push('multiple-dhcp-dns-declarations-in-inventory-review-effective-offer');
  if (entries.some((e) => e.key === 'server' && e.value === '127.0.0.1#53')) reasons.push('possible-self-forwarding-review-listener');
  return { backend: 'unselected', requiresReview: true, reasons,
    noResolvObserved: entries.some((e) => e.key === 'no-resolv'),
    upstreamsObserved: entries.filter((e) => e.key === 'server').map((e) => e.value),
    dhcpDnsObserved: dnsOptions.map((e) => e.value.slice(e.value.indexOf(',') + 1)) };
}

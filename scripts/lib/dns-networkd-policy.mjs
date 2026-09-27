/** Fixed VPS2 deployment artifact. Rendering/validation never changes the OS. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { filterNetworkdState } from './dns-client-ownership.mjs';

export const DNS_NETWORKD_POLICY = '/etc/systemd/network/00-clean-vpn-dns.network';
export const DNS_NETWORKD_CONTENTS = `# clean-vpn owned DNS links only; leave uplink configuration untouched.
[Match]
Name=cvdns${'[0-9a-f]'.repeat(8)}

[Link]
Unmanaged=yes
`;
export function dnsNetworkdPolicyArtifact() {
  return { path: DNS_NETWORKD_POLICY, mode: '0644', contents: DNS_NETWORKD_CONTENTS,
    sha256: createHash('sha256').update(DNS_NETWORKD_CONTENTS).digest('hex') };
}
// Data assertion, NOT authority or proof of ownership. Caller must separately
// pin the kernel link/journal, networkd owner and this file before any setter.
export function assertDnsNetworkdUnmanaged({ name, ifindex, state }) {
  assert.match(name, /^cvdns[a-f0-9]{8}$/);
  assert.ok(Number.isInteger(ifindex) && ifindex > 1 && ifindex <= 2147483647);
  assert.equal(typeof state, 'string'); assert.ok(Buffer.byteLength(state) <= 65536);
  assert.equal(filterNetworkdState(state).ADMIN_STATE, 'unmanaged', 'networkd must not manage the DNS link');
  return true;
}

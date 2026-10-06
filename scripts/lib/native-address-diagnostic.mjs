// Explicit allowlist: addresses/protocol only, never arbitrary packet fields.
import { isIPv4 } from 'node:net';
export function validAddressDiagnostic(v) {
  const keys = ['version', 'event', 'role', 'source', 'destination', 'protocol'];
  return v && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => k in v)
    && v.version === 1 && v.event === 'peer_address_rejected' && ['client', 'exit'].includes(v.role)
    && typeof v.source === 'string' && isIPv4(v.source)
    && typeof v.destination === 'string' && isIPv4(v.destination)
    && Number.isInteger(v.protocol) && v.protocol >= 0 && v.protocol <= 255;
}

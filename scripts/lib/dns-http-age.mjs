import { dnsError } from './lab-dns-wire.mjs';

/** Read raw headers: Node's normalized headers can hide duplicate Age fields.
 * No HTTP cache is implemented. Saturate delta-seconds per RFC 9111 section 1.2.2.
 */
export function dnsHttpAge(rawHeaders) {
  let age = 0, found = false;
  for (let i = 0; i < rawHeaders.length; i += 2) {
    if (rawHeaders[i].toLowerCase() !== 'age') continue;
    // HTTP OWS is SP/HTAB only, not JavaScript's Unicode whitespace class.
    const value = rawHeaders[i + 1].replace(/^[ \t]+|[ \t]+$/g, '');
    if (found || !/^[0-9]+$/.test(value)) throw dnsError('DNS_HTTP_AGE');
    found = true; age = Math.min(0x80000000, Number(value));
  }
  return age;
}

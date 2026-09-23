/** Bounded offline read shared by the validator and exit startup. */
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { DNS_UPSTREAM_CONFIG_MAX_BYTES, parseDnsUpstream } from './dns-upstream-config.mjs';

export async function readDnsUpstreamConfig(path) {
  let file;
  try {
    if (typeof path !== 'string' || !path || path.includes('\0')) throw new Error();
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await file.stat();
    if (!info.isFile() || info.size > DNS_UPSTREAM_CONFIG_MAX_BYTES) throw new Error();
    const buffer = Buffer.alloc(DNS_UPSTREAM_CONFIG_MAX_BYTES + 1); let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await file.read(buffer, size, buffer.length - size, null);
      if (!bytesRead) break; size += bytesRead;
    }
    if (size > DNS_UPSTREAM_CONFIG_MAX_BYTES) throw new Error();
    return parseDnsUpstream(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size)));
  } catch { throw Object.assign(new Error('DNS_UPSTREAM_CONFIG'), { code: 'DNS_UPSTREAM_CONFIG' }); }
  finally { await file?.close(); }
}

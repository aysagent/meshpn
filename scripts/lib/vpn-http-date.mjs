/** Time recovery ONLY after certificate-verified TLS and a rejected VPN response. */
import { execFileSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';

export const DATE_MAX_RTT_MS = 5000;
export const CLOCK_UPDATED = 'CLEAN_VPN_CLOCK_UPDATED';

export function parseHttpDate(value) {
  if (typeof value !== 'string' || !/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) return null;
  const ms = Date.parse(value);
  // Reject duplicates, impossible dates, wrong weekday, obsolete formats and local time.
  return Number.isFinite(ms) && ms >= 0 && new Date(ms).toUTCString() === value ? ms : null;
}

export function vpnResponseAccepted(status, contentType) {
  return String(status) === '200' && typeof contentType === 'string' &&
    contentType.trim().toLowerCase() === 'application/octet-stream';
}

/** Preserve duplicate fields as arrays, so security-sensitive consumers reject them. */
export function responseHeaders(head) {
  const headers = Object.create(null);
  for (const line of head.split('\r\n').slice(1)) {
    const colon = line.indexOf(':');
    if (colon < 1) continue;
    const name = line.slice(0, colon).toLowerCase(), value = line.slice(colon + 1).trim();
    headers[name] = headers[name] === undefined ? value : [].concat(headers[name], value);
  }
  return headers;
}

/** One clock-setting attempt per client process, including failed setter attempts.
 * No transport, firewall, NTP, RTC, certificate or Bearer-policy changes.
 * Test injection never changes the workstation clock.
 */
export function createHttpDateRecovery({ windowMs, wall = Date.now, mono = () => performance.now(),
  setClock = ms => execFileSync('/usr/bin/date', ['-u', '-s', `@${ms / 1000}`], {
    timeout: 3000, maxBuffer: 4096, stdio: 'pipe',
    env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' },
  }), log = message => console.warn(message),
} = {}) {
  if (!Number.isSafeInteger(windowMs) || windowMs < 1000) throw Error('invalid Bearer window');
  let attempted = false;
  return {
    begin(socket) {
      const sentWall = wall(), started = mono();
      // The CLI invokes this only in native TLS secureConnect, with CA/name checks on.
      // BoringSSL pipe transports do not expose this evidence: never infer trust from HTTP.
      let certificate;
      const trusted = socket?.encrypted === true && socket?.authorized === true && !socket.authorizationError;
      if (trusted) { try { certificate = socket.getPeerCertificate(true); } catch {} }
      let consumed = false;
      return (headers, message) => {
        const error = new Error(message);
        const refuse = reason => { error.message += `; clock-date=${reason}`; return error; };
        if (consumed) return refuse('response-already-used');
        consumed = true;
        if (!trusted || !certificate?.raw) return refuse('verified-native-TLS-required');
        const elapsed = mono() - started;
        if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > DATE_MAX_RTT_MS) return refuse('stale-response');
        const serverMs = parseHttpDate(headers.date);
        if (serverMs === null || headers.age !== undefined) return refuse('missing-invalid-or-cached-Date');
        // Date has whole-second precision; allow transport delay around a window boundary.
        const first = Math.floor(serverMs / windowMs);
        const last = Math.floor((serverMs + 999 + elapsed) / windowMs);
        const client = Math.floor(sentWall / windowMs);
        if (client >= first - 1 && client <= last + 1) return refuse('within-Bearer-window');
        if (Math.abs(wall() - (sentWall + elapsed)) > 2000) return refuse('clock-changed-during-request');
        // Do not move into a date at which the authenticated certificate chain is invalid.
        const seen = new Set();
        let cert = certificate;
        while (cert && !seen.has(cert)) {
          if (seen.size >= 16) return refuse('invalid-certificate-chain');
          seen.add(cert);
          const from = Date.parse(cert.valid_from), to = Date.parse(cert.valid_to);
          if (!Number.isFinite(from) || !Number.isFinite(to) || serverMs < from || serverMs + 999 + elapsed > to)
            return refuse('Date-outside-certificate-validity');
          cert = cert.issuerCertificate;
        }
        if (attempted) return refuse('attempt-already-used');
        attempted = true;
        const before = wall();
        try {
          setClock(serverMs);
          if (Math.abs(wall() - serverMs) > 5000) throw Error('clock did not reach server Date');
        } catch {
          log('[clean-vpn] clock-date: не удалось установить часы; повторные переводы отключены до перезапуска клиента');
          return refuse('set-failed');
        }
        log(`[clean-vpn] clock-date: UTC ${new Date(before).toISOString()} -> ${new Date(serverMs).toISOString()} по Date проверенного exit; повторная TLS/Bearer авторизация`);
        error.code = CLOCK_UPDATED;
        return refuse('updated');
      };
    },
  };
}

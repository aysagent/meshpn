/**
 * Encrypted origin hostname для transparent-tls relay SNI: `<labels>.<publicName>`.
 * AEAD (AES-256-GCM) + base62 wire encoding (0-9, a-z, A-Z — LDH-safe);
 * длинный blob — несколько DNS-labels (≤63 B каждый). Wire format v2 (BREAKING vs base32hex v1).
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'crypto';

export const ENC_SNI_TS_WINDOW_MS = 5 * 60 * 1000;
const ENC_SNI_VERSION = 0x02;
const ENC_SNI_NONCE_LEN = 12;
const ENC_SNI_TAG_LEN = 16;
const DNS_LABEL_MAX = 63;
const HOSTNAME_MAX = 253;
const BASE62 =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

/** @param {Buffer} psk */
function deriveEncSniKey(psk) {
  return createHmac('sha256', psk).update('transparent-tls-enc-sni-v2\0').digest();
}

/** @param {Buffer} buf */
export function base62Encode(buf) {
  if (!buf.length) return '';
  /** @type {number[]} */
  const digits = [0];
  for (let i = 0; i < buf.length; i++) {
    let carry = buf[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 62;
      carry = (carry / 62) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 62);
      carry = (carry / 62) | 0;
    }
  }
  let out = '';
  for (let i = 0; i < buf.length && buf[i] === 0; i++) out += BASE62[0];
  for (let q = digits.length - 1; q >= 0; q--) out += BASE62[digits[q]];
  return out || BASE62[0];
}

/** @param {string} str */
export function base62Decode(str) {
  if (!str.length) return Buffer.alloc(0);
  /** @type {number[]} */
  const bytes = [0];
  let zeros = 0;
  for (let i = 0; i < str.length && str[i] === BASE62[0]; i++) zeros++;
  for (let i = zeros; i < str.length; i++) {
    const idx = BASE62.indexOf(str[i]);
    if (idx < 0) throw new Error('enc-sni: bad base62 char');
    let carry = idx;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 62;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  const core = Buffer.from(bytes.reverse());
  return Buffer.concat([Buffer.alloc(zeros), core]);
}

/** @param {string} hostname */
function assertRelayHostname(hostname) {
  const h = String(hostname || '');
  if (!h || h.length > HOSTNAME_MAX) throw new Error('enc-sni: hostname length');
  if (h.includes(':') || h.includes('/') || h.includes(' ')) {
    throw new Error('enc-sni: hostname invalid');
  }
  for (let i = 0; i < h.length; i++) {
    const c = h.charCodeAt(i);
    const ok =
      (c >= 0x61 && c <= 0x7a) ||
      (c >= 0x30 && c <= 0x39) ||
      c === 0x2e ||
      c === 0x2d;
    if (!ok) throw new Error('enc-sni: hostname non-ascii/idna');
  }
}

/**
 * @param {string} hostname
 * @param {number} port
 */
function buildPlaintext(hostname, port) {
  assertRelayHostname(hostname);
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('enc-sni: bad port');
  const hostB = Buffer.from(hostname, 'utf8');
  if (hostB.length < 1 || hostB.length > 253) throw new Error('enc-sni: host utf8');
  const out = Buffer.allocUnsafe(1 + 4 + 2 + 1 + hostB.length);
  let o = 0;
  out[o++] = ENC_SNI_VERSION;
  out.writeUInt32BE(Math.floor(Date.now() / 1000), o);
  o += 4;
  out.writeUInt16BE(p, o);
  o += 2;
  out[o++] = hostB.length;
  hostB.copy(out, o);
  return out;
}

/** @param {Buffer} pt */
function parsePlaintext(pt) {
  if (pt.length < 1 + 4 + 2 + 1) throw new Error('enc-sni: plaintext short');
  if (pt[0] !== ENC_SNI_VERSION) {
    throw new Error(pt[0] === 0x01 ? 'enc-sni: v1 base32hex not supported' : 'enc-sni: bad version');
  }
  const expiry = pt.readUInt32BE(1);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - expiry) > ENC_SNI_TS_WINDOW_MS / 1000) {
    throw new Error('enc-sni: ts_window');
  }
  const port = pt.readUInt16BE(5);
  const hl = pt[7];
  if (pt.length !== 8 + hl) throw new Error('enc-sni: plaintext len');
  const hostname = pt.subarray(8, 8 + hl).toString('utf8');
  assertRelayHostname(hostname);
  return { hostname, port };
}

/** @param {string} blob */
function splitDnsLabels(blob) {
  /** @type {string[]} */
  const labels = [];
  for (let i = 0; i < blob.length; i += DNS_LABEL_MAX) {
    labels.push(blob.slice(i, i + DNS_LABEL_MAX));
  }
  return labels;
}

/**
 * @param {Buffer} psk
 * @param {{ hostname: string, port?: number }} opts
 */
export function encodeRelaySniLabel(psk, opts) {
  const key = deriveEncSniKey(psk);
  const pt = buildPlaintext(opts.hostname, opts.port ?? 443);
  const nonce = randomBytes(ENC_SNI_NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (tag.length !== ENC_SNI_TAG_LEN) throw new Error('enc-sni: tag len');
  const blob = base62Encode(Buffer.concat([nonce, ct, tag]));
  return splitDnsLabels(blob);
}

/**
 * @param {Buffer} psk
 * @param {string[]} labels
 */
export function decodeRelaySniLabel(psk, labels) {
  const blob = labels.join('');
  const wire = base62Decode(blob);
  if (wire.length < ENC_SNI_NONCE_LEN + ENC_SNI_TAG_LEN + 8) {
    throw new Error('enc-sni: wire short');
  }
  const nonce = wire.subarray(0, ENC_SNI_NONCE_LEN);
  const tag = wire.subarray(wire.length - ENC_SNI_TAG_LEN);
  const ct = wire.subarray(ENC_SNI_NONCE_LEN, wire.length - ENC_SNI_TAG_LEN);
  const key = deriveEncSniKey(psk);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return parsePlaintext(pt);
}

/**
 * @param {string[]} encLabels
 * @param {string} publicName
 */
export function buildRelayHostname(encLabels, publicName) {
  const pn = String(publicName || '').trim().toLowerCase();
  if (!pn) throw new Error('enc-sni: publicName required');
  for (const l of encLabels) {
    if (!l || l.length > DNS_LABEL_MAX) throw new Error('enc-sni: label len');
  }
  const host = [...encLabels, pn].join('.');
  if (Buffer.byteLength(host, 'utf8') > HOSTNAME_MAX) {
    throw new Error('enc-sni: relay SNI too long');
  }
  return host;
}

/**
 * @param {Buffer} psk
 * @param {{ hostname: string, port?: number }} opts
 * @param {string} publicName
 */
export function encodeRelayHostname(psk, opts, publicName) {
  const labels = encodeRelaySniLabel(psk, opts);
  return buildRelayHostname(labels, publicName);
}

/**
 * Suffix `.publicName` — case-insensitive; enc prefix labels — case-preserving (base62).
 * @param {string} sni
 * @param {string} publicName
 * @returns {string[]|null}
 */
export function parseRelayEncLabels(sni, publicName) {
  const pn = String(publicName || '').trim().toLowerCase();
  if (!pn || !sni) return null;
  const suffix = `.${pn}`;
  if (!sni.toLowerCase().endsWith(suffix)) return null;
  const prefix = sni.slice(0, sni.length - suffix.length);
  if (!prefix) return null;
  /** @type {string[]} */
  const labels = prefix.split('.').filter(Boolean);
  if (!labels.length) return null;
  for (const l of labels) {
    if (l.length > DNS_LABEL_MAX) return null;
  }
  return labels;
}

/**
 * @param {string} sni
 * @param {string} publicName
 * @param {Buffer} psk
 */
export function decodeRelayFromHostname(sni, publicName, psk) {
  const labels = parseRelayEncLabels(sni, publicName);
  if (!labels) return { ok: false, reason: 'bad_suffix' };
  try {
    const { hostname, port } = decodeRelaySniLabel(psk, labels);
    return { ok: true, hostname, port, relaySni: sni, labels };
  } catch (e) {
    return { ok: false, reason: /** @type {Error} */ (e).message || String(e) };
  }
}

/**
 * @param {string} sni
 * @param {string} publicName
 */
export function looksLikeRelayEncSniHostname(sni, publicName) {
  return parseRelayEncLabels(sni, publicName) !== null;
}

/** Constant-time-ish compare for optional use. */
export function encSniKeysEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

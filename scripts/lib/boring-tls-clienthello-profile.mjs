/**
 * Файл профиля ClientHello / JA3 для boring-tls-helper (schema v1).
 * См. scripts/boring-tls-plan.md — поток mini-сервер → JSON → clean-vpn client.
 */

import fs from 'fs';
import path from 'path';

export const BORING_TLS_CLIENTHELLO_SCHEMA_VERSION = '1';

/**
 * @typedef {{
 *   schema_version?: string,
 *   user_agent: string,
 *   legacy_version: number,
 *   cipher_suites: number[],
 *   extension_types: number[],
 *   supported_groups: number[],
 *   ec_point_formats: number[],
 *   ja3_string?: string,
 *   ja3_md5?: string,
 *   tls_info?: { alpn?: string[], supported_versions?: number[] },
 * }} BoringTlsClienthelloProfileFile
 */

/** @param {unknown} n */
function isUint16(n) {
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 0xffff;
}

/** @param {unknown} n */
function isUint8(n) {
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= 0xff;
}

/**
 * @param {unknown} obj
 * @returns {{ ok: true, profile: BoringTlsClienthelloProfileFile } | { ok: false, error: string }}
 */
export function validateBoringTlsClienthelloProfileFile(obj) {
  if (!obj || typeof obj !== 'object') return { ok: false, error: 'profile: не объект' };
  const p = /** @type {Record<string, unknown>} */ (obj);
  const sv = p.schema_version;
  if (sv !== undefined && sv !== BORING_TLS_CLIENTHELLO_SCHEMA_VERSION) {
    return { ok: false, error: `profile: неподдерживаемый schema_version=${sv}` };
  }
  if (typeof p.user_agent !== 'string') {
    return { ok: false, error: 'profile: нужно строковое поле user_agent' };
  }
  for (const key of ['legacy_version', 'cipher_suites', 'extension_types', 'supported_groups', 'ec_point_formats']) {
    if (!(key in p)) return { ok: false, error: `profile: отсутствует поле ${key}` };
  }
  if (!isUint16(p.legacy_version)) return { ok: false, error: 'profile: legacy_version должен быть uint16' };
  if (!Array.isArray(p.cipher_suites) || p.cipher_suites.length === 0) {
    return { ok: false, error: 'profile: cipher_suites — непустой массив uint16' };
  }
  if (!Array.isArray(p.extension_types) || p.extension_types.length === 0) {
    return { ok: false, error: 'profile: extension_types — непустой массив uint16' };
  }
  if (!Array.isArray(p.supported_groups) || p.supported_groups.length === 0) {
    return { ok: false, error: 'profile: supported_groups — непустой массив uint16' };
  }
  if (!Array.isArray(p.ec_point_formats)) return { ok: false, error: 'profile: ec_point_formats должен быть массивом' };
  for (const c of p.cipher_suites) {
    if (!isUint16(c)) return { ok: false, error: 'profile: cipher_suites содержит не uint16' };
  }
  for (const e of p.extension_types) {
    if (!isUint16(e)) return { ok: false, error: 'profile: extension_types содержит не uint16' };
  }
  for (const g of p.supported_groups) {
    if (!isUint16(g)) return { ok: false, error: 'profile: supported_groups содержит не uint16' };
  }
  for (const f of p.ec_point_formats) {
    if (!isUint8(f)) return { ok: false, error: 'profile: ec_point_formats содержит не uint8' };
  }
  if (p.ja3_md5 !== undefined) {
    if (typeof p.ja3_md5 !== 'string' || !/^[0-9a-f]{32}$/.test(p.ja3_md5)) {
      return { ok: false, error: 'profile: ja3_md5 должен быть 32 lowercase hex' };
    }
  }
  if (p.ja3_string !== undefined && typeof p.ja3_string !== 'string') {
    return { ok: false, error: 'profile: ja3_string должно быть строкой' };
  }
  if (p.tls_info !== undefined) {
    if (!p.tls_info || typeof p.tls_info !== 'object') return { ok: false, error: 'profile: tls_info не объект' };
    const ti = /** @type {Record<string, unknown>} */ (p.tls_info);
    if (ti.alpn !== undefined) {
      if (!Array.isArray(ti.alpn) || ti.alpn.some((x) => typeof x !== 'string')) {
        return { ok: false, error: 'profile: tls_info.alpn должен быть string[]' };
      }
    }
    if (ti.supported_versions !== undefined) {
      if (!Array.isArray(ti.supported_versions) || ti.supported_versions.some((x) => !isUint16(x))) {
        return { ok: false, error: 'profile: tls_info.supported_versions должен быть uint16[]' };
      }
    }
  }
  return {
    ok: true,
    profile: /** @type {BoringTlsClienthelloProfileFile} */ (obj),
  };
}

/**
 * Документ профиля для сохранения на диск (компактный JSON).
 * @param {{ tls: Record<string, unknown>, ja3: Record<string, unknown> }} handshakeOk — результат tlsClientHandshakeProfileFromTcpBuf при ok:true (поля tls/ja3)
 * @param {string} userAgent
 */
export function buildCompactProfileDocument(handshakeOk, userAgent) {
  if (
    !handshakeOk ||
    typeof handshakeOk !== 'object' ||
    !('ja3' in handshakeOk) ||
    !('tls' in handshakeOk)
  ) {
    throw new Error('buildCompactProfileDocument: ожидается успешный профиль handshake');
  }
  const p = /** @type {{ tls: Record<string, unknown>, ja3: Record<string, unknown> }} */ (handshakeOk);
  const comp = /** @type {Record<string, unknown>} */ (p.ja3.components || {});
  const tls = p.tls || {};
  const alpn = tls.offered_alpn_protocols;
  const sv = tls.supported_versions_extension;
  return {
    schema_version: BORING_TLS_CLIENTHELLO_SCHEMA_VERSION,
    user_agent: userAgent,
    legacy_version: comp.legacy_version_decimal,
    cipher_suites: comp.cipher_suites_decimal_grease_filtered,
    extension_types: comp.extension_types_decimal_grease_filtered,
    supported_groups: comp.supported_groups_decimal_grease_filtered,
    ec_point_formats: comp.ec_point_formats_decimal,
    ja3_string: p.ja3.string_before_md5,
    ja3_md5: p.ja3.md5,
    tls_info: {
      alpn: Array.isArray(alpn) ? [...alpn] : [],
      supported_versions: Array.isArray(sv) ? [...sv] : [],
    },
  };
}

/**
 * Объект для поля `client_hello_profile` в JSON конфигурации boring-tls-helper.
 * ec_point_formats передаются для будущих версий helper (сейчас могут игнорироваться стеком).
 * @param {BoringTlsClienthelloProfileFile} profile
 * @param {{ ja3Strict?: boolean }} [opts]
 */
export function profileFileToHelperClientHelloBlock(profile, opts = {}) {
  const ja3Strict = Boolean(opts.ja3Strict);
  /** @type {Record<string, unknown>} */
  const out = {
    cipher_suites: [...profile.cipher_suites],
    supported_groups: [...profile.supported_groups],
    ec_point_formats: [...profile.ec_point_formats],
  };
  if (profile.ja3_md5) {
    out.ja3_md5 = profile.ja3_md5;
    out.ja3_strict = ja3Strict;
  }
  return out;
}

/**
 * @param {string} filePath
 * @param {unknown} doc
 */
export function atomicWriteJsonFileSync(filePath, doc) {
  const dir = path.dirname(filePath);
  const base = path.basename(filePath);
  const tmp = path.join(dir, `.${base}.${process.pid}.${Date.now()}.tmp`);
  const json = `${JSON.stringify(doc, null, 2)}\n`;
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(tmp, json, 'utf8');
  fs.renameSync(tmp, filePath);
}

/**
 * Читает и валидирует профиль с диска.
 * @param {string} filePath
 */
export function readClienthelloProfileFileSync(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`boring-tls profile: невалидный JSON (${filePath})`);
  }
  const v = validateBoringTlsClienthelloProfileFile(parsed);
  if (!v.ok) throw new Error(`${v.error} (${filePath})`);
  return v.profile;
}

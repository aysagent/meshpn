/**
 * Файл профиля ClientHello / JA3 для boring-tls-helper (schema v1).
 * См. scripts/boring-tls-plan.md — поток mini-сервер → JSON → clean-vpn client.
 */

import fs from 'fs';
import path from 'path';
import { MESHVPN_OPAQUE_EXTENSION_SKIP_TYPES } from './tls-clienthello-ja3.mjs';

export const BORING_TLS_CLIENTHELLO_SCHEMA_VERSION = '1';

/**
 * @typedef {{
 *   fingerprint: string,
 *   ja4_a?: string,
 *   ja4_b?: string,
 *   ja4_c?: string,
 * }} BoringTlsProfileJa4Block
 */

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
 *   ja3_sorted_string?: string,
 *   ja3_sorted_md5?: string,
 *   ja4?: BoringTlsProfileJa4Block,
 *   permute_extensions?: boolean,
 *   // Явно из экспорта ja3-snif: false — helper не вызывает SSL_set_tlsext_host_name (JA4_a «i»). Если ключ отсутствует — считается true (без SNI ломается verify на многих CDN).
 *   clienthello_emit_sni?: boolean,
 *   tls_info?: { alpn?: string[], supported_versions?: number[] },
 *   signature_algorithms?: number[],
 *   signature_algorithms_cert?: number[],
 *   // Opaque расширения для патча BoringSSL (type + hex тело с захвата)
 *   client_hello_extra_extensions?: { type: number, hex: string }[],
 *   opaque_extension_skip_types_decimal?: number[],
 *   extension_types_note?: string,
 * }} BoringTlsClienthelloProfileFile
 */

/** FoxIO JA4 fingerprint: `ja4_a_ja4_b_ja4_c` */
function validateJa4FingerprintString(s) {
  if (typeof s !== 'string' || s.length < 10) return false;
  const parts = s.split('_');
  if (parts.length !== 3) return false;
  const [a, b, c] = parts;
  if (!/^t\d{2}[di]\d{4}[\s\S]{2}$/.test(a)) return false;
  if (!/^[0-9a-f]{12}$/.test(b) || !/^[0-9a-f]{12}$/.test(c)) return false;
  return true;
}

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
  if (p.ja3_sorted_md5 !== undefined) {
    if (typeof p.ja3_sorted_md5 !== 'string' || !/^[0-9a-f]{32}$/.test(p.ja3_sorted_md5)) {
      return { ok: false, error: 'profile: ja3_sorted_md5 должен быть 32 lowercase hex' };
    }
  }
  if (p.ja3_sorted_string !== undefined && typeof p.ja3_sorted_string !== 'string') {
    return { ok: false, error: 'profile: ja3_sorted_string должно быть строкой' };
  }
  if (p.permute_extensions !== undefined && typeof p.permute_extensions !== 'boolean') {
    return { ok: false, error: 'profile: permute_extensions должен быть boolean' };
  }
  if (p.clienthello_emit_sni !== undefined && typeof p.clienthello_emit_sni !== 'boolean') {
    return { ok: false, error: 'profile: clienthello_emit_sni должен быть boolean' };
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
  const checkUint16ArrOpt = (key) => {
    const v = p[key];
    if (v === undefined) return true;
    if (!Array.isArray(v)) return false;
    return v.every((x) => isUint16(x));
  };
  if (!checkUint16ArrOpt('signature_algorithms')) {
    return { ok: false, error: 'profile: signature_algorithms должен быть uint16[]' };
  }
  if (!checkUint16ArrOpt('signature_algorithms_cert')) {
    return { ok: false, error: 'profile: signature_algorithms_cert должен быть uint16[]' };
  }

  if (p.client_hello_extra_extensions !== undefined) {
    if (!Array.isArray(p.client_hello_extra_extensions)) {
      return { ok: false, error: 'profile: client_hello_extra_extensions должен быть массивом' };
    }
    for (let i = 0; i < p.client_hello_extra_extensions.length; i++) {
      const row = p.client_hello_extra_extensions[i];
      if (!row || typeof row !== 'object') {
        return { ok: false, error: `profile: client_hello_extra_extensions[${i}] не объект` };
      }
      const r = /** @type {Record<string, unknown>} */ (row);
      if (!isUint16(r.type)) {
        return { ok: false, error: `profile: client_hello_extra_extensions[${i}].type — uint16` };
      }
      if (typeof r.hex !== 'string') {
        return { ok: false, error: `profile: client_hello_extra_extensions[${i}].hex — строка hex` };
      }
      const compact = r.hex.replace(/\s+/g, '');
      if (!/^[0-9a-fA-F]*$/.test(compact)) {
        return { ok: false, error: `profile: client_hello_extra_extensions[${i}].hex — только hex` };
      }
      if (compact.length % 2 !== 0) {
        return { ok: false, error: `profile: client_hello_extra_extensions[${i}].hex — чётная длина` };
      }
    }
  }

  if (p.ja4 !== undefined) {
    if (!p.ja4 || typeof p.ja4 !== 'object') return { ok: false, error: 'profile: ja4 должен быть объектом' };
    const j4 = /** @type {Record<string, unknown>} */ (p.ja4);
    if (typeof j4.fingerprint !== 'string' || !validateJa4FingerprintString(j4.fingerprint)) {
      return { ok: false, error: 'profile: ja4.fingerprint — строка FoxIO JA4 (t…_12hex_12hex)' };
    }
    for (const key of ['ja4_a', 'ja4_b', 'ja4_c']) {
      const v = j4[key];
      if (v !== undefined && typeof v !== 'string') {
        return { ok: false, error: `profile: ja4.${key} должно быть строкой` };
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
 * @param {{
 *   tls: Record<string, unknown>,
 *   ja3: Record<string, unknown>,
 *   ja3_sorted?: Record<string, unknown>,
 *   ja4?: { fingerprint?: string, ja4_a?: string, ja4_b?: string, ja4_c?: string, error?: string },
 *   client_hello_extra_extensions?: { type: number, hex: string }[],
 * }} handshakeOk — результат `tlsClientHandshakeProfileFromTcpBuf` или `tlsClientHandshakeProfileWithJa4FromTcpBuf` при ok:true
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
  const p = /** @type {{
    tls: Record<string, unknown>,
    ja3: Record<string, unknown>,
    ja3_sorted?: Record<string, unknown>,
    ja4?: { fingerprint?: string, ja4_a?: string, ja4_b?: string, ja4_c?: string, error?: string },
    client_hello_extra_extensions?: { type: number, hex: string }[],
  }} */ (handshakeOk);
  const comp = /** @type {Record<string, unknown>} */ (p.ja3.components || {});
  const tls = p.tls || {};
  const alpn = tls.offered_alpn_protocols;
  const sv = tls.supported_versions_extension;
  const sorted = p.ja3_sorted && typeof p.ja3_sorted === 'object' ? p.ja3_sorted : null;
  const extTypesArr = /** @type {unknown[]} */ (
    Array.isArray(comp.extension_types_decimal_grease_filtered)
      ? comp.extension_types_decimal_grease_filtered
      : []
  );
  const hasSniExt = extTypesArr.includes(0);
  /** @type {Record<string, unknown>} */
  const doc = {
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
    ...(tls.signature_algorithms &&
    Array.isArray(tls.signature_algorithms) &&
    tls.signature_algorithms.length > 0
      ? { signature_algorithms: [...tls.signature_algorithms] }
      : {}),
    ...(tls.signature_algorithms_cert &&
    Array.isArray(tls.signature_algorithms_cert) &&
    tls.signature_algorithms_cert.length > 0
      ? { signature_algorithms_cert: [...tls.signature_algorithms_cert] }
      : {}),
    /** Совпадает с наличием расширения server_name (0) в списке JA3 — для эталона JA4_a в файле; clean-vpn всегда шлёт SNI в helper. */
    clienthello_emit_sni: hasSniExt,
    /** Как у Chromium: порядок расширений на wire меняется между сессиями; ja3_sorted_md5 стабилен. */
    permute_extensions: true,
    opaque_extension_skip_types_decimal: [...MESHVPN_OPAQUE_EXTENSION_SKIP_TYPES].sort(
      (a, b) => a - b,
    ),
    extension_types_note:
      'extension_types — порядок типов расширений как в JA3 (на проводе), без статического GREASE из набора RFC8701 и без динамического GREASE типа расширения. Типы из opaque_extension_skip_types_decimal не попадают в client_hello_extra_extensions: их добавляет стек/helper (в т.ч. 41 pre_shared_key); при необходимости паритет с браузером — профиль BoringSSL/Meshvpn, а не пропуск экспорта.',
  };
  if (
    Array.isArray(p.client_hello_extra_extensions) &&
    p.client_hello_extra_extensions.length > 0
  ) {
    doc.client_hello_extra_extensions = p.client_hello_extra_extensions.map((e) => ({
      type: e.type,
      hex: typeof e.hex === 'string' ? e.hex.replace(/\s+/g, '') : '',
    }));
  }
  if (sorted && typeof sorted.md5 === 'string') {
    doc.ja3_sorted_md5 = sorted.md5;
  }
  if (sorted && typeof sorted.string_before_md5 === 'string') {
    doc.ja3_sorted_string = sorted.string_before_md5;
  }
  const j4 = p.ja4 && typeof p.ja4 === 'object' ? p.ja4 : null;
  if (
    j4 &&
    typeof j4.fingerprint === 'string' &&
    validateJa4FingerprintString(j4.fingerprint) &&
    j4.error === undefined
  ) {
    doc.ja4 = {
      fingerprint: j4.fingerprint,
      ...(typeof j4.ja4_a === 'string' ? { ja4_a: j4.ja4_a } : {}),
      ...(typeof j4.ja4_b === 'string' ? { ja4_b: j4.ja4_b } : {}),
      ...(typeof j4.ja4_c === 'string' ? { ja4_c: j4.ja4_c } : {}),
    };
  }
  return doc;
}

/**
 * Объект для поля `client_hello_profile` в JSON конфигурации boring-tls-helper.
 * ec_point_formats передаются для будущих версий helper (сейчас могут игнорироваться стеком).
 * @param {BoringTlsClienthelloProfileFile} profile
 * @param {{ ja3Strict?: boolean }} [opts]
 */
export function profileFileToHelperClientHelloBlock(profile, opts = {}) {
  const ja3Strict = Boolean(opts.ja3Strict);
  const permute =
    profile.permute_extensions !== undefined ? profile.permute_extensions : true;

  if (ja3Strict && permute) {
    throw new Error(
      'boring-tls profile: ja3_strict несовместим с permute_extensions; задайте permute_extensions:false в JSON профиля или отключите --boring-tls-profile-ja3-strict',
    );
  }

  /** @type {Record<string, unknown>} */
  const out = {
    cipher_suites: [...profile.cipher_suites],
    supported_groups: [...profile.supported_groups],
    ec_point_formats: [...profile.ec_point_formats],
    permute_extensions: permute,
    extension_types: [...profile.extension_types],
  };

  if (profile.signature_algorithms && profile.signature_algorithms.length > 0) {
    out.signature_algorithms = [...profile.signature_algorithms];
  }
  if (profile.signature_algorithms_cert && profile.signature_algorithms_cert.length > 0) {
    out.signature_algorithms_cert = [...profile.signature_algorithms_cert];
  }

  /**
   * Всегда true для IPC helper: профиль часто снят к локальному ja3-snif по IP — в захвате нет SNI, но к прод-хосту без SNI
   * CDN отдают чужой сертификат → CERTIFICATE_VERIFY_FAILED при verify_host. Поле clienthello_emit_sni в JSON остаётся
   * справочным для эталона JA4 из экспорта; clean-vpn на реальное соединение всегда шлёт server_name.
   */
  out.emit_sni = true;

  const omitWireJa3Expectation = permute && !ja3Strict;
  if (profile.ja3_md5 && !omitWireJa3Expectation) {
    out.ja3_md5 = profile.ja3_md5;
    out.ja3_strict = ja3Strict;
  }
  if (profile.ja3_string && !omitWireJa3Expectation) {
    out.ja3_string = profile.ja3_string;
  }
  if (
    profile.ja4 &&
    typeof profile.ja4 === 'object' &&
    typeof profile.ja4.fingerprint === 'string' &&
    validateJa4FingerprintString(profile.ja4.fingerprint)
  ) {
    out.ja4 = { fingerprint: profile.ja4.fingerprint };
  }
  if (
    Array.isArray(profile.client_hello_extra_extensions) &&
    profile.client_hello_extra_extensions.length > 0
  ) {
    out.client_hello_extra_extensions = profile.client_hello_extra_extensions.map((e) => ({
      type: e.type,
      hex: typeof e.hex === 'string' ? e.hex.replace(/\s+/g, '').toLowerCase() : '',
    }));
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

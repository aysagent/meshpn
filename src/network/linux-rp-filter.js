import fs from 'fs';

function confPath(name) {
  return `/proc/sys/net/ipv4/conf/${name}/rp_filter`;
}

function readRpFilter(name) {
  try {
    const p = confPath(name);
    if (fs.existsSync(p)) {
      return fs.readFileSync(p, 'utf8').trim();
    }
  } catch {
    /* ignore */
  }
  return null;
}

function writeRpFilter(name, value) {
  try {
    fs.writeFileSync(confPath(name), `${String(value).trim()}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/**
 * Loose reverse-path filter — иначе при tun + split-default ядро может отбрасывать
 * входящий UDP от TURN (ICE consent / медиа), симптом ~30s затем ICE failed на обоих пирах.
 * @param {string[]} ifaceNames имена интерфейсов (eth0, tun0, …)
 * @param {string} logPrefix
 * @returns {Record<string, string>|null} снимок для restore
 */
export function applyLooseRpFilterForVpn(ifaceNames, logPrefix = '[NET]') {
  const uniq = [...new Set((ifaceNames || []).filter(Boolean))];
  const names = ['all', 'default', ...uniq];
  /** @type {Record<string, string>} */
  const backup = {};
  for (const n of names) {
    if (!fs.existsSync(confPath(n))) {
      continue;
    }
    const cur = readRpFilter(n);
    if (cur === null) {
      continue;
    }
    if (writeRpFilter(n, '2')) {
      backup[n] = cur;
    }
  }
  if (Object.keys(backup).length > 0) {
    console.log(
      `${logPrefix} rp_filter=2 (loose): ${Object.keys(backup).join(', ')} — для приёма UDP от TURN при policy routing`,
    );
  }
  return Object.keys(backup).length > 0 ? backup : null;
}

/**
 * @param {Record<string, string>|null|undefined} backup
 * @param {string} logPrefix
 */
export function restoreRpFilterBackup(backup, logPrefix = '[NET]') {
  if (!backup || typeof backup !== 'object') {
    return;
  }
  for (const [n, v] of Object.entries(backup)) {
    if (v != null && String(v) !== '') {
      writeRpFilter(n, v);
    }
  }
  console.log(`${logPrefix} rp_filter восстановлен из снимка`);
}

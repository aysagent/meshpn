import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const requireAddon = createRequire(import.meta.url);
const TUN_LINUX_ADDON = path.join(__dirname, '../../../native/tun_linux/build/Release/tun_linux.node');

/** @type {{ open: (name: string) => object, originalDstIpv4FromFd?: (fd: number) => object } | null} */
let tunLinuxAddonCache = null;

export function loadTunLinuxAddon() {
  if (tunLinuxAddonCache) return tunLinuxAddonCache;
  try {
    tunLinuxAddonCache = requireAddon(TUN_LINUX_ADDON);
  } catch (e) {
    throw new Error(
      `Не удалось загрузить native TUN (${TUN_LINUX_ADDON}). Соберите: npm run build:tun-linux`,
      { cause: e },
    );
  }
  return tunLinuxAddonCache;
}

/**
 * @param {string} tunName
 */
export function openTunLinux(tunName) {
  const addon = loadTunLinuxAddon();
  const tun = addon.open(tunName);
  return { tun, name: tun.ifname };
}

/** @param {number} fd */
export function originalDstIpv4FromFdLinux(fd) {
  const addon = loadTunLinuxAddon();
  if (typeof addon.originalDstIpv4FromFd !== 'function') {
    throw new Error('tun_linux без originalDstIpv4FromFd — пересоберите addon');
  }
  return addon.originalDstIpv4FromFd(fd);
}

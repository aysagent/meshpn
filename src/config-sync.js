import https from 'https';
import http from 'http';
import { EventEmitter } from 'events';

/**
 * Периодически скачивает конфиг с remoteConfig.url и применяет изменения.
 *
 * Горячее обновление (без рестарта) — HOT_RELOAD_KEYS:
 *   signallingServer, iceServers, turnServers, exitNodePreference,
 *   logLevel, routing.*, remoteConfig.intervalMs
 *
 * Рестарт требуется — RESTART_REQUIRED_KEYS (только логируем предупреждение):
 *   enableTun, nat.*, virtualNetwork, privateKey, dataServerPort
 */
const HOT_RELOAD_KEYS = new Set([
  'signallingServer',
  'iceServers',
  'turnServers',
  'exitNodePreference',
  'logLevel',
  'routing',
  'remoteConfig',
]);

const RESTART_REQUIRED_KEYS = new Set([
  'enableTun',
  'nat',
  'virtualNetwork',
  'privateKey',
  'dataServerPort',
]);

export class ConfigSync extends EventEmitter {
  /**
   * @param {object} node — инстанс MeshNode
   * @param {object} currentConfig — текущий конфиг (мутируется при горячих обновлениях)
   */
  constructor(node, currentConfig) {
    super();
    this.node = node;
    this.config = currentConfig;
    this._timer = null;
  }

  start() {
    const rc = this.config.remoteConfig;
    if (!rc || !rc.url) {
      return; // Синхронизация отключена
    }

    const intervalMs = rc.intervalMs || 300000;
    console.log(`[ConfigSync] Remote config sync enabled: ${rc.url} every ${intervalMs}ms`);
    this._scheduleNext(intervalMs);
  }

  stop() {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }

  _scheduleNext(intervalMs) {
    this._timer = setTimeout(async () => {
      await this._sync();
      // Перечитываем intervalMs — он мог измениться
      const newIntervalMs = this.config.remoteConfig?.intervalMs || 300000;
      this._scheduleNext(newIntervalMs);
    }, intervalMs);
  }

  async _sync() {
    const rc = this.config.remoteConfig;
    if (!rc || !rc.url) return;

    let remoteConfig;
    try {
      remoteConfig = await this._fetchJson(rc.url);
    } catch (err) {
      console.warn(`[ConfigSync] Failed to fetch remote config: ${err.message}`);
      return;
    }

    const diff = this._diff(this.config, remoteConfig);
    if (Object.keys(diff).length === 0) {
      return; // Нет изменений
    }

    console.log(`[ConfigSync] Remote config diff keys: ${Object.keys(diff).join(', ')}`);
    this._applyDiff(diff);
  }

  /** Возвращает shallow-diff: только топ-уровневые ключи, которые изменились. */
  _diff(current, incoming) {
    const diff = {};
    for (const [key, val] of Object.entries(incoming)) {
      if (JSON.stringify(current[key]) !== JSON.stringify(val)) {
        diff[key] = val;
      }
    }
    return diff;
  }

  _applyDiff(diff) {
    const hotKeys = [];
    const restartKeys = [];

    for (const key of Object.keys(diff)) {
      if (RESTART_REQUIRED_KEYS.has(key)) {
        restartKeys.push(key);
      } else if (HOT_RELOAD_KEYS.has(key)) {
        hotKeys.push(key);
      }
    }

    if (restartKeys.length > 0) {
      console.warn(
        `[ConfigSync] Changes to ${restartKeys.join(', ')} require a node restart to take effect.`,
      );
    }

    for (const key of hotKeys) {
      const oldVal = this.config[key];
      const newVal = diff[key];
      this.config[key] = newVal;
      console.log(`[ConfigSync] Hot-reloaded: ${key}`);

      if (key === 'signallingServer') {
        this._applySignallingServerChange(newVal);
      } else if (key === 'iceServers' || key === 'turnServers') {
        this._applyIceServersChange();
      } else if (key === 'exitNodePreference') {
        this.node.preferredExitNode = newVal || null;
        this.node.router._rebuildActiveRoutes();
      } else if (key === 'routing') {
        this._applyRoutingChange(newVal, oldVal);
      }
    }

    this.emit('config-updated', diff);
  }

  _applySignallingServerChange(newUrl) {
    if (!this.node.discovery?.signalling) return;
    const signalling = this.node.discovery.signalling;
    if (signalling.serverUrl === newUrl) return;

    console.log(`[ConfigSync] Switching signalling server: ${signalling.serverUrl} → ${newUrl}`);
    signalling.disconnect();
    signalling.serverUrl = newUrl;
    signalling.connect(signalling.role).catch((err) => {
      if (err.code !== 'ABORTED') {
        console.error('[ConfigSync] Failed to connect to new signalling server:', err.message);
      }
    });
  }

  _applyIceServersChange() {
    // ICE servers обновляются в конфиге — подхватятся при следующем WebRTC offer
    console.log('[ConfigSync] ICE/TURN servers updated (applied to next WebRTC connection)');
  }

  _applyRoutingChange(newRouting, oldRouting) {
    const newInterval = newRouting?.updateIntervalMs;
    const oldInterval = oldRouting?.updateIntervalMs;
    if (newInterval && newInterval !== oldInterval) {
      this.node.router.stop();
      this.node.router._updateIntervalMs = newInterval;
      this.node.router.start();
      console.log(`[ConfigSync] Routing update interval changed to ${newInterval}ms`);
    }
  }

  _fetchJson(url) {
    return new Promise((resolve, reject) => {
      const lib = url.startsWith('https') ? https : http;
      const req = lib.get(url, { timeout: 10000 }, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}`));
          res.resume();
          return;
        }
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            reject(new Error(`Invalid JSON: ${err.message}`));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
    });
  }
}

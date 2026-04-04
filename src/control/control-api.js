import { createServer } from 'http';

/**
 * HTTP Control API — позволяет менять exit/relay-предпочтения и смотреть статус без рестарта.
 *
 * Включается если в конфиге задан controlPort (и опционально controlApiToken).
 * Все запросы к /api/* требуют заголовка Authorization: Bearer <token> (если token задан).
 *
 * Endpoints:
 *   GET  /api/status          — статус ноды, пиры, маршруты
 *   GET  /api/routes          — activeRoutes из router
 *   POST /api/routes/exit     — { preferredExit: "<nodeId>" | null }
 *   POST /api/routes/relay    — { preferredRelay: "<nodeId>" | null }
 *   POST /api/routes/refresh  — принудительный пересчёт маршрутов
 */
export class ControlApi {
  constructor(node, config) {
    this.node = node;
    this.port = config.controlPort;
    this.token = config.controlApiToken || null;
    this._server = null;
  }

  start() {
    if (!this.port) return;

    this._server = createServer((req, res) => {
      this._handleRequest(req, res);
    });

    this._server.listen(this.port, '127.0.0.1', () => {
      console.log(`[ControlAPI] Listening on 127.0.0.1:${this.port}`);
    });

    this._server.on('error', (err) => {
      console.error('[ControlAPI] Server error:', err.message);
    });
  }

  stop() {
    if (this._server) {
      this._server.close();
      this._server = null;
    }
  }

  _handleRequest(req, res) {
    if (this.token) {
      const auth = req.headers['authorization'] || '';
      if (auth !== `Bearer ${this.token}`) {
        this._json(res, 401, { error: 'Unauthorized' });
        return;
      }
    }

    const url = req.url.split('?')[0];

    if (req.method === 'GET' && url === '/api/status') {
      this._json(res, 200, this._getStatus());
      return;
    }

    if (req.method === 'GET' && url === '/api/routes') {
      this._json(res, 200, this._getRoutes());
      return;
    }

    if (req.method === 'POST' && url === '/api/routes/exit') {
      this._readBody(req, (body) => {
        const { preferredExit } = body;
        this.node.preferredExitNode = preferredExit || null;
        this.node.router._rebuildActiveRoutes();
        this._json(res, 200, { ok: true, preferredExit: this.node.preferredExitNode });
      }, res);
      return;
    }

    if (req.method === 'POST' && url === '/api/routes/relay') {
      this._readBody(req, (body) => {
        const { preferredRelay } = body;
        this.node.preferredRelayNode = preferredRelay || null;
        this._json(res, 200, { ok: true, preferredRelay: this.node.preferredRelayNode });
      }, res);
      return;
    }

    if (req.method === 'POST' && url === '/api/routes/refresh') {
      this.node.router._rebuildActiveRoutes();
      this._json(res, 200, { ok: true });
      return;
    }

    this._json(res, 404, { error: 'Not found' });
  }

  _getStatus() {
    const node = this.node;
    const peers = node.discovery ? node.discovery.getAllPeers() : [];
    const exits = node.discovery ? node.discovery.getExitNodes() : [];
    const graphStats = node.router.getGraphStats();

    return {
      nodeId: node.nodeId,
      virtualIp: node.virtualIp || null,
      role: node.role,
      running: node.running,
      peers: peers.map((p) => ({
        nodeId: p.nodeId,
        name: p.name || null,
        role: p.role,
        virtualIp: p.virtualIp,
        externalIp: p.externalIp || null,
        geo: p.geo || null,
      })),
      exitNodes: exits.map((e) => ({
        nodeId: e.nodeId,
        name: e.name || null,
        virtualIp: e.virtualIp,
      })),
      preferredExit: node.preferredExitNode || null,
      preferredRelay: node.preferredRelayNode || null,
      graph: graphStats,
      activeRoutes: this._getRoutes(),
    };
  }

  _getRoutes() {
    const routes = {};
    for (const [key, info] of this.node.router.activeRoutes) {
      routes[key] = {
        route: info.route,
        exitNode: info.exitNode,
        latency: info.latency || null,
        updatedAt: info.updatedAt,
        unavailable: info.unavailable || false,
      };
    }
    return routes;
  }

  _readBody(req, cb, res) {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try {
        const body = data ? JSON.parse(data) : {};
        cb(body);
      } catch {
        this._json(res, 400, { error: 'Invalid JSON' });
      }
    });
  }

  _json(res, status, body) {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    });
    res.end(payload);
  }
}

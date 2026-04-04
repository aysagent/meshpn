import WebSocket from 'ws';
import { EventEmitter } from 'events';

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export class SignallingClient extends EventEmitter {
  constructor(serverUrl, identity, options = {}) {
    super();
    this.serverUrl = serverUrl;
    this.identity = identity;
    this.name = options.name || null;
    this.reconnectInterval = options.reconnectIntervalMs ?? options.reconnectInterval ?? 5000;
    this.pingIntervalMs = options.pingIntervalMs ?? 30000;
    this.ws = null;
    this.connected = false;
    this.registered = false;
    this.virtualIp = null;
    this.reconnectTimer = null;
    this.pingInterval = null;
    this.peers = new Map();
    this.exitNodes = new Map();
    /** Остановка цикла подключения (disconnect / shutdown). */
    this._stopConnecting = false;
    /** Отмена текущей попытки _connectOnce при disconnect(). */
    this._pendingConnectReject = null;
  }

  /**
   * Ждёт доступности сервера: повторяет попытки с экспоненциальным backoff.
   * Начальная задержка 1 с, удваивается до maxReconnectInterval (60 с).
   */
  async connect(role = 'client') {
    this.role = role;
    this._stopConnecting = false;
    let delay = 1000;

    while (!this._stopConnecting) {
      try {
        await this._connectOnce();
        console.log(`[Signalling] Connected to ${this.serverUrl}`);
        delay = 1000; // сброс backoff после успешного подключения
        return;
      } catch (err) {
        if (this._stopConnecting) {
          const e = new Error('Signalling connection aborted');
          e.code = 'ABORTED';
          throw e;
        }
        const detail = err.code ? `${err.message} (${err.code})` : err.message;
        console.warn(
          `[Signalling] ${this.serverUrl} — ${detail} — retry in ${delay}ms`,
        );
        await sleep(delay);
        if (this._stopConnecting) {
          const e = new Error('Signalling connection aborted');
          e.code = 'ABORTED';
          throw e;
        }
        delay = Math.min(delay * 2, 60000);
      }
    }

    const e = new Error('Signalling connection aborted');
    e.code = 'ABORTED';
    throw e;
  }

  _connectOnce() {
    return new Promise((resolve, reject) => {
      // Чистим слушатели предыдущего сокета (если он уже закрыт), чтобы не накапливались
      // между reconnect-циклами и позволить GC собрать объект.
      const prevWs = this.ws;
      if (prevWs && (prevWs.readyState === prevWs.CLOSED || prevWs.readyState === prevWs.CLOSING)) {
        prevWs.removeAllListeners();
      }

      const ws = new WebSocket(this.serverUrl);
      this.ws = ws;
      let settled = false;
      this._pendingConnectReject = reject;

      const finishFail = (err) => {
        if (settled) return;
        settled = true;
        this._pendingConnectReject = null;
        ws.removeAllListeners();
        if (this.ws === ws) {
          this.ws = null;
        }
        reject(err);
      };

      ws.on('open', () => {
        if (settled) return;
        settled = true;
        this._pendingConnectReject = null;
        this.connected = true;
        this.ws = ws;
        this._startPingInterval();
        this._register();
        resolve();
      });

      ws.on('message', (data) => {
        this._handleMessage(data);
      });

      ws.on('close', () => {
        const wasOpen = this.connected;
        this._handleDisconnect(wasOpen);
        if (!settled) {
          finishFail(new Error('WebSocket closed before open'));
        }
      });

      ws.on('error', (err) => {
        if (!this.connected) {
          finishFail(err);
        } else {
          this.emit('error', err);
        }
      });
    });
  }

  _register() {
    const msg = {
      type: 'register',
      nodeId: this.identity.nodeId,
      publicKey: this.identity.exportPublicKey(),
      role: this.role,
    };
    if (this.name) {
      msg.name = this.name;
    }
    this._send(msg);
  }

  _handleMessage(data) {
    try {
      const message = JSON.parse(data.toString());

      switch (message.type) {
        case 'registered':
          this.registered = true;
          this.virtualIp = message.virtualIp;
          this.emit('registered', {
            virtualIp: message.virtualIp,
            networkCidr: message.networkCidr,
          });
          this._requestPeers();
          this._requestExitNodes();
          break;

        case 'peers':
          this._handlePeersList(message.peers);
          break;

        case 'exit-nodes':
          this._handleExitNodesList(message.exitNodes);
          break;

        case 'peer-join':
          this._handlePeerJoin(message.peer);
          break;

        case 'peer-leave':
          this._handlePeerLeave(message.nodeId);
          break;

        case 'signal':
          this.emit('signal', message.from, message.signal);
          break;

        case 'signal-error':
          this.emit('signal-error', message.to, message.error);
          break;

        case 'topology':
          this.emit('topology', message.topology);
          break;

        case 'pong':
          this.emit('pong', message.timestamp);
          break;

        case 'error':
          this.emit('server-error', message.error);
          break;
      }
    } catch (err) {
      console.error('Failed to parse signalling message:', err);
    }
  }

  _handlePeersList(peers) {
    for (const peer of peers) {
      this.peers.set(peer.nodeId, peer);
      if (peer.role === 'exit') {
        this.exitNodes.set(peer.nodeId, peer);
      }
    }
    this.emit('peers-updated', Array.from(this.peers.values()));
  }

  _handleExitNodesList(exitNodes) {
    for (const node of exitNodes) {
      this.exitNodes.set(node.nodeId, node);
    }
    this.emit('exit-nodes-updated', Array.from(this.exitNodes.values()));
  }

  _handlePeerJoin(peer) {
    this.peers.set(peer.nodeId, peer);
    if (peer.role === 'exit') {
      this.exitNodes.set(peer.nodeId, peer);
    }
    this.emit('peer-join', peer);
  }

  _handlePeerLeave(nodeId) {
    this.peers.delete(nodeId);
    this.exitNodes.delete(nodeId);
    this.emit('peer-leave', nodeId);
  }

  /**
   * @param {boolean} wasOpen — было ли соединение установлено (после open).
   */
  _handleDisconnect(wasOpen) {
    this.connected = false;
    this.registered = false;

    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }

    if (wasOpen) {
      this.emit('disconnected');
    }

    if (wasOpen && !this._stopConnecting) {
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect() {
    if (this._stopConnecting || this.reconnectTimer) {
      return;
    }

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      if (this._stopConnecting) {
        return;
      }
      try {
        await this.connect(this.role);
        this.emit('reconnected');
      } catch (err) {
        if (err.code === 'ABORTED' || this._stopConnecting) {
          return;
        }
        console.error('Reconnect failed:', err.message);
        this._scheduleReconnect();
      }
    }, this.reconnectInterval);
  }

  _startPingInterval() {
    this.pingInterval = setInterval(() => {
      this._send({ type: 'ping' });
    }, this.pingIntervalMs);
  }

  _send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  sendSignal(toNodeId, signal) {
    this._send({
      type: 'signal',
      to: toNodeId,
      signal,
    });
  }

  updateTopology(connectedPeers) {
    this._send({
      type: 'topology-update',
      connectedTo: connectedPeers,
    });
  }

  _requestPeers() {
    this._send({ type: 'get-peers' });
  }

  _requestExitNodes() {
    this._send({ type: 'get-exit-nodes' });
  }

  getPeer(nodeId) {
    return this.peers.get(nodeId);
  }

  getAllPeers() {
    return Array.from(this.peers.values());
  }

  getExitNodes() {
    return Array.from(this.exitNodes.values());
  }

  disconnect() {
    this._stopConnecting = true;

    if (this._pendingConnectReject) {
      const rj = this._pendingConnectReject;
      this._pendingConnectReject = null;
      const err = new Error('Signalling connection aborted');
      err.code = 'ABORTED';
      rj(err);
    }

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }

    const hadSession = this.connected;

    if (this.ws) {
      try {
        this.ws.removeAllListeners();
        this.ws.close();
      } catch {
        /* ignore */
      }
      this.ws = null;
    }

    this.connected = false;
    this.registered = false;

    if (hadSession) {
      this.emit('disconnected');
    }
  }
}

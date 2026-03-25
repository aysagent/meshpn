import { PeerConnection, setSctpSettings } from 'node-datachannel';
import { EventEmitter } from 'events';
import { TransportSendBuffer, unframe } from './send-buffer.js';

const SCTP_DEFAULTS = {
  recvBufferSize: 16 * 1024 * 1024,
  sendBufferSize: 16 * 1024 * 1024,
  maxChunksOnQueue: 32768,
  initialCongestionWindow: 65535,
  delayedSackTime: 2,
};

setSctpSettings(SCTP_DEFAULTS);

const DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' }
];

/**
 * Convert werift-style ICE server objects to node-datachannel string format.
 * Filters by iceMode (auto/relay/direct).
 */
function convertIceServers(servers, iceMode) {
  const result = [];
  for (const s of servers) {
    const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
    for (const url of urls) {
      if (!url) continue;
      const isStun = url.startsWith('stun:');
      const isTurn = url.startsWith('turn:') || url.startsWith('turns:');

      if (iceMode === 'relay' && isStun) continue;
      if (iceMode === 'direct' && isTurn) continue;

      if (isTurn && (s.username || s.credential)) {
        const proto = url.startsWith('turns:') ? 'turns' : 'turn';
        const addr = url.replace(/^turns?:/, '');
        result.push(`${proto}:${s.username}:${s.credential}@${addr}`);
      } else {
        result.push(url);
      }
    }
  }
  return result;
}

export class WebRTCTransport extends EventEmitter {
  constructor(config = {}) {
    super();
    this.iceMode = config.iceMode || 'auto';
    this.dcMode = config.dcMode || 'reliable';
    this.rawIceServers = config.iceServers || DEFAULT_ICE_SERVERS;
    this.ndcIceServers = convertIceServers(this.rawIceServers, this.iceMode);

    if (config.sctp && typeof config.sctp === 'object') {
      setSctpSettings({ ...SCTP_DEFAULTS, ...config.sctp });
      console.log('[WebRTC] SCTP settings merged from config');
    }

    /** Сколько IP-пакетов держим в агрегаторе до flush (iperf -R / TURN — выше = меньше дропов). */
    this.sendBufferMaxQueue = config.sendBufferMaxQueue ?? 2000;
    /** Очередь поверх DC при полном TransportSendBuffer; 0 = не использовать overflow. */
    this.sendOverflowMax = config.sendOverflowMax ?? 8000;
    /** Порог bufferedAmount на DC: ниже — чаще ждём, выше — больше памяти, меньше «Failed to forward». */
    this.dcBufferedHighWater = config.dcBufferedHighWater ?? 8 * 1024 * 1024;
    this.dcBufferedLowWater = config.dcBufferedLowWater ?? 512 * 1024;
    /** @type {Map<string, Buffer[]>} очередь при полном TransportSendBuffer */
    this._sendOverflow = new Map();
    /** Сколько раз send() остановился из‑за полной overflow (backpressure). */
    this._overflowBlocked = 0;

    this.connections = new Map();
    this.dataChannels = new Map();
    this.sendBuffers = new Map();
    this._descriptionResolvers = new Map();
    /** После setRemoteDescription можно вызывать addRemoteCandidate (до этого — очередь). */
    this._remoteDescForTrickle = new Set();
    /** peerId -> список { candidateStr, mid } */
    this._pendingRemoteIce = new Map();
    /** Слить PC terminal + DC close в одно событие; отмена при новом PC для того же peerId (replace). */
    this._peerDisconnectEmitTimer = new Map();
    /** Монотонный счётчик поколения PC на peerId — игнорируем disconnect от предыдущего PC/DC. */
    this._connectionEpoch = new Map();
    /** peerId -> epoch, в котором DC уже был open (onClosed до open при replace не шлём в mesh). */
    this._dcOpenEpoch = new Map();

    const hasTurn = this.ndcIceServers.some(s => s.startsWith('turn:') || s.startsWith('turns:'));

    console.log(`[WebRTC] ICE mode: ${this.iceMode}`);
    console.log(`[WebRTC] DC mode: ${this.dcMode}`);
    console.log(`[WebRTC] ICE servers (${this.ndcIceServers.length}):`);
    for (const s of this.ndcIceServers) {
      const display = s.replace(/:[^:@]+@/, ':***@');
      console.log(`  - ${display}`);
    }
    if (this.iceMode === 'relay' && !hasTurn) {
      console.warn('[WebRTC] WARNING: relay mode but no TURN servers configured!');
    }
    if (this.dcMode === 'performance') {
      console.warn(
        '[WebRTC] dcMode=performance: unordered/unreliable DC — TCP через TUN может ломаться '
        + '(потери/перестановки). Для iperf/стабильности используйте dcMode: reliable.',
      );
    }
  }

  async testTurnConnectivity() {
    const turnOnly = convertIceServers(this.rawIceServers, 'relay');
    if (turnOnly.length === 0) {
      console.log('[WebRTC] No TURN servers configured, skipping connectivity test');
      return { success: false, reason: 'no_turn_servers' };
    }

    console.log('[WebRTC] Testing TURN server connectivity...');
    return new Promise((resolve) => {
      const pc = new PeerConnection('turn-test', {
        iceServers: turnOnly,
        iceTransportPolicy: 'relay',
      });

      let hasRelay = false;
      let resolved = false;

      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          try { pc.destroy(); } catch {}
          const ok = hasRelay;
          console.log(`[WebRTC] TURN test: ${ok ? 'OK' : 'FAILED (no relay candidates after timeout)'}`);
          resolve({ success: ok, reason: ok ? undefined : 'timeout' });
        }
      }, 10000);

      pc.onLocalCandidate((candidate) => {
        if (candidate.includes('typ relay')) {
          hasRelay = true;
          if (!resolved) {
            resolved = true;
            clearTimeout(timeout);
            try { pc.destroy(); } catch {}
            console.log('[WebRTC] TURN test: OK (relay candidate received)');
            resolve({ success: true });
          }
        }
      });

      pc.onGatheringStateChange((state) => {
        if (state === 'complete' && !resolved) {
          resolved = true;
          clearTimeout(timeout);
          try { pc.destroy(); } catch {}
          console.log(`[WebRTC] TURN test: ${hasRelay ? 'OK' : 'FAILED (no relay candidates)'}`);
          resolve({ success: hasRelay, reason: hasRelay ? undefined : 'no_relay_candidates' });
        }
      });

      pc.createDataChannel('test');
    });
  }

  async createOffer(peerId) {
    const { pc, epoch } = this._createPeerConnection(peerId);

    return new Promise((resolve, reject) => {
      this._descriptionResolvers.set(peerId, resolve);

      pc.onLocalDescription((sdp, type) => {
        const resolver = this._descriptionResolvers.get(peerId);
        if (resolver) {
          this._descriptionResolvers.delete(peerId);
          resolver({ type: type.toLowerCase(), sdp });
        }
      });

      const dcOpts = this._getDcOptions();
      const dc = pc.createDataChannel('mesh-vpn', dcOpts);
      this._setupDataChannel(peerId, dc, epoch);
    });
  }

  async handleOffer(peerId, offer) {
    const { pc, epoch } = this._createPeerConnection(peerId);

    return new Promise((resolve) => {
      this._descriptionResolvers.set(peerId, resolve);

      pc.onLocalDescription((sdp, type) => {
        const resolver = this._descriptionResolvers.get(peerId);
        if (resolver) {
          this._descriptionResolvers.delete(peerId);
          resolver({ type: type.toLowerCase(), sdp });
        }
      });

      pc.onDataChannel((dc) => {
        this._setupDataChannel(peerId, dc, epoch);
      });

      pc.setRemoteDescription(offer.sdp, 'Offer');
      this._afterRemoteDescriptionForTrickle(peerId);
    });
  }

  async handleAnswer(peerId, answer) {
    const pc = this.connections.get(peerId);
    if (!pc) {
      throw new Error(`No connection found for peer ${peerId}`);
    }
    pc.setRemoteDescription(answer.sdp, 'Answer');
    this._afterRemoteDescriptionForTrickle(peerId);
  }

  _pushPendingIce(peerId, candidateStr, mid) {
    let q = this._pendingRemoteIce.get(peerId);
    if (!q) {
      q = [];
      this._pendingRemoteIce.set(peerId, q);
    }
    q.push({ candidateStr, mid });
  }

  _afterRemoteDescriptionForTrickle(peerId) {
    this._remoteDescForTrickle.add(peerId);
    this._flushPendingRemoteIce(peerId);
  }

  _flushPendingRemoteIce(peerId) {
    const pc = this.connections.get(peerId);
    if (!pc) {
      return;
    }
    const q = this._pendingRemoteIce.get(peerId);
    if (!q || q.length === 0) {
      return;
    }
    this._pendingRemoteIce.delete(peerId);
    for (const { candidateStr, mid } of q) {
      try {
        pc.addRemoteCandidate(candidateStr, mid);
      } catch (err) {
        console.error(`[WebRTC] Failed to flush ICE candidate for ${peerId}: ${err.message}`);
      }
    }
  }

  async addIceCandidate(peerId, candidate) {
    try {
      const candidateStr = typeof candidate === 'string'
        ? candidate
        : (candidate.candidate || candidate);
      const mid = candidate.mid || candidate.sdpMid || '0';

      if (!this._remoteDescForTrickle.has(peerId)) {
        this._pushPendingIce(peerId, candidateStr, mid);
        return;
      }

      const pc = this.connections.get(peerId);
      if (!pc) {
        this._pushPendingIce(peerId, candidateStr, mid);
        return;
      }

      pc.addRemoteCandidate(candidateStr, mid);
    } catch (err) {
      console.error(`[WebRTC] Failed to add ICE candidate for ${peerId}: ${err.message}`);
    }
  }

  send(peerId, data) {
    const sb = this.sendBuffers.get(peerId);
    if (!sb) return false;

    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (sb.push(buffer)) {
      this._drainSendOverflow(peerId);
      return true;
    }

    if (this.sendOverflowMax <= 0) {
      return false;
    }

    let q = this._sendOverflow.get(peerId);
    if (!q) {
      q = [];
      this._sendOverflow.set(peerId, q);
    }
    // Никогда не выкидываем байты из середины потока — иначе ломается TCP в TUN
    // (iperf3: "Size of data read does not correspond to offered length").
    if (q.length >= this.sendOverflowMax) {
      this._overflowBlocked++;
      return false;
    }
    q.push(buffer);
    return true;
  }

  _drainSendOverflow(peerId) {
    const sb = this.sendBuffers.get(peerId);
    if (!sb) return;
    const q = this._sendOverflow.get(peerId);
    if (!q || q.length === 0) return;
    while (q.length > 0) {
      if (!sb.push(q[0])) break;
      q.shift();
    }
    if (q.length === 0) {
      this._sendOverflow.delete(peerId);
    }
  }

  /** Диагностика: очереди DC / send-buffer / overflow. */
  getSendDiagnostics() {
    const peers = [];
    for (const [peerId, dc] of this.dataChannels) {
      let bufferedAmount = null;
      try {
        bufferedAmount = dc.bufferedAmount();
      } catch {
        bufferedAmount = null;
      }
      const sb = this.sendBuffers.get(peerId);
      peers.push({
        peerId: peerId.substring(0, 12),
        bufferedAmount,
        sendBufferQueued: sb ? sb.getQueueLength() : 0,
        overflowQueued: (this._sendOverflow.get(peerId) || []).length,
      });
    }
    return { peers, overflowBlockedTotal: this._overflowBlocked };
  }

  isConnected(peerId) {
    const dc = this.dataChannels.get(peerId);
    if (!dc) return false;
    try { return dc.isOpen(); } catch { return false; }
  }

  close(peerId) {
    this._remoteDescForTrickle.delete(peerId);
    this._pendingRemoteIce.delete(peerId);

    this._sendOverflow.delete(peerId);

    const sb = this.sendBuffers.get(peerId);
    if (sb) { sb.stop(); this.sendBuffers.delete(peerId); }

    const dc = this.dataChannels.get(peerId);
    if (dc) {
      try { dc.close(); } catch {}
      this.dataChannels.delete(peerId);
    }

    const pc = this.connections.get(peerId);
    if (pc) {
      try { pc.destroy(); } catch {}
      this.connections.delete(peerId);
    }

    this._descriptionResolvers.delete(peerId);
    this._dcOpenEpoch.delete(peerId);
    this._cancelPeerDisconnectEmit(peerId);
  }

  closeAll() {
    for (const peerId of [...this.connections.keys()]) {
      this.close(peerId);
    }
  }

  getConnectedPeers() {
    const connected = [];
    for (const [peerId, dc] of this.dataChannels) {
      try { if (dc.isOpen()) connected.push(peerId); } catch {}
    }
    return connected;
  }

  _getDcOptions() {
    if (this.dcMode === 'performance') {
      return { unordered: true, maxRetransmits: 0 };
    }
    return {};
  }

  _emitPeerDisconnectSoon(peerId) {
    if (this._peerDisconnectEmitTimer.has(peerId)) {
      return;
    }
    const t = setTimeout(() => {
      this._peerDisconnectEmitTimer.delete(peerId);
      this.emit('peer-disconnected', peerId);
    }, 0);
    this._peerDisconnectEmitTimer.set(peerId, t);
  }

  _cancelPeerDisconnectEmit(peerId) {
    const t = this._peerDisconnectEmitTimer.get(peerId);
    if (t != null) {
      clearTimeout(t);
      this._peerDisconnectEmitTimer.delete(peerId);
    }
  }

  _createPeerConnection(peerId) {
    const epoch = (this._connectionEpoch.get(peerId) || 0) + 1;
    this._connectionEpoch.set(peerId, epoch);

    if (this.connections.has(peerId)) {
      this.close(peerId);
    }

    console.log(`[WebRTC] Creating connection to ${peerId} (ice=${this.iceMode}, dc=${this.dcMode})`);

    const pcConfig = {
      iceServers: this.ndcIceServers,
      maxMessageSize: 65536,
    };
    if (this.iceMode === 'relay') {
      pcConfig.iceTransportPolicy = 'relay';
    }

    const pc = new PeerConnection(`pc-${peerId.substring(0, 8)}`, pcConfig);

    pc.onLocalCandidate((candidate, mid) => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      this.emit('ice-candidate', peerId, { candidate, mid });
    });

    pc.onStateChange((state) => {
      // Старый PC после replace всё ещё шлёт disconnected/failed/closed — iperf при этом идёт по новому PC.
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }

      console.log(`[WebRTC] ${peerId.substring(0, 8)}… state: ${state}`);

      if (state === 'connected') {
        this._logSelectedCandidatePair(peerId, pc);
      }

      this.emit('connection-state', peerId, state);

      // Не эмитим при `disconnected` — ICE может кратковременно падать и восстанавливаться;
      // иначе discovery снимает сессию, а ключи не переобмениваются.
      if (state === 'failed' || state === 'closed') {
        this._dcOpenEpoch.delete(peerId);
        this._emitPeerDisconnectSoon(peerId);
      }
    });

    pc.onGatheringStateChange((state) => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      console.log(`[WebRTC] ${peerId.substring(0, 8)}… gathering: ${state}`);
    });

    this.connections.set(peerId, pc);
    return { pc, epoch };
  }

  _logSelectedCandidatePair(peerId, pc) {
    try {
      const pair = pc.getSelectedCandidatePair();
      const l = pair.local;
      const r = pair.remote;
      const isRelay = l.type === 'relay' || r.type === 'relay';
      const tag = isRelay ? 'RELAY (TURN)' : 'DIRECT P2P';
      console.log(`[WebRTC] Path for ${peerId.substring(0, 8)}…: ${l.type} ${l.address}:${l.port} (${l.transportType}) <-> ${r.type} ${r.address}:${r.port} (${r.transportType}) [${tag}]`);

      try {
        const rtt = pc.rtt();
        if (rtt > 0) console.log(`[WebRTC] RTT: ${rtt}ms`);
      } catch {}
    } catch (err) {
      console.log(`[WebRTC] Could not get candidate pair for ${peerId.substring(0, 8)}…: ${err.message}`);
    }
  }

  _setupDataChannel(peerId, dc, epoch) {
    this.dataChannels.set(peerId, dc);

    const DC_HIGH_WATER = this.dcBufferedHighWater;
    const DC_LOW_WATER = this.dcBufferedLowWater;

    dc.onOpen(() => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      this._dcOpenEpoch.set(peerId, epoch);
      console.log(`[WebRTC] DataChannel open for ${peerId.substring(0, 8)}…`);
      const sb = new TransportSendBuffer((frame) => {
        try {
          dc.sendMessageBinary(Buffer.isBuffer(frame) ? frame : Buffer.from(frame));
        } catch {}
      }, {
        isReady: () => {
          try { return dc.bufferedAmount() < DC_HIGH_WATER; } catch { return false; }
        },
        maxQueuePackets: this.sendBufferMaxQueue,
      });
      this.sendBuffers.set(peerId, sb);
      this.emit('peer-connected', peerId);
    });

    dc.onClosed(() => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      if (this._dcOpenEpoch.get(peerId) !== epoch) {
        return;
      }
      this._dcOpenEpoch.delete(peerId);
      console.log(`[WebRTC] DataChannel closed for ${peerId.substring(0, 8)}…`);
      const sb = this.sendBuffers.get(peerId);
      if (sb) { sb.stop(); this.sendBuffers.delete(peerId); }
      this._emitPeerDisconnectSoon(peerId);
    });

    dc.onError((err) => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      console.error(`[WebRTC] DataChannel error for ${peerId.substring(0, 8)}…: ${err}`);
      this.emit('error', peerId, err);
    });

    dc.onMessage((raw) => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      for (const data of unframe(buf)) {
        this.emit('message', peerId, data);
      }
    });

    dc.onBufferedAmountLow(() => {
      if (this._connectionEpoch.get(peerId) !== epoch) {
        return;
      }
      const sb = this.sendBuffers.get(peerId);
      if (sb) sb.resume();
      this._drainSendOverflow(peerId);
      // После внутреннего drain — чтобы MeshNode мог дописать свою очередь повтора.
      process.nextTick(() => this.emit('buffer-low', peerId));
    });
    dc.setBufferedAmountLowThreshold(DC_LOW_WATER);
  }
}

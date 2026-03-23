import { PeerConnection, setSctpSettings } from 'node-datachannel';
import { EventEmitter } from 'events';
import { TransportSendBuffer, unframe } from './send-buffer.js';

setSctpSettings({
  recvBufferSize: 4 * 1024 * 1024,
  sendBufferSize: 4 * 1024 * 1024,
  maxChunksOnQueue: 16384,
  initialCongestionWindow: 65535,
  delayedSackTime: 2,
});

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
    this.dcMode = config.dcMode || 'performance';
    this.rawIceServers = config.iceServers || DEFAULT_ICE_SERVERS;
    this.ndcIceServers = convertIceServers(this.rawIceServers, this.iceMode);

    this.connections = new Map();
    this.dataChannels = new Map();
    this.sendBuffers = new Map();
    this._descriptionResolvers = new Map();

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
    const pc = this._createPeerConnection(peerId);

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
      this._setupDataChannel(peerId, dc);
    });
  }

  async handleOffer(peerId, offer) {
    const pc = this._createPeerConnection(peerId);

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
        this._setupDataChannel(peerId, dc);
      });

      pc.setRemoteDescription(offer.sdp, 'Offer');
    });
  }

  async handleAnswer(peerId, answer) {
    const pc = this.connections.get(peerId);
    if (!pc) {
      throw new Error(`No connection found for peer ${peerId}`);
    }
    pc.setRemoteDescription(answer.sdp, 'Answer');
  }

  async addIceCandidate(peerId, candidate) {
    const pc = this.connections.get(peerId);
    if (!pc) return;

    try {
      const candidateStr = typeof candidate === 'string'
        ? candidate
        : (candidate.candidate || candidate);
      const mid = candidate.mid || candidate.sdpMid || '0';
      pc.addRemoteCandidate(candidateStr, mid);
    } catch (err) {
      console.error(`[WebRTC] Failed to add ICE candidate for ${peerId}: ${err.message}`);
    }
  }

  send(peerId, data) {
    const sb = this.sendBuffers.get(peerId);
    if (!sb) return false;

    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    sb.push(buffer);
    return true;
  }

  isConnected(peerId) {
    const dc = this.dataChannels.get(peerId);
    if (!dc) return false;
    try { return dc.isOpen(); } catch { return false; }
  }

  close(peerId) {
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

  _createPeerConnection(peerId) {
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
      this.emit('ice-candidate', peerId, { candidate, mid });
    });

    pc.onStateChange((state) => {
      console.log(`[WebRTC] ${peerId.substring(0, 8)}… state: ${state}`);

      if (state === 'connected') {
        this._logSelectedCandidatePair(peerId, pc);
      }

      this.emit('connection-state', peerId, state);

      if (state === 'failed' || state === 'disconnected' || state === 'closed') {
        this.emit('peer-disconnected', peerId);
      }
    });

    pc.onGatheringStateChange((state) => {
      console.log(`[WebRTC] ${peerId.substring(0, 8)}… gathering: ${state}`);
    });

    this.connections.set(peerId, pc);
    return pc;
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

  _setupDataChannel(peerId, dc) {
    this.dataChannels.set(peerId, dc);

    const DC_HIGH_WATER = 2 * 1024 * 1024;
    const DC_LOW_WATER = 256 * 1024;

    dc.onOpen(() => {
      console.log(`[WebRTC] DataChannel open for ${peerId.substring(0, 8)}…`);
      const sb = new TransportSendBuffer((frame) => {
        try {
          dc.sendMessageBinary(Buffer.isBuffer(frame) ? frame : Buffer.from(frame));
        } catch {}
      }, {
        isReady: () => {
          try { return dc.bufferedAmount() < DC_HIGH_WATER; } catch { return false; }
        },
      });
      this.sendBuffers.set(peerId, sb);
      this.emit('peer-connected', peerId);
    });

    dc.onClosed(() => {
      console.log(`[WebRTC] DataChannel closed for ${peerId.substring(0, 8)}…`);
      const sb = this.sendBuffers.get(peerId);
      if (sb) { sb.stop(); this.sendBuffers.delete(peerId); }
      this.emit('peer-disconnected', peerId);
    });

    dc.onError((err) => {
      console.error(`[WebRTC] DataChannel error for ${peerId.substring(0, 8)}…: ${err}`);
      this.emit('error', peerId, err);
    });

    dc.onMessage((raw) => {
      const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      for (const data of unframe(buf)) {
        this.emit('message', peerId, data);
      }
    });

    dc.onBufferedAmountLow(() => {
      const sb = this.sendBuffers.get(peerId);
      if (sb) sb.resume();
      this.emit('buffer-low', peerId);
    });
    dc.setBufferedAmountLowThreshold(DC_LOW_WATER);
  }
}

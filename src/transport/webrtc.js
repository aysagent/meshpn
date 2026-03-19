import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate } from 'werift';
import { EventEmitter } from 'events';

const DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' }
];

export class WebRTCTransport extends EventEmitter {
  constructor(config = {}) {
    super();
    this.iceServers = config.iceServers || DEFAULT_ICE_SERVERS;
    this.connections = new Map();
    this.dataChannels = new Map();
    this.relayCandidates = new Map();
    
    this.dataChannelConfig = {
      ordered: config.ordered !== undefined ? config.ordered : true,
      maxRetransmits: config.maxRetransmits
    };
    
    this.bufferedAmountLowThreshold = config.bufferedAmountLowThreshold || 256 * 1024;
    
    this.turnServers = this.iceServers.filter(s => {
      const urls = Array.isArray(s.urls) ? s.urls : [s.urls];
      return urls.some(url => url?.startsWith('turn:') || url?.startsWith('turns:'));
    });
    
    this.hasTurnServers = this.turnServers.length > 0;
    
    if (this.hasTurnServers) {
      console.log(`TURN servers configured: ${this.turnServers.length}`);
      this.turnServers.forEach(server => {
        const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
        urls.forEach(url => console.log(`  - ${url}`));
      });
    }
    
    console.log(`[WebRTC] DataChannel config: ordered=${this.dataChannelConfig.ordered}`);
  }

  async testTurnConnectivity() {
    if (!this.hasTurnServers) {
      console.log('No TURN servers configured, skipping connectivity test');
      return { success: false, reason: 'no_turn_servers' };
    }

    console.log('Testing TURN server connectivity...');
    
    return new Promise((resolve) => {
      const pc = new RTCPeerConnection({
        iceServers: this.turnServers
      });
      
      let hasRelay = false;
      let resolved = false;
      
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          pc.close();
          if (hasRelay) {
            console.log('TURN server test: OK (relay candidates received)');
            resolve({ success: true });
          } else {
            console.error('TURN server test: FAILED (no relay candidates after timeout)');
            console.error('Check: server address, port, firewall, credentials');
            resolve({ success: false, reason: 'timeout' });
          }
        }
      }, 10000);
      
      pc.onicecandidate = (event) => {
        if (event.candidate) {
          const candidateStr = event.candidate.candidate || '';
          if (candidateStr.includes('typ relay')) {
            hasRelay = true;
            if (!resolved) {
              resolved = true;
              clearTimeout(timeout);
              pc.close();
              console.log('TURN server test: OK (relay candidate received)');
              resolve({ success: true });
            }
          }
        }
      };
      
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === 'complete' && !resolved) {
          resolved = true;
          clearTimeout(timeout);
          pc.close();
          if (hasRelay) {
            console.log('TURN server test: OK (relay candidates received)');
            resolve({ success: true });
          } else {
            console.error('TURN server test: FAILED (no relay candidates)');
            console.error('Check: server address, port, firewall, credentials');
            resolve({ success: false, reason: 'no_relay_candidates' });
          }
        }
      };
      
      pc.createDataChannel('test');
      pc.createOffer().then(offer => pc.setLocalDescription(offer));
    });
  }

  async createOffer(peerId) {
    const pc = this._createPeerConnection(peerId);
    
    const dcOptions = {
      ordered: this.dataChannelConfig.ordered
    };
    
    if (this.dataChannelConfig.maxRetransmits !== undefined) {
      dcOptions.maxRetransmits = this.dataChannelConfig.maxRetransmits;
    }
    
    const dc = pc.createDataChannel('mesh-vpn', dcOptions);
    
    this._setupDataChannel(peerId, dc);
    
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    
    return {
      type: 'offer',
      sdp: pc.localDescription.sdp
    };
  }

  async handleOffer(peerId, offer) {
    const pc = this._createPeerConnection(peerId);
    
    pc.ondatachannel = (event) => {
      this._setupDataChannel(peerId, event.channel);
    };
    
    await pc.setRemoteDescription(new RTCSessionDescription(offer.sdp, offer.type));
    
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    
    return {
      type: 'answer',
      sdp: pc.localDescription.sdp
    };
  }

  async handleAnswer(peerId, answer) {
    const pc = this.connections.get(peerId);
    if (!pc) {
      throw new Error(`No connection found for peer ${peerId}`);
    }
    
    await pc.setRemoteDescription(new RTCSessionDescription(answer.sdp, answer.type));
  }

  async addIceCandidate(peerId, candidate) {
    const pc = this.connections.get(peerId);
    if (!pc) {
      return;
    }
    
    try {
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    } catch (err) {
      console.error(`Failed to add ICE candidate for ${peerId}:`, err.message);
    }
  }

  send(peerId, data) {
    const dc = this.dataChannels.get(peerId);
    if (!dc || dc.readyState !== 'open') {
      return false;
    }
    
    // Check buffer overflow - 16MB is typical max, warn at 1MB
    const HIGH_WATER_MARK = 1024 * 1024;
    if (dc.bufferedAmount > HIGH_WATER_MARK) {
      console.warn(`[WebRTC] Buffer high for ${peerId}: ${(dc.bufferedAmount / 1024).toFixed(0)}KB`);
      // Still try to send, but this indicates backpressure issue
    }
    
    try {
      const buffer = typeof data === 'string' ? Buffer.from(data) : data;
      dc.send(buffer);
      return true;
    } catch (err) {
      console.error(`Failed to send to ${peerId}:`, err.message);
      return false;
    }
  }

  isConnected(peerId) {
    const dc = this.dataChannels.get(peerId);
    return dc && dc.readyState === 'open';
  }

  close(peerId) {
    const dc = this.dataChannels.get(peerId);
    if (dc) {
      dc.close();
      this.dataChannels.delete(peerId);
    }
    
    const pc = this.connections.get(peerId);
    if (pc) {
      pc.close();
      this.connections.delete(peerId);
    }
    
    this.relayCandidates.delete(peerId);
  }

  closeAll() {
    for (const peerId of this.connections.keys()) {
      this.close(peerId);
    }
  }

  getConnectedPeers() {
    const connected = [];
    for (const [peerId, dc] of this.dataChannels) {
      if (dc.readyState === 'open') {
        connected.push(peerId);
      }
    }
    return connected;
  }

  _createPeerConnection(peerId) {
    const pc = new RTCPeerConnection({
      iceServers: this.iceServers
    });
    
    this.relayCandidates.set(peerId, false);
    
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        const candidate = event.candidate;
        const candidateStr = candidate.candidate || '';
        
        if (candidateStr.includes('typ relay')) {
          this.relayCandidates.set(peerId, true);
          console.log(`TURN relay candidate gathered for peer ${peerId}`);
        }
        
        this.emit('ice-candidate', peerId, candidate.toJSON());
      }
    };
    
    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === 'complete') {
        const hasRelay = this.relayCandidates.get(peerId);
        if (this.hasTurnServers && !hasRelay) {
          console.warn(`ICE gathering complete for ${peerId}: no relay candidates collected`);
          console.warn('TURN server may be unreachable or credentials may be invalid');
        } else if (hasRelay) {
          console.log(`ICE gathering complete for ${peerId}: relay candidates available`);
        }
      }
    };
    
    pc.oniceconnectionstatechange = () => {
      const state = pc.iceConnectionState;
      
      if (state === 'connected' || state === 'completed') {
        console.log(`ICE connection established for peer ${peerId}`);
      } else if (state === 'failed') {
        console.error(`ICE connection failed for peer ${peerId}`);
        if (this.hasTurnServers) {
          console.error('Check TURN server availability and credentials');
        }
      } else if (state === 'disconnected') {
        console.warn(`ICE connection disconnected for peer ${peerId}`);
      }
    };
    
    pc.onconnectionstatechange = () => {
      this.emit('connection-state', peerId, pc.connectionState);
      
      if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected') {
        this.emit('peer-disconnected', peerId);
      }
    };
    
    this.connections.set(peerId, pc);
    return pc;
  }

  _setupDataChannel(peerId, dc) {
    this.dataChannels.set(peerId, dc);
    
    if (dc.bufferedAmountLowThreshold !== undefined) {
      dc.bufferedAmountLowThreshold = this.bufferedAmountLowThreshold;
    }
    
    dc.onopen = () => {
      this.emit('peer-connected', peerId);
    };
    
    dc.onclose = () => {
      this.emit('peer-disconnected', peerId);
    };
    
    dc.onerror = (err) => {
      this.emit('error', peerId, err);
    };
    
    dc.onmessage = (event) => {
      const data = event.data instanceof ArrayBuffer 
        ? Buffer.from(event.data)
        : event.data;
      this.emit('message', peerId, data);
    };
    
    dc.onbufferedamountlow = () => {
      this.emit('buffer-low', peerId);
    };
  }
}

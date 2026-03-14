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
  }

  async createOffer(peerId) {
    const pc = this._createPeerConnection(peerId);
    
    const dc = pc.createDataChannel('mesh-vpn', {
      ordered: false,
      maxRetransmits: 0
    });
    
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
    
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.emit('ice-candidate', peerId, event.candidate.toJSON());
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
  }
}

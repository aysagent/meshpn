import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from 'crypto';

export class SessionKeyExchange {
  constructor() {
    this.privateKey = randomBytes(32);
    this.publicKey = x25519.getPublicKey(this.privateKey);
  }

  deriveSharedSecret(peerPublicKey) {
    const peerPubBuffer = typeof peerPublicKey === 'string'
      ? Buffer.from(peerPublicKey, 'base64')
      : peerPublicKey;
    
    return x25519.getSharedSecret(this.privateKey, peerPubBuffer);
  }

  deriveSessionKey(peerPublicKey, info = 'mesh-vpn-session') {
    const sharedSecret = this.deriveSharedSecret(peerPublicKey);
    
    const sessionKey = hkdf(sha256, sharedSecret, undefined, info, 32);
    
    return Buffer.from(sessionKey);
  }

  exportPublicKey() {
    return Buffer.from(this.publicKey).toString('base64');
  }
}

export class SessionManager {
  constructor() {
    this.sessions = new Map();
  }

  createSession(peerId) {
    const keyExchange = new SessionKeyExchange();
    this.sessions.set(peerId, {
      keyExchange,
      sessionKey: null,
      established: false
    });
    return keyExchange.exportPublicKey();
  }

  completeSession(peerId, peerPublicKey) {
    const session = this.sessions.get(peerId);
    if (!session) {
      throw new Error(`No session found for peer ${peerId}`);
    }
    
    session.sessionKey = session.keyExchange.deriveSessionKey(peerPublicKey);
    session.established = true;
    
    return session.sessionKey;
  }

  getSessionKey(peerId) {
    const session = this.sessions.get(peerId);
    if (!session || !session.established) {
      return null;
    }
    return session.sessionKey;
  }

  hasSession(peerId) {
    const session = this.sessions.get(peerId);
    return session && session.established;
  }

  removeSession(peerId) {
    this.sessions.delete(peerId);
  }

  clear() {
    this.sessions.clear();
  }
}

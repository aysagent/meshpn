import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from 'crypto';

export class Identity {
  constructor(privateKey = null) {
    if (privateKey) {
      this.privateKey = typeof privateKey === 'string' 
        ? Buffer.from(privateKey, 'base64') 
        : privateKey;
    } else {
      this.privateKey = randomBytes(32);
    }
    this.publicKey = ed25519.getPublicKey(this.privateKey);
  }

  get nodeId() {
    return Buffer.from(this.publicKey).toString('base64url').slice(0, 16);
  }

  sign(message) {
    const msgBuffer = typeof message === 'string' 
      ? Buffer.from(message) 
      : message;
    return ed25519.sign(msgBuffer, this.privateKey);
  }

  static verify(message, signature, publicKey) {
    const msgBuffer = typeof message === 'string' 
      ? Buffer.from(message) 
      : message;
    const sigBuffer = typeof signature === 'string'
      ? Buffer.from(signature, 'base64')
      : signature;
    const pubBuffer = typeof publicKey === 'string'
      ? Buffer.from(publicKey, 'base64')
      : publicKey;
    
    try {
      return ed25519.verify(sigBuffer, msgBuffer, pubBuffer);
    } catch {
      return false;
    }
  }

  exportPrivateKey() {
    return Buffer.from(this.privateKey).toString('base64');
  }

  exportPublicKey() {
    return Buffer.from(this.publicKey).toString('base64');
  }

  static fromPrivateKey(privateKeyBase64) {
    return new Identity(privateKeyBase64);
  }

  toJSON() {
    return {
      nodeId: this.nodeId,
      publicKey: this.exportPublicKey()
    };
  }
}

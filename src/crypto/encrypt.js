import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

export function encrypt(plaintext, key) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  
  const plaintextBuffer = typeof plaintext === 'string' 
    ? Buffer.from(plaintext) 
    : plaintext;
  
  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final()
  ]);
  
  const authTag = cipher.getAuthTag();
  
  return Buffer.concat([iv, authTag, encrypted]);
}

export function decrypt(ciphertext, key) {
  const ciphertextBuffer = typeof ciphertext === 'string'
    ? Buffer.from(ciphertext, 'base64')
    : ciphertext;
  
  if (ciphertextBuffer.length < IV_LENGTH + AUTH_TAG_LENGTH) {
    throw new Error('Invalid ciphertext: too short');
  }
  
  const iv = ciphertextBuffer.subarray(0, IV_LENGTH);
  const authTag = ciphertextBuffer.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const encrypted = ciphertextBuffer.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  
  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  
  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
}

export function encryptJSON(data, key) {
  const json = JSON.stringify(data);
  return encrypt(json, key);
}

export function decryptJSON(ciphertext, key) {
  const decrypted = decrypt(ciphertext, key);
  return JSON.parse(decrypted.toString('utf8'));
}

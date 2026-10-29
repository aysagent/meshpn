// Optional mTLS for raw TLS only; no Bearer/exporter protocol changes.
import fs from 'node:fs';
import {X509Certificate} from 'node:crypto';
export function rawTlsClientAuthOptions(file) {
  if (file == null) return {};
  if (typeof file !== 'string' || !file.trim()) throw Error('--tls-raw-client-ca requires a PEM CA file');
  const fd=fs.openSync(file,'r');let pem;
  try {
    if(fs.fstatSync(fd).size>32768)throw Error('Raw TLS client CA exceeds 32 KiB');
    pem=fs.readFileSync(fd,'utf8');
  } finally {fs.closeSync(fd);}
  const blocks=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)||[];
  if(!blocks.length||blocks.length>16||pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,'').trim()||
      blocks.some(p=>!new X509Certificate(p).ca)) throw Error('Raw TLS client CA must contain CA certificates only');
  return {ca:pem,requestCert:true,rejectUnauthorized:true};
}

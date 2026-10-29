import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import {checkProfile} from '../scripts/vpn-profile-check.mjs';
import {buildCompactProfileDocument} from '../../scripts/lib/boring-tls-clienthello-profile.mjs';
import {tlsClientHandshakeProfileWithJa4FromTcpBuf} from '../../scripts/lib/tls-clienthello-ja4.mjs';
const reference=JSON.parse(fs.readFileSync(new URL('fixtures/browser-fingerprint-reference.json',import.meta.url)));
// Capture actual fresh Node ClientHellos, no target outside loopback. This is
// deliberately not labelled a browser or ESP32 capture.
async function capture(){let socket,client;
 const server=net.createServer(s=>socket=s);let timer;
 try{
  const captured=new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(Error('capture timeout')),3000);
   server.on('connection',s=>{let data=Buffer.alloc(0);s.on('data',b=>{data=Buffer.concat([data,b]);if(data.length>65536)return reject(Error('oversize'));
    const p=tlsClientHandshakeProfileWithJa4FromTcpBuf(data);if(p.ok)resolve({data,p});});});});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  client=tls.connect({host:'127.0.0.1',port:server.address().port,servername:'exit.meshpn.test',minVersion:'TLSv1.2',maxVersion:'TLSv1.2',ALPNProtocols:['http/1.1']});client.on('error',()=>{});
  return await captured;
 }finally{clearTimeout(timer);client?.destroy();socket?.destroy();await new Promise(r=>server.close(r));}
}
for(let i=0;i<3;i++){
 const {data,p}=await capture();const profile=buildCompactProfileDocument(p,'Node loopback test (not a browser)');
 assert(checkProfile(profile,data).match);
 const altered=structuredClone(profile);altered.ja3_md5='0'.repeat(32);assert(!checkProfile(altered,data).match);
 delete altered.ja4;assert.throws(()=>checkProfile(altered,data),/Both saved/);
 assert.throws(()=>checkProfile(profile,data.subarray(0,8)),/Cannot validate/);
 assert(!checkProfile(reference.profile,data).match,'ordinary TLS must not masquerade as the saved browser');
}
console.log('Fresh ClientHello JA3/JA4 matching, mismatch and missing evidence checks passed');

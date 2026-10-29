import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import net from 'node:net';
import {execFileSync,spawn} from 'node:child_process';
import {startRealExit} from './helpers/real-exit.mjs';
import {createLabPKI} from '../scripts/create-vpn-lab-pki.mjs';
import {clientPKI} from './helpers/client-pki.mjs';
import {rawTlsClientAuthOptions} from '../../scripts/lib/tls-raw-client-auth.mjs';
const root=new URL('../',import.meta.url),idf=process.env.IDF_PATH,libs=process.argv[2];
if(!idf||!libs)throw Error('Set IDF_PATH and pass host mbedTLS library directory');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-exit-compat-'));
const pki=await createLabPKI(path.join(dir,'pki'));clientPKI(path.join(dir,'pki'));
assert.deepEqual(rawTlsClientAuthOptions(undefined),{});
assert.throws(()=>rawTlsClientAuthOptions(''));
assert.throws(()=>rawTlsClientAuthOptions(pki.certificate),/CA certificates/);
const binary=path.join(dir,'client');
execFileSync(process.env.CC||'cc',['-std=c11','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
 '-I'+new URL('components/meshvpn_vpn/include',root).pathname,'-I'+path.join(idf,'components/mbedtls/mbedtls/include'),
 new URL('tests/test_vpn_exit_client.c',root).pathname,new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,
 ...['libmbedtls.a','libmbedx509.a','libmbedcrypto.a'].map(n=>path.join(libs,n)),'-o',binary],{stdio:'inherit'});
async function client(type,port,identity,expected=0){
 const args=[type,String(port),pki.ca];if(identity)args.push(path.join(dir,'pki',identity+'.pem'),path.join(dir,'pki',identity+'.key'));
 await new Promise((resolve,reject)=>{
  const c=spawn(binary,args,{stdio:['ignore','pipe','pipe']});let out='',err='';const timer=setTimeout(()=>c.kill('SIGKILL'),15000);
  c.stdout.on('data',b=>out+=b);c.stderr.on('data',b=>err+=b);c.on('error',reject);
  c.on('close',code=>{clearTimeout(timer);try{assert.equal(code,expected,out+err);if(expected===0)assert.match(out,/REAL_EXIT_CLIENT_OK/);resolve();}catch(e){reject(e);}});
 });
}
const reports=[];
for(const type of ['tcp','udp','tls']){
 const peer=await startRealExit({type,cert:pki.certificate,key:pki.privateKey,onPacket(p,c){c.send({inject:p.toString('base64')});}});
 try {
  for(let i=0;i<3;i++)await client(type,peer.port);
  assert.equal(peer.packets.length,192);
  if(type==='tcp'){
   // Break an incomplete frame; the next connection must start a fresh decoder.
   const s=net.connect(peer.port,'127.0.0.1');await new Promise(r=>s.once('connect',r));s.write(Buffer.from([0,0]));s.destroy();
   await client(type,peer.port);assert.equal(peer.packets.length,256);
  }
  reports.push({type,packets:peer.packets.length,artifact:peer.dir});
 }finally{await peer.close();}
}
const peer=await startRealExit({type:'tls',cert:pki.certificate,key:pki.privateKey,tlsRawClientCa:pki.ca,onPacket(p,c){c.send({inject:p.toString('base64')});}});
try{
 await client('tls',peer.port,null,3);assert.equal(peer.packets.length,0);
 await client('tls',peer.port,'wrong',3);assert.equal(peer.packets.length,0);
 await client('tls',peer.port,'expired-client',3);assert.equal(peer.packets.length,0);
 for(let i=0;i<3;i++)await client('tls',peer.port,'client');assert.equal(peer.packets.length,192);
 reports.push({type:'mtls',packets:peer.packets.length,rejected:['missing','wrong-ca','expired'],artifact:peer.dir});
}finally{await peer.close();}
fs.writeFileSync(path.join(dir,'result.json'),JSON.stringify({scope:'Production exit and firmware framing over real loopback sockets; in-memory TUN; no NAT/radio',reports},null,2));
console.log('Real exit TCP/UDP/TLS + mTLS compatibility passed: '+dir);

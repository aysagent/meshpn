import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawn} from 'node:child_process';
import assert from 'node:assert/strict';
import {startPeer} from '../scripts/vpn-local-peer.mjs';
const root=new URL('../',import.meta.url), idf=process.env.IDF_PATH;
const libraries=process.argv[2];
if(!idf||!libraries)throw Error('Set IDF_PATH; pass host mbedTLS library directory');
const rounds=Number(process.env.VPN_TLS_IO_ROUNDS ?? 1);
assert(Number.isInteger(rounds)&&rounds>=1&&rounds<=100);
const packets=Number(process.env.VPN_TLS_IO_PACKETS ?? 128);
assert(Number.isInteger(packets)&&packets>=1&&packets<=32768,'VPN_TLS_IO_PACKETS must be 1..32768');
const production=fs.readFileSync(new URL('components/meshvpn_vpn/meshvpn_vpn.c',root),'utf8');
const a=production.indexOf('static bool tls_would_block('),b=production.indexOf('static void socket_tx_worker(',a);
const c=production.indexOf('static void record_timing('),d=production.indexOf('void meshvpn_vpn_get_status(',c);
if(a<0||b<a||c<0||d<c)throw Error('Production I/O functions not found');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-tls-io-'));
fs.writeFileSync(path.join(dir,'vpn-tls-io.inc'),production.slice(c,d)+production.slice(a,b));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=loopback-test',
  '-keyout',path.join(dir,'key.pem'),'-out',path.join(dir,'cert.pem')],{stdio:'ignore'});
const binary=path.join(dir,'test');
execFileSync(process.env.CC||'cc',['-I'+new URL('components/meshvpn_profiled_tls/include',root).pathname,'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=undefined','-pthread',
  '-DPACKETS='+packets,
  '-I'+dir,...['tests/stubs','components/meshvpn_config/include','components/meshvpn_vpn/include'].map(p=>'-I'+new URL(p,root).pathname),
  '-I'+path.join(idf,'components/mbedtls/mbedtls/include'),new URL('tests/test_vpn_tls_io.c',root).pathname,
  ...['meshvpn_vpn_frame.c','meshvpn_vpn_stream.c'].map(p=>new URL('components/meshvpn_vpn/'+p,root).pathname),
  ...['libmbedtls.a','libmbedx509.a','libmbedcrypto.a'].map(p=>path.join(libraries,p)),'-o',binary],{stdio:'inherit'});
for (const mode of ['fragmented', 'backpressure']) {
 const count=mode==='backpressure'?Math.min(packets,256):packets;
 const peer=await startPeer({type:'tls',key:fs.readFileSync(path.join(dir,'key.pem')),cert:fs.readFileSync(path.join(dir,'cert.pem')),fragmentFrames:true});
 try {
  await new Promise((resolve,reject)=>{
    const p=spawn(binary,[String(peer.port),path.join(dir,'cert.pem'),mode,String(rounds)],{stdio:['ignore','pipe','pipe']});let output='',errors='';
    const timer=setTimeout(()=>{p.kill();reject(Error('TLS I/O test deadline exceeded'));},rounds*(30000+count*(mode==='backpressure'?150:30)));
    p.stdout.on('data',b=>output+=b);p.stderr.on('data',b=>errors+=b);
    p.on('error',reject);p.on('close',code=>{clearTimeout(timer);if(code!==0)reject(Error(`TLS I/O exit ${code}: ${errors}`));else{assert.match(output,/TLS_IO_OK/);console.log(output.trim());resolve();}});
  });
  assert.equal(peer.stats.packets_in,count*rounds);assert.equal(peer.stats.packets_out,count*rounds);assert.equal(peer.stats.invalid,0);
 } finally {await peer.close();}
}

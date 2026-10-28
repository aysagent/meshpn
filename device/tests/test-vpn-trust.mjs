import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
const root=new URL('../',import.meta.url),idf=process.env.IDF_PATH,libs=process.argv[2];
if(!idf||!libs)throw Error('Set IDF_PATH and pass host mbedTLS library directory');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'meshpn-vpn-trust-'));
for(const [file,out] of [['meshvpn_vpn_trust.c','trust-production.inc'],['meshvpn_vpn_tls.c','tls-production.inc']]){
 const src=fs.readFileSync(new URL('components/meshvpn_vpn/'+file,root),'utf8').replace(/^#include .*$/gm,'');
 fs.writeFileSync(path.join(dir,out),src);
}
function openssl(...args){execFileSync('openssl',args,{cwd:dir,stdio:'pipe'});}
for(const ca of ['ca','other'])openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','30','-subj','/CN='+ca,'-addext','basicConstraints=critical,CA:TRUE','-keyout',ca+'.key','-out',ca+'.pem');
openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=exit.example','-keyout','server.key','-out','server.csr');
fs.writeFileSync(path.join(dir,'index'),'');fs.writeFileSync(path.join(dir,'serial'),'01');
fs.writeFileSync(path.join(dir,'ca.cnf'),`[ca]
default_ca=sign
[sign]
database=index
serial=serial
new_certs_dir=.
certificate=ca.pem
private_key=ca.key
default_md=sha256
policy=policy
x509_extensions=server
[policy]
commonName=supplied
[server]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:exit.example
`);
// Reset issuance database: same subject deliberately used for validity variants.
for(const [name,start,end] of [['valid','20250101000000Z','20400101000000Z'],['expired','20200101000000Z','20200102000000Z'],['future','20400101000000Z','20410101000000Z']]){
 fs.writeFileSync(path.join(dir,'index'),'');
 openssl('ca','-batch','-config','ca.cnf','-in','server.csr','-out',name+'.pem','-startdate',start,'-enddate',end,'-notext');
}
const bin=path.join(dir,'test');
execFileSync(process.env.CC||'cc',['-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-pthread',
 '-I'+dir,...['tests/stubs','components/meshvpn_vpn/include'].map(p=>'-I'+new URL(p,root).pathname),
 '-I'+path.join(idf,'components/mbedtls/mbedtls/include'),new URL('tests/test_vpn_trust.c',root).pathname,
 new URL('components/meshvpn_vpn/meshvpn_vpn_frame.c',root).pathname,
 ...['libmbedtls.a','libmbedx509.a','libmbedcrypto.a'].map(p=>path.join(libs,p)),'-o',bin],{stdio:'inherit'});
for(const [cert,ca,name,reason] of [['valid','ca','exit.example','verified'],['valid','ca','wrong.example','certificate_name_mismatch'],['valid','other','exit.example','certificate_untrusted'],['expired','ca','exit.example','certificate_expired'],['future','ca','exit.example','certificate_not_yet_valid']]){
 let received=0;
 const sockets=new Set();
 const server=tls.createServer({key:fs.readFileSync(path.join(dir,'server.key')),cert:fs.readFileSync(path.join(dir,cert+'.pem')),minVersion:'TLSv1.2',maxVersion:'TLSv1.2'},s=>{s.on('error',()=>{});s.on('data',b=>received+=b.length);});
 server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});server.on('tlsClientError',()=>{});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  await new Promise((resolve,reject)=>{
   const p=spawn(bin,[String(server.address().port),path.join(dir,ca+'.pem'),name,reason,path.join(dir,'valid.pem')],{stdio:['ignore','pipe','pipe']});let output='';
   const timer=setTimeout(()=>{p.kill();reject(Error('TLS trust test timed out'));},20000);
   p.stdout.on('data',b=>output+=b);p.stderr.on('data',b=>output+=b);p.on('error',reject);
   p.on('close',code=>{clearTimeout(timer);code===0?resolve():reject(Error(output));});
  });
  assert.equal(received,0,'no tunnel data before accepted handshake');console.log('TLS trust: '+reason+' (3 fresh connections)');
 }finally{for(const s of sockets)s.destroy();await new Promise(r=>server.close(r));}
}
console.log('TLS trust artifacts: '+dir);

import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
export function clientPKI(dir){
 const openssl=(...args)=>execFileSync('openssl',args,{cwd:dir,stdio:'pipe'});
 for(const name of ['client','wrong']){
  openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-subj','/CN='+name,'-keyout',name+'.key','-out',name+'.csr');
  fs.writeFileSync(path.join(dir,name+'.ext'),'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
  const ca=name==='client'?'ca':'other';
  openssl('x509','-req','-in',name+'.csr','-CA',ca+'.pem','-CAkey',ca+'.key','-CAcreateserial','-days','2','-extfile',name+'.ext','-out',name+'.pem');
 }
 fs.appendFileSync(path.join(dir,'ca.cnf'),'\n[client]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
 fs.writeFileSync(path.join(dir,'index'),'');
 openssl('ca','-batch','-config','ca.cnf','-extensions','client','-in','client.csr','-out','expired-client.pem','-startdate','20200101000000Z','-enddate','20200102000000Z','-notext');
 fs.copyFileSync(path.join(dir,'client.key'),path.join(dir,'expired-client.key'));
 for(const name of ['client.key','wrong.key','expired-client.key'])fs.chmodSync(path.join(dir,name),0o600);
}

// Private, disposable CA/leaf fixtures. Never installs trust in macOS.
import fs from 'node:fs/promises';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export async function createLabPKI(directory) {
  await fs.mkdir(directory,{mode:0o700});
  const openssl=(...args)=>execFileSync('openssl',args,{cwd:directory,stdio:'pipe'});
  for(const ca of ['ca','other']) openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','7',
    '-subj','/CN=MeshPN disposable '+ca,'-addext','basicConstraints=critical,CA:TRUE','-keyout',ca+'.key','-out',ca+'.pem');
  openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=exit.meshpn.test','-keyout','server.key','-out','server.csr');
  await fs.writeFile(path.join(directory,'serial'),'01');
  await fs.writeFile(path.join(directory,'ca.cnf'),`[ca]
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
subjectAltName=DNS:exit.meshpn.test
`);
  const date=days=>new Date(Date.now()+days*86400000).toISOString().replace(/[-:]/g,'').replace('T','').slice(0,14)+'Z';
  for(const [name,start,end] of [['valid',-1,2],['expired',-3,-2],['future',2,3]]) {
    await fs.writeFile(path.join(directory,'index'),'');
    openssl('ca','-batch','-config','ca.cnf','-in','server.csr','-out',name+'.pem','-startdate',date(start),'-enddate',date(end),'-notext');
  }
  for(const name of await fs.readdir(directory)) await fs.chmod(path.join(directory,name),0o600);
  return {ca:path.join(directory,'ca.pem'),certificate:path.join(directory,'valid.pem'),privateKey:path.join(directory,'server.key'),serverName:'exit.meshpn.test'};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv.length!==3)throw Error('Usage: node create-vpn-lab-pki.mjs NEW_DIRECTORY');
  console.log(JSON.stringify(await createLabPKI(path.resolve(process.argv[2]))));
}

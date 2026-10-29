// Offline candidate only. No service, network, clock or source-config changes.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import {execFileSync} from 'node:child_process';
import {X509Certificate,createPrivateKey,createPublicKey,createHash,randomBytes} from 'node:crypto';
const fail=message=>{throw Error(message);};
const hash=b=>createHash('sha256').update(b).digest('hex');
const read=(file,privateKey=false)=>{const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.size>262144||(privateKey&&(s.mode&0o077)))fail('bounded_private_material_required');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}};
const certs=bytes=>{const pems=String(bytes).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)??[];if(!pems.length||pems.length>16)fail('certificate_chain_required');return pems.map(pem=>({pem,cert:new X509Certificate(pem)}));};
const command=(file,args,input,keyFd)=>{try{return execFileSync(file,args,{input,encoding:'utf8',timeout:60000,maxBuffer:1024*1024,stdio:keyFd===undefined?['pipe','pipe','pipe']:['ignore','pipe','pipe',keyFd]});}catch{fail('certificate_command_failed');}};
function names(cert){const entries=(cert.subjectAltName??'').split(/,\s*/);if(!entries.length||entries.length>32)fail('bounded_SAN_required');return entries.map(entry=>{if(entry.startsWith('DNS:')){const n=entry.slice(4);if(!/^(?:\*\.)?(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(n)||n.includes('..'))fail('unsupported_SAN');return'DNS:'+n;}if(entry.startsWith('IP Address:')){const ip=entry.slice(11);if(!net.isIP(ip))fail('unsupported_SAN');return'IP:'+ip;}fail('unsupported_SAN');});}
export function prepareCertificateRenewal(o,{validateCandidate=file=>command(o.engine,['--check-config',file])}={}){
 for(const key of ['config','caCert','caKey','output','engine'])if(typeof o[key]!=='string'||!path.isAbsolute(o[key]))fail('absolute_paths_required');
 if(o.trust!==undefined&&(typeof o.trust!=='string'||!path.isAbsolute(o.trust)))fail('absolute_paths_required');
 const days=Number(o.days??30);if(!Number.isInteger(days)||days<1||days>397)fail('days_1_to_397_required');
 if(typeof o.serverName!=='string'||!/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(o.serverName))fail('server_name_required');
 const sourceBytes=read(o.config),config=JSON.parse(sourceBytes),packet=config.transport==='combo-tls'?config.boring:config;
 if(packet?.role!=='exit'||config.transport==='transparent-tls')fail('TLS_exit_config_required');
 if(typeof packet.cert!=='string'||!path.isAbsolute(packet.cert))fail('absolute_certificate_path_required');
 const oldBytes=read(packet.cert),old=certs(oldBytes),signingBytes=read(o.caCert),signing=certs(signingBytes),trustBytes=read(o.trust??o.caCert),trust=certs(trustBytes),keyBytes=read(o.caKey,true);
 const now=Date.now(),deadline=now+days*86400000+60000;
 for(const {cert}of [...signing,...trust,...old.slice(1)])if(!cert.ca||Date.parse(cert.validFrom)>now||Date.parse(cert.validTo)<deadline)fail('CA_validity_insufficient_rotation_is_separate');
 if(old[0].cert.ca||!old[0].cert.checkHost(o.serverName)||!old[0].cert.verify(signing[0].cert.publicKey))fail('existing_leaf_name_or_signer_mismatch');
 const privateKey=createPrivateKey(keyBytes),pub=k=>k.export({type:'spki',format:'der'});if(!pub(createPublicKey(privateKey)).equals(pub(signing[0].cert.publicKey)))fail('CA_key_mismatch');
 const sans=names(old[0].cert),leafPublic=old[0].cert.publicKey;let keyArgs;
 if(leafPublic.asymmetricKeyType==='rsa'){const bits=leafPublic.asymmetricKeyDetails.modulusLength;if(bits<2048||bits>4096)fail('unsupported_existing_leaf_key');keyArgs=['-newkey','rsa:'+bits];}
 else if(leafPublic.asymmetricKeyType==='ec'&&['prime256v1','secp384r1','secp521r1'].includes(leafPublic.asymmetricKeyDetails.namedCurve))keyArgs=['-newkey','ec','-pkeyopt','ec_paramgen_curve:'+leafPublic.asymmetricKeyDetails.namedCurve];
 else fail('unsupported_existing_leaf_key');
 if(fs.existsSync(o.output))fail('new_output_directory_required');
 fs.mkdirSync(o.output,{mode:0o700});let complete=false;
 const put=(name,data)=>{const f=path.join(o.output,name);fs.writeFileSync(f,data,{mode:0o600,flag:'wx'});return f;};
 try{
  const ca=put('signing-chain.pem',signingBytes),trustPath=put('trust.pem',trustBytes),oldPath=put('previous-chain.pem',oldBytes);
  command('openssl',['verify','-no_check_time','-purpose','sslserver','-verify_hostname',o.serverName,'-CAfile',trustPath,'-untrusted',oldPath,oldPath]);
  const key=path.join(o.output,'key.pem'),csr=path.join(o.output,'leaf.csr'),leaf=path.join(o.output,'leaf.pem');
  command('openssl',['req','-new',...keyArgs,'-nodes','-subj','/CN='+o.serverName,'-keyout',key,'-out',csr]);fs.chmodSync(key,0o600);
  const ext=put('extensions.cnf','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName='+sans.join(',')+'\n');
  const keyFd=fs.openSync(o.caKey,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{command('openssl',['x509','-req','-in',csr,'-CA',ca,'-CAkey','/dev/fd/3','-set_serial','0x'+randomBytes(16).toString('hex'),'-days',String(days),'-extfile',ext,'-out',leaf],undefined,keyFd);}finally{fs.closeSync(keyFd);}
  const freshBytes=read(leaf),fresh=certs(freshBytes)[0].cert;
  if(JSON.stringify(names(fresh))!==JSON.stringify(sans)||!fresh.checkHost(o.serverName)||Date.parse(fresh.validTo)>Math.min(...[...signing,...trust,...old.slice(1)].map(x=>Date.parse(x.cert.validTo))))fail('candidate_name_or_validity_mismatch');
  if(!fresh.checkPrivateKey(createPrivateKey(read(key,true))))fail('candidate_key_mismatch');
  const chain=put('cert.pem',String(freshBytes)+'\n'+old.slice(1).map(x=>x.pem).join('\n'));
  command('openssl',['verify','-purpose','sslserver','-verify_hostname',o.serverName,'-CAfile',trustPath,'-untrusted',chain,chain]);
  const candidate=structuredClone(config),next=config.transport==='combo-tls'?candidate.boring:candidate;next.cert=chain;next.key=key;
  const candidatePath=put('engine.json',JSON.stringify(candidate,null,2)+'\n');validateCandidate(candidatePath);
  if(!read(o.config).equals(sourceBytes)||!read(packet.cert).equals(oldBytes)||!read(o.caCert).equals(signingBytes)||!read(o.trust??o.caCert).equals(trustBytes)||!read(o.caKey,true).equals(keyBytes))fail('source_material_changed');
  const manifest={schema:1,kind:'native-certificate-renewal-candidate',installed:false,serviceChanged:false,trustChanged:false,serverName:o.serverName,sans,days,sourceConfigSha256:hash(sourceBytes),candidateConfigSha256:hash(read(candidatePath)),previousLeafSha256:hash(old[0].cert.raw),candidateLeafSha256:hash(fresh.raw),trustSha256:hash(trustBytes),validFrom:fresh.validFrom,validTo:fresh.validTo,nativeConfigValidated:true};
  put('manifest.json',JSON.stringify(manifest,null,2)+'\n');for(const f of fs.readdirSync(o.output))fs.chmodSync(path.join(o.output,f),0o600);complete=true;return manifest;
 }finally{keyBytes.fill(0);if(!complete)fs.rmSync(o.output,{recursive:true,force:true});}
}

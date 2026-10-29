// Offline, per-ClientHello comparison. Does not configure a TLS backend.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {validateBoringTlsClienthelloProfileFile} from '../../scripts/lib/boring-tls-clienthello-profile.mjs';
import {ja3FromTcpBuf,parseFirstTlsClientHelloFromTcpBuf} from '../../scripts/lib/tls-clienthello-ja3.mjs';
import {ja4FromTcpBuf} from '../../scripts/lib/tls-clienthello-ja4.mjs';
export function checkProfile(profile,hello){
 const validation=validateBoringTlsClienthelloProfileFile(profile);
 if(!validation.ok)throw Error(validation.error);
 if(!/^[a-f0-9]{32}$/.test(profile.ja3_md5||'')||!profile.ja4?.fingerprint)
  throw Error('Both saved wire JA3 MD5 and FoxIO JA4 are required; no sorted-only fallback');
 if(!Buffer.isBuffer(hello)||hello.length>65536)throw Error('ClientHello input must be binary TLS records, <=64 KiB');
 const parsed=parseFirstTlsClientHelloFromTcpBuf(hello);
 if(!parsed.ok)throw Error('Cannot validate ClientHello: '+(parsed.reason||'incomplete'));
 const a=ja3FromTcpBuf(hello),b=ja4FromTcpBuf(hello);
 if(!a||!b||b.error)throw Error('Cannot compute both fingerprints');
 const ja3=a.ja3Digest===profile.ja3_md5,ja4=b.fingerprint===profile.ja4.fingerprint;
 return {schema:1,scope:'One observed ClientHello; no backend/handshake/browser-equivalence claim',
  match:ja3&&ja4,ja3:{match:ja3,expected:profile.ja3_md5,actual:a.ja3Digest,sorted_actual:a.ja3SortedDigest},
  ja4:{match:ja4,expected:profile.ja4.fingerprint,actual:b.fingerprint},
  clienthello_sha256:createHash('sha256').update(parsed.clientHelloBody).digest('hex'),
  note:'Every new connection needs a fresh observation. No fallback to sorted JA3 or alternate JA4.'};
}
function boundedRead(file,max){const fd=fs.openSync(file,'r');try{if(fs.fstatSync(fd).size>max)throw Error('Input too large');return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [profileFile,helloFile,out]=process.argv.slice(2);
 if(!profileFile||!helloFile||!out||process.argv.length!==5)throw Error('Usage: node device/scripts/vpn-profile-check.mjs PROFILE.json CLIENTHELLO.bin REPORT.json');
 const raw=boundedRead(profileFile,65536),document=JSON.parse(raw),profile=document.profile??document;
 const result=checkProfile(profile,boundedRead(helloFile,65536));
 result.profile_sha256=createHash('sha256').update(raw).digest('hex');
 fs.writeFileSync(out,JSON.stringify(result,null,2)+'\n',{mode:0o600,flag:'wx'});
 console.log(`${result.match?'MATCH':'MISMATCH'}: ${out}`);if(!result.match)process.exitCode=2;
}

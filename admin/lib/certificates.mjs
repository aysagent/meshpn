// Passive local-material inspection. Never probes peers or changes trust/time.
import fs from 'node:fs';
import {X509Certificate} from 'node:crypto';

export function certificateStatus(config,{now=Date.now(),read=file=>{
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{const s=fs.fstatSync(fd);if(!s.isFile()||s.size>262144)throw Error('bounded_certificate');const b=Buffer.alloc(262145);let n=0,k;while(n<b.length&&(k=fs.readSync(fd,b,n,b.length-n,null))>0)n+=k;if(n>262144)throw Error('bounded_certificate');return b.subarray(0,n);}finally{fs.closeSync(fd);}
}}={}){
 const packet=config?.transport==='combo-tls'?config.boring:config;
 const scope=packet?.role==='exit'?'local-exit-chain':'local-client-trust';
 const base={scope,remoteLeafObserved:false,clock:'local-system-clock',warningDays:30};
 if(config?.transport==='transparent-tls')return{...base,status:'not-applicable',certificates:[]};
 try{
  if(!Number.isFinite(now))throw Error('clock');
  const file=packet?.role==='exit'?packet.cert:packet?.ca;
  if(typeof file!=='string'||!file.startsWith('/'))throw Error('path');
  const text=String(read(file));if(Buffer.byteLength(text)>262144)throw Error('size');
  const pems=text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)??[];
  if(!pems.length||pems.length>32)throw Error('count');
  const certificates=pems.map((pem,index)=>{
   const c=new X509Certificate(pem),from=Date.parse(c.validFrom),to=Date.parse(c.validTo);
   if(!Number.isFinite(from)||!Number.isFinite(to))throw Error('dates');
   const state=now<from?'not-yet-valid':now>to?'expired':to-now<=30*86400000?'expiring':'valid';
   return{index,ca:c.ca,fingerprint256:c.fingerprint256,validFrom:new Date(from).toISOString(),validTo:new Date(to).toISOString(),daysRemaining:Math.floor((to-now)/86400000),state};
  });
  const status=certificates.some(c=>['expired','not-yet-valid'].includes(c.state))?'attention':certificates.some(c=>c.state==='expiring')?'expiring':'valid';
  return{...base,status,certificates,verification:'dates-only; no chain, hostname, revocation or remote handshake verification'};
 }catch{return{...base,status:'unavailable',certificates:[],reason:'local-certificate-unreadable-or-invalid'};}
}

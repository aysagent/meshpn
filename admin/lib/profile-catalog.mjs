// File/config evidence only. A catalog cannot attest the running TLS socket.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function read(file,max){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{const s=fs.fstatSync(fd);if(!s.isFile()||s.size>max)throw Error('profile_file');const bytes=fs.readFileSync(fd);if(bytes.length>max)throw Error('profile_file');return{bytes,value:JSON.parse(bytes)};}finally{fs.closeSync(fd);}
}
export function profileImportReceipt(file,now=Date.now()){
 const {bytes}=read(file,16384);
 return{schema:1,kind:'native-profile-import-receipt',fileSha256:digest(bytes),checkedAt:new Date(now).toISOString(),check:'native-check-config',browserEquivalent:false};
}
export function profileCatalog(directory,{configuredPath=null}={}){
 return fs.readdirSync(directory).filter(n=>/^[a-zA-Z0-9_.-]+\.json$/.test(n)).sort().slice(0,256).flatMap(id=>{
  try{
   const file=path.join(directory,id),{bytes,value:p}=read(file,16384);
   if(p.schema!==1||p.kind!=='clean-vpn-native-tls-profile'||typeof p.id!=='string'||! /^[a-zA-Z0-9_.-]{1,64}$/.test(p.id)||p.scenario!=='cold')return[];
   const fileSha256=digest(bytes);let validation={status:'unknown',scope:'catalog-does-not-run-native-validation'};
   try{const r=read(file+'.receipt',2048).value;
    if(r.schema===1&&r.kind==='native-profile-import-receipt'&&r.fileSha256===fileSha256&&r.check==='native-check-config'&&typeof r.checkedAt==='string'&&Number.isFinite(Date.parse(r.checkedAt)))
     validation={status:'accepted-at-import',checkedAt:r.checkedAt,scope:'saved-file-only-not-current-engine-or-wire-proof'};
   }catch{}
   return[{id,name:p.id,scenario:p.scenario,fileSha256,configured:configuredPath!==null&&path.resolve(configuredPath)===path.resolve(file),
    runtimeVerified:false,browserEquivalent:false,validation,
    provenance:{status:'unverified',reason:'local-file-does-not-establish-browser-capture-origin'},
    layers:{packet:'saved-cold-ClientHello',http:p.http?'bounded-request-fields':'native-defaults',relay:'original-application-TLS-not-this-profile'}}];
  }catch{return[];}
 });
}

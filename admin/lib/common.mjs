import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
export function need(ok,code,status=400){if(!ok)throw Object.assign(Error(code),{status});}
export function exact(o,keys){need(o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).every(k=>keys.includes(k)),'unknown_fields');}
export const id=x=>typeof x==='string'&&/^[a-zA-Z0-9_-]{1,64}$/.test(x);
export function hostname(x){need(typeof x==='string','hostname');x=x.toLowerCase().replace(/\.local$/,'');need(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x),'hostname');return x;}
export function readJson(file,fallback){try{return JSON.parse(fs.readFileSync(file,'utf8'));}catch(e){if(e.code==='ENOENT'&&fallback!==undefined)return structuredClone(fallback);throw e;}}
export function atomic(file,value,mode=0o600){const bytes=typeof value==='string'?value:JSON.stringify(value,null,2)+'\n';const p=file+'.'+randomBytes(8).toString('hex');let fd;try{fd=fs.openSync(p,'wx',mode);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(p,file);const d=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(d);}finally{fs.closeSync(d);}}finally{if(fd!==undefined)fs.closeSync(fd);try{fs.unlinkSync(p);}catch(e){if(e.code!=='ENOENT')throw e;}}}
export async function body(req,limit=32768){need(req.headers['content-type']?.split(';')[0]==='application/json','json_required',415);let n=0,parts=[];for await(const b of req){n+=b.length;need(n<=limit,'body_limit',413);parts.push(b);}let result;try{result=JSON.parse(Buffer.concat(parts));}catch{throw Object.assign(Error('invalid_json'),{status:400});}need(result&&typeof result==='object'&&!Array.isArray(result),'json_object');return result;}
export function send(res,status,data,headers={}){res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers});res.end(JSON.stringify(data));}
export const safeError=e=>/^[a-z0-9_]{1,100}$/.test(e.message)?e.message:'operation_failed';
export function ipv4Subnet(ip,cidr){if(typeof ip!=='string')return false;const [base,bits]=cidr.split('/');const n=Number(bits);const conv=s=>{const a=s.split('.');if(a.length!==4||a.some(x=>!/^\d{1,3}$/.test(x)||Number(x)>255))return null;return a.reduce((v,x)=>(v*256+Number(x))>>>0,0);};const a=conv(ip),b=conv(base);return a!==null&&b!==null&&n>=1&&n<=32&&((a^b)>>>0)<2**(32-n);}

/** Device profile capture. Direct HTTPS only: a TLS proxy would capture its own hello. */
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import http2 from 'node:http2';
import {once} from 'node:events';
import {randomBytes,createHash,constants} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {measureTlsClientHello} from '../../scripts/lib/native-tls-profile-observer.mjs';
import {parseFirstTlsClientHelloFromTcpBuf} from '../../scripts/lib/tls-clienthello-ja3.mjs';
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const allowed=new Set([0,5,10,11,13,16,18,21,23,27,35,43,45,51,65281,17613,65037,51764]);
const required=[0,10,11,13,16,43,45,51];
export function deviceProfile(wire,name='Captured browser') {
 const m=measureTlsClientHello(wire),a=m.actual,reasons=[];
 const points=m.ja3String.split(',')[4].split('-').filter(Boolean).map(Number);
 for(const k of ['cipher_suites','supported_groups','key_share_groups','signature_algorithms','extension_types'])
  if(!a[k].length||a[k].length>32||new Set(a[k]).size!==a[k].length)reasons.push(k);
 for(const n of a.extension_types)if(!allowed.has(n))reasons.push('extension '+n);
 for(const n of required)if(!a.extension_types.includes(n))reasons.push('missing extension '+n);
 if(a.key_share_groups.length>4)reasons.push('key share limit');
 if(!same(a.supported_versions,[772,771]))reasons.push('TLS versions');
 if(!same(points,[0]))reasons.push('EC point formats');
 if(!same(a.alpn,['h2'])&&!same(a.alpn,['h2','http/1.1']))reasons.push('ALPN must start with h2');
 if(!same(a.certificate_compression,a.extension_types.includes(27)?[2]:[]))reasons.push('certificate compression');
 if(!same(a.application_settings,a.extension_types.includes(17613)?['h2']:[]))reasons.push('ALPS');
 // Trust-anchor identifiers are private PKI hints, not JA3/JA4 inputs. The device
 // emits an empty request and keeps its separately configured CA; never imports browser trust.
 const tls={...a,ec_point_formats:points};delete tls.trust_anchors;
 // Content identity includes the exact observed order; never claims a browser's permutation policy.
 const id='p-'+createHash('sha256').update(JSON.stringify(tls)).digest('hex').slice(0,24);
 name=String(name).replace(/[\x00-\x1f\x7f]/g,' ').trim();
 while(Buffer.byteLength(name)>64)name=name.slice(0,-1);
 const profile={schema:1,id,name:name||'Captured browser',ja3:m.ja3,ja4:m.ja4.fingerprint,tls};
 if(Buffer.byteLength(JSON.stringify(profile))>4096)reasons.push('profile size');
 return {id,observedAt:new Date().toISOString(),ja3:m.ja3,ja4:m.ja4.fingerprint,name:profile.name,
  status:reasons.length?'unsupported':'candidate',reasons,profile:reasons.length?null:profile};
}
const escape=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export async function startCapture({cert,key,store,host='127.0.0.1',port=9443,name='localhost',maxProfiles=32}) {
 if(!Number.isInteger(port)||port<0||port>65535||!Number.isInteger(maxProfiles)||maxProfiles<1||maxProfiles>32||!/^[a-zA-Z0-9.-]{1,253}$/.test(name))throw Error('Invalid capture settings');
 fs.mkdirSync(store,{recursive:true,mode:0o700});
 const catalog=new Map();
 for(const file of fs.readdirSync(store).filter(f=>/^p-[a-f0-9]{24}\.json$/.test(f))){
  const stat=fs.lstatSync(path.join(store,file));if(!stat.isFile()||stat.size>16384)throw Error('Invalid catalog file');
  const r=JSON.parse(fs.readFileSync(path.join(store,file),'utf8'));
  if(file!==r.id+'.json'||!['candidate','unsupported'].includes(r.status))throw Error('Invalid catalog record');
  catalog.set(r.id,r);
 }if(catalog.size>maxProfiles)throw Error('Catalog exceeds limit');
 const token=randomBytes(24).toString('hex'),prefix='/capture/'+token;
 const sockets=new Set(),sessions=new Set(),connections=new Map();let front,closing;
 const headers={'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff',
  'content-security-policy':"default-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"};
 const track=s=>{sockets.add(s);s.setTimeout(15000,()=>s.destroy());s.on('error',()=>{});s.on('close',()=>sockets.delete(s));};
 const backend=http2.createSecureServer({cert,key,allowHTTP1:true,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',
  secureOptions:constants.SSL_OP_NO_TICKET,numTickets:0,handshakeTimeout:5000,maxSessionMemory:2,
  maxHeaderListPairs:32,maxHeaderSize:8192,settings:{maxConcurrentStreams:4,maxHeaderListSize:8192}});
 backend.maxConnections=8;backend.on('connection',track);backend.on('tlsClientError',()=>{});
 backend.on('session',s=>{sessions.add(s);s.on('error',()=>{});s.on('close',()=>sessions.delete(s));s.setTimeout(15000,()=>s.destroy());});
 backend.on('request',(req,res)=>{
  req.on('error',()=>{});res.on('error',()=>{});
  const authority=name+':'+front.address().port;
  const fail=(status,text)=>{res.writeHead(status,headers);res.end(text);};
  const url=req.url;
  if(req.method!=='GET'||(req.headers[':authority']||req.headers.host)!==authority||req.headers.origin||!url.startsWith(prefix))return fail(404,'Not found');
  const match=url.match(new RegExp('^'+prefix+'/download/(p-[a-f0-9]{24})$'));
  if(match){const r=catalog.get(match[1]);if(!r?.profile)return fail(404,'Profile unavailable');
   res.writeHead(200,{...headers,'content-type':'application/json','content-disposition':`attachment; filename="${r.id}.json"`});res.end(JSON.stringify(r.profile,null,2));return;}
  if(url!==prefix&&url!==prefix+'/list')return fail(404,'Not found');
  let captured=null;
  if(url===prefix){
   const c=connections.get(req.socket.remotePort);
   if(!c||req.socket.isSessionReused())return fail(409,'A fresh TLS connection is required');
   try {
    if(!c.saved){
     if(!c.wire)return fail(409,'ClientHello unavailable');
     const ua=String(req.headers['user-agent']||'');const browser=ua.match(/(?:Chrome|Firefox|Edg|Version)\/[0-9.]+/g)?.at(-1)||'Browser';const platform=ua.match(/\(([^)]+)\)/)?.[1]||'';const r=deviceProfile(c.wire,browser+' '+platform);c.wire=null;
     if(!catalog.has(r.id)){
      if(catalog.size>=maxProfiles)return fail(429,'Catalog full. Stop capture and archive unused catalog files.');
      const dest=path.join(store,r.id+'.json'),temp=dest+'.'+randomBytes(8).toString('hex')+'.tmp';
      try{fs.writeFileSync(temp,JSON.stringify(r,null,2),{mode:0o600,flag:'wx'});fs.renameSync(temp,dest);}finally{fs.rmSync(temp,{force:true});}
      catalog.set(r.id,r);
     }c.saved=r.id;
    }captured=c.saved;
   }catch{return fail(422,'Unsupported or malformed ClientHello. Nothing saved.');}
  }
  res.writeHead(200,{...headers,'content-type':'text/html; charset=utf-8'});
  const rows=[...catalog.values()].map(r=>`<li><strong>${escape(r.name)}</strong> ${r.id===captured?'— этот браузер':''}<br>${escape(r.observedAt)}<br>JA3: ${escape(r.ja3)}<br>JA4: ${escape(r.ja4)}<br>${r.profile?`<a href="${prefix}/download/${r.id}">Скачать профиль JSON</a> — проверка воспроизводимости на плате при импорте`:`Не поддерживается: ${escape(r.reasons.join(', '))}`}</li>`).join('');
  res.end(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Профили браузеров — MeshPN</title><h1>${captured?'Профиль браузера сохранён':'Сохранённые профили'}</h1><p>Скачайте JSON, откройте админку платы → VPN → boring-tls → Import browser profile. Затем выберите профиль и нажмите Save and apply.</p><p>Это снимок одного ClientHello. Фиксируется порядок расширений этого соединения, а не случайная перестановка браузера. Идентификаторы доверенных CA, случайные значения и ключи браузера не копируются. JA3/JA4 проверяются перед каждым подключением; совпадение не означает полную имитацию браузера или HTTP/2.</p><p>Для другого браузера откройте в нём эту же ссылку захвата. Обновление страницы в одном соединении не создаёт новый профиль.</p><a href="${prefix}/list">Обновить список без нового захвата</a><ul>${rows}</ul></html>`);
 });
 async function close(){if(closing)return closing;for(const s of sessions)s.destroy();for(const s of sockets)s.destroy();closing=Promise.all([front,backend].filter(s=>s?.listening).map(s=>new Promise(r=>s.close(r))));return closing;}
 try{
  backend.listen(0,'127.0.0.1');await once(backend,'listening');
  front=net.createServer({pauseOnConnect:true},client=>{
   if(connections.size>=8){client.destroy();return;}
   const upstream=net.connect(backend.address().port,'127.0.0.1'),c={wire:null,saved:null};let bytes=Buffer.alloc(0),observed=false,localPort;
   for(const s of [client,upstream]){track(s);s.on('error',()=>{client.destroy();upstream.destroy();});s.on('close',()=>{connections.delete(localPort);client.destroy();upstream.destroy();});}
   client.on('data',chunk=>{if(observed)return;if(bytes.length+chunk.length>65536){client.destroy();return;}bytes=Buffer.concat([bytes,chunk]);
    const parsed=parseFirstTlsClientHelloFromTcpBuf(bytes);if(parsed.ok){c.wire=Buffer.from(bytes.subarray(0,parsed.bytesConsumed));bytes=null;observed=true;}else if(!parsed.needMore)client.destroy();});
   upstream.once('connect',()=>{localPort=upstream.localPort;connections.set(localPort,c);client.pipe(upstream);upstream.pipe(client);client.resume();});
  });front.maxConnections=8;front.listen(port,host);await once(front,'listening');
  return {url:`https://${name}:${front.address().port}${prefix}`,port:front.address().port,catalog:()=>structuredClone([...catalog.values()]),close};
 }catch(e){await close();throw e;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--help')){console.log('Usage: npm run device:profile:capture -- --cert=/path/fullchain.pem --key=/path/key.pem --name=capture.example.com [--host=127.0.0.1 --port=9443 --store=/path/catalog]\nOpen the printed HTTPS link directly in the browser. Requires a trusted certificate; no TLS-terminating proxy.');process.exit(0);}
 const args=Object.fromEntries(process.argv.slice(2).map(a=>{const i=a.indexOf('=');if(!a.startsWith('--')||i<3)throw Error('Use --option=value');return[a.slice(2,i),a.slice(i+1)];}));
 for(const k of Object.keys(args))if(!['cert','key','store','host','port','name'].includes(k))throw Error('Unknown option '+k);
 if(!args.cert||!args.key)throw Error('Usage: node device/scripts/browser-profile-capture.mjs --cert=fullchain.pem --key=key.pem --name=capture.example.com [--host=127.0.0.1 --port=9443 --store=directory]. Certificate must be trusted by the browser; no TLS reverse proxy.');
 const capture=await startCapture({cert:fs.readFileSync(args.cert),key:fs.readFileSync(args.key),name:args.name||'localhost',host:args.host||'127.0.0.1',port:args.port?Number(args.port):9443,store:path.resolve(args.store||fileURLToPath(new URL('../browser-profiles',import.meta.url)))});
 console.log('Open in the browser to capture:\n'+capture.url+'\nCatalog: '+path.resolve(args.store||fileURLToPath(new URL('../browser-profiles',import.meta.url))));
 for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>void capture.close());
}

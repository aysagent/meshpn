#!/usr/bin/env node
import fs from 'node:fs';
import {X509Certificate} from 'node:crypto';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {once} from 'node:events';
import {readPortalState,portalUrl} from './lib/captive.mjs';
import {Auth} from './lib/auth.mjs';
import {need,exact,hostname,readJson,atomic,body,send,safeError,ipv4Subnet} from './lib/common.mjs';
import {command} from './lib/command.mjs';
import {startBrowserCapture} from '../scripts/lib/native-browser-capture-server.mjs';
const PUBLIC=fileURLToPath(new URL('./public/',import.meta.url));
export async function brokerRequest(socket,route,data={}){return await new Promise((resolve,reject)=>{const req=http.request({socketPath:socket,path:route,method:'POST',headers:{'content-type':'application/json'}},res=>{let bytes=0,chunks=[];res.on('data',b=>{bytes+=b.length;if(bytes>24*1024*1024){req.destroy();reject(Error('broker_response_limit'));}else chunks.push(b);});res.on('end',()=>{try{const data=JSON.parse(Buffer.concat(chunks));if(res.statusCode!==200)throw Object.assign(Error(data.error??'broker_failed'),{status:res.statusCode});resolve(data);}catch(e){reject(e);}});});req.setTimeout(20000,()=>req.destroy(Error('broker_timeout')));req.on('error',reject);req.end(JSON.stringify(data));});}
export async function createAdmin(c,{rpc=(route,data)=>brokerRequest(c.brokerSocket,route,data),run=command}={}){
 need(net.isIPv4(c.address)&&typeof c.subnet==='string'&&ipv4Subnet(c.address,c.subnet),'usb_bind');need(Number.isInteger(c.port)&&c.port>=0&&c.port<=65535,'listen_port');fs.mkdirSync(c.state,{recursive:true,mode:0o700});const auth=new Auth(c.state+'/auth.json');await auth.init();let mutationBusy=false,downloadBusy=false;let currentHostname=hostname((await rpc('/settings',{})).hostname),capture=null,captureView=null,captureTimer;
 if(c.captureHostname!==undefined)need(typeof c.captureHostname==='string'&&c.captureHostname.length<=253&&c.captureHostname.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)),'capture_hostname');
 const cookie=sid=>`mpn_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`;
 const publicPort=c.publicPort??c.port,publicAddress=c.publicAddress??c.address;
 const acceptedHosts=()=>[currentHostname+'.local',publicAddress].flatMap(h=>publicPort===80?[h,h+':80']:[h+':'+publicPort]);
 const allowed=req=>c.lab===true||c.loopbackProxy===true?req.socket.remoteAddress==='127.0.0.1':req.socket.localAddress===c.address&&ipv4Subnet(req.socket.remoteAddress,c.subnet);
 const closeCapture=async()=>{clearTimeout(captureTimer);if(capture){captureView=capture.snapshot();await capture.close();capture=null;}return{status:'stopped',capture:captureView};};
 const captureFront=net.createServer(client=>{if(!allowed({socket:client})||!capture){client.destroy();return;}const dest=new URL(capture.url),upstream=net.connect(Number(dest.port),'127.0.0.1');client.setTimeout(12000,()=>client.destroy());upstream.setTimeout(12000,()=>upstream.destroy());for(const s of [client,upstream]){s.on('error',()=>{client.destroy();upstream.destroy();});s.on('close',()=>{client.destroy();upstream.destroy();});}client.pipe(upstream);upstream.pipe(client);});captureFront.maxConnections=8;
 const security={'content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",'x-frame-options':'DENY','x-content-type-options':'nosniff','referrer-policy':'no-referrer','cache-control':'no-store'};
 const routes=new Map([['/api/status','/status'],['/api/settings','/settings'],['/api/hostname','/hostname'],['/api/vpn/settings','/vpn/settings'],['/api/vpn/action','/vpn/action'],['/api/guard','/guard'],['/api/wifi/scan','/wifi/scan'],['/api/wifi/save','/wifi/save'],['/api/wifi/connect','/wifi/connect'],['/api/wifi/delete','/wifi/delete'],['/api/logs','/logs'],['/api/probe','/probe'],['/api/observer','/observer'],['/api/observer/start','/observer/start'],['/api/observer/stop','/observer/stop'],['/api/profile/import','/profile/import'],['/api/clients','/clients'],['/api/clients/add','/clients/add'],['/api/clients/rename','/clients/rename'],['/api/clients/rotate','/clients/rotate'],['/api/clients/revoke','/clients/revoke']]);
 const readonly=new Set(['/api/status','/api/settings','/api/observer','/api/clients']);
 const server=http.createServer(async(req,res)=>{let locked=false;for(const[k,v]of Object.entries(security))res.setHeader(k,v);try{
 need(allowed(req),'usb_only',403);
 if(!acceptedHosts().includes(req.headers.host)&&['GET','HEAD'].includes(req.method)&&!req.url.startsWith('/api/')&&c.brokerSocket&&readPortalState(path.dirname(c.brokerSocket)+'/captive.json').active){res.writeHead(302,{location:portalUrl,connection:'close'});res.end();return;}
 need(acceptedHosts().includes(req.headers.host),'invalid_host',403);
 const mutation=req.method!=='GET';if(mutation){need(req.method==='POST','method',405);need(req.headers.origin==='http://'+req.headers.host,'origin',403);}
 if(req.url==='/api/login'){need(req.method==='POST','method',405);const p=await body(req,1024);exact(p,['password']);const s=await auth.login(p.password,req.socket.remoteAddress);send(res,200,{csrf:s.csrf,defaultPassword:s.defaultPassword},{'set-cookie':cookie(s.sid)});return;}
 if(req.url.startsWith('/api/')){
 const s=auth.session(req);if(mutation){auth.csrf(req,s);need(!mutationBusy,'operation_in_progress',409);mutationBusy=true;locked=true;}const p=mutation?await body(req):{};
 if(req.url==='/api/session'){need(!mutation,'method',405);send(res,200,{csrf:s.csrf,defaultPassword:auth.record.defaultPassword});return;}
 if(req.url==='/api/logout'){need(mutation,'method',405);auth.sessions.delete(s.sid);send(res,200,{loggedOut:true},{'set-cookie':'mpn_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});return;}
 if(req.url==='/api/password'){need(mutation,'method',405);exact(p,['oldPassword','newPassword']);await auth.change(p.oldPassword,p.newPassword);send(res,200,{changed:true,loginRequired:true},{'set-cookie':'mpn_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'});return;}
 if(mutation)need(!auth.record.defaultPassword,'change_default_password_first',403);
 if(req.url==='/api/clients/export'){need(mutation,'method',405);exact(p,['name']);need(typeof p.name==='string'&&/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p.name),'client_name');const result=await rpc('/clients/export',p);send(res,200,result,{'content-disposition':'attachment; filename='+p.name+'.meshpn.json'});return;}
 if(req.url==='/api/observer/pcap'){need(!mutation,'method',405);need(!downloadBusy,'download_in_progress',429);downloadBusy=true;res.once('close',()=>{downloadBusy=false;});const result=await rpc('/observer/pcap',{});res.writeHead(200,{'content-type':'application/vnd.tcpdump.pcap','content-disposition':'attachment; filename=observer.pcap'});res.end(Buffer.from(result.base64,'base64'));return;}
 if(req.url==='/api/capture'){need(!mutation,'method',405);send(res,200,{active:!!capture,bundle:capture?.snapshot()??captureView});return;}
 if(req.url==='/api/capture/stop'){need(mutation,'method',405);send(res,200,await closeCapture());return;}
 if(req.url==='/api/capture/start'){
 need(mutation,'method',405);exact(p,['browser','version','platform','architecture','extensionOrder','echMode','padding']);need(!capture,'capture_busy',409);const certificateName=c.captureHostname??currentHostname+'.local';const authority=certificateName+':'+(c.publicCapturePort??c.capturePort);
 const metadata={schema:1,id:'browser-'+Date.now().toString(36),identity:{browser:p.browser,version:p.version,platform:p.platform,architecture:p.architecture,versionSource:'operator-declared'},context:{scenario:'cold',isolation:'operator-declared',certificateValidation:'enabled',http:'h2',proxy:'none',extensionOrder:p.extensionOrder,echMode:p.echMode,padding:p.padding}};
 const cert=c.state+'/capture.pem',key=c.state+'/capture.key';
 let renew=true;try{renew=Date.parse(new X509Certificate(fs.readFileSync(cert)).validTo)<Date.now()+86400000||readJson(c.state+'/capture-name.json',null)?.name!==certificateName;}catch{}
 if(renew){await run('/usr/bin/openssl',['req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',key,'-out',cert,'-days','30','-subj','/CN='+certificateName,'-addext','subjectAltName=DNS:'+certificateName+',IP:'+c.address],{timeout:15000});fs.chmodSync(key,0o600);atomic(c.state+'/capture-name.json',{name:certificateName});}
 capture=await startBrowserCapture({cert:fs.readFileSync(cert),key:fs.readFileSync(key),metadata,publicAuthority:authority,lifetimeMs:180000});captureTimer=setTimeout(()=>void closeCapture(),180000);const u=new URL(capture.url);send(res,200,{url:'https://'+authority+u.pathname,expiresSeconds:180,trust:'Device-generated certificate; establish trust before recording. No host trust settings changed.',autoActivation:false});return;
 }
 if(req.url==='/api/capture/certificate'){need(!mutation,'method',405);const file=c.state+'/capture.pem';need(fs.existsSync(file),'start_capture_first',404);res.writeHead(200,{'content-type':'application/x-pem-file','content-disposition':'attachment; filename=mpn-capture.pem'});res.end(fs.readFileSync(file));return;}
 const route=routes.get(req.url);need(route,'not_found',404);need(readonly.has(req.url)?!mutation:mutation,'method',405);const result=await rpc(route,p);if(req.url==='/api/settings')currentHostname=hostname(result.hostname);if(req.url==='/api/hostname')currentHostname=hostname(result.hostname);send(res,200,result);return;
 }
 need(!mutation,'method',405);const asset=new Map([['/','index.html'],['/capture','capture.html'],['/app.js','app.js'],['/capabilities.js','capabilities.js'],['/capture.js','capture.js'],['/style.css','style.css']]).get(req.url);need(asset,'not_found',404);res.writeHead(200,{'content-type':asset.endsWith('.js')?'text/javascript; charset=utf-8':asset.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8'});res.end(fs.readFileSync(path.join(PUBLIC,asset)));
 }catch(e){send(res,e.status??500,{error:safeError(e)});}finally{if(locked)mutationBusy=false;}});
 server.requestTimeout=15000;server.headersTimeout=5000;server.keepAliveTimeout=5000;server.maxConnections=32;server.on('clientError',(_,s)=>s.destroy());
 return{server,captureFront,auth,async close(){await closeCapture();if(captureFront.listening)captureFront.close();if(server.listening)server.close();}};
}
async function main(){need(process.argv.length===3,'config_argument');const c=readJson(process.argv[2]);const app=await createAdmin(c);if(Number(process.env.LISTEN_PID)===process.pid&&Number(process.env.LISTEN_FDS)===2){app.server.listen({fd:3});app.captureFront.listen({fd:4});}else{need(c.lab===true||c.container===true,'usb_socket_activation_required');app.server.listen(c.port,c.address);app.captureFront.listen(c.capturePort,c.address);}for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>void app.close());}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(e=>{console.error(safeError(e));process.exitCode=1;});

// Recover a local-lab VPN journal after SIGKILL/power loss. No Wi-Fi changes.
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {boardProfile} from './board-profile.mjs';
import {sameSubnet} from './perf-lib.mjs';
export async function restoreVPN(journal, api) {
  const s=await api('/api/status');
  assert.equal(s.board,journal.board,'Wrong board: no settings changed');
  assert.equal(s.net.usb_ip,journal.gateway,'Wrong USB gateway');
  assert.equal(typeof journal.ca_pem,'string');
  const saved=journal.original;
  assert(saved && typeof saved.enabled==='boolean' && typeof saved.kill_switch==='boolean');
  await api('/api/vpn/config',{enabled:false,transport:s.vpn.transport,server:s.vpn.server,tls_server_name:s.vpn.tls_server_name});
  await api('/api/vpn/tls-ca',{ca_pem:journal.ca_pem});
  await api('/api/vpn/config',saved);
  const after=await api('/api/status');
  for(const key of ['enabled','transport','server','kill_switch','tls_server_name'])
    assert.equal(after.vpn[key],saved[key],`VPN restore mismatch: ${key}`);
  assert.deepEqual(after.vpn.saved_servers,saved.saved_servers);
  assert.equal((await api('/api/vpn/tls-ca')).ca_pem,journal.ca_pem);
}
export async function restoreFile(file) {
  const journal=JSON.parse(await fs.readFile(file,'utf8'));
  if(journal.restored)return;
  const profile=boardProfile(journal.board);
  assert.equal(profile.usb,journal.gateway,'Journal is not for the selected USB subnet');
  const candidates=Object.values(os.networkInterfaces()).flat().filter(a=>!a.internal&&a.family==='IPv4'&&sameSubnet(a.address,journal.gateway,a.netmask));
  assert.equal(candidates.length,1,'Expected one directly attached USB source');
  let token;
  async function api(resource,data) {
    const body=data===undefined?null:JSON.stringify(data);
    return new Promise((resolve,reject)=>{
      const req=http.request({host:journal.gateway,localAddress:candidates[0].address,path:resource,
        method:body?'POST':'GET',agent:false,headers:{Host:profile.hostname,
          ...(token?{Authorization:`Bearer ${token}`} : {}),
          ...(body?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}:{})}},res=>{
        let text='';res.setEncoding('utf8');res.on('data',b=>{text+=b;if(text.length>256*1024)req.destroy(Error('Oversize response'));});
        res.on('error',reject);res.on('end',()=>{
          if(res.statusCode!==200){reject(Error(resource+': HTTP '+res.statusCode));return;}
          try{resolve(JSON.parse(text));}catch(e){reject(e);}
        });
      });
      const timer=setTimeout(()=>req.destroy(Error('API deadline')),15000);
      req.on('close',()=>clearTimeout(timer));req.on('error',reject);req.end(body);
    });
  }
  token=(await api('/api/login',{password:process.env.MESHPN_ADMIN_PASSWORD??'admin'})).token;
  assert(token,'No authentication token');
  await restoreVPN(journal,api);
  journal.restored=true;journal.restored_at=new Date().toISOString();
  const tmp=file+'.tmp';await fs.writeFile(tmp,JSON.stringify(journal,null,2),{mode:0o600});await fs.rename(tmp,file);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==3)throw Error('Usage: node vpn-local-restore.mjs RUN/restore.json');
  await restoreFile(process.argv[2]);console.log('VPN settings and public CA restored and verified');
}

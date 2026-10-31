import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { browserOrigin } from './lib/browser-lab-origin.mjs';
import { probeNativeHttp2 } from './clean-vpn-native-h2-probe.mjs';

const profilePath='fixtures/native-tls-profiles/chromium-156-bounded-http.json';
const profile=JSON.parse(await fs.readFile(profilePath));
test('independent TLS endpoint observes saved UA, pseudo order and bounded H2 SETTINGS', {timeout:60000},async()=>{
  const report=await probeNativeHttp2(profilePath);
  for(const sample of report.bundle.samples){
    const h=sample.http2;
    assert.deepEqual(h.headers.names.slice(0,4),profile.http.http2_pseudo_header_order);
    assert.deepEqual(h.headers.publicValues.find(([name])=>name==='user-agent'),['user-agent',profile.http.user_agent]);
    assert.deepEqual(h.settingsFrames,[profile.http2.settings]);
    assert.ok(h.settingsFrames.flat().every(([id])=>id!==3));
    assert.deepEqual(h.windowUpdates,[{streamId:0,increment:profile.http2.connection_window-65535}]);
    assert.equal(h.firstHeaders.priority,null,'priority remains an explicit browser difference');
    assert.ok(h.headers.names.includes('authorization'));
  }
  assert.doesNotMatch(JSON.stringify(report),/Bearer /);
  if(process.env.CVPN_HTTP_PROFILE_RECEIPT){
    assert.ok(path.isAbsolute(process.env.CVPN_HTTP_PROFILE_RECEIPT));
    await fs.writeFile(process.env.CVPN_HTTP_PROFILE_RECEIPT,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  }
});

test('independent HTTP/1.1 endpoint observes saved UA with fixed authenticated carrier', {timeout:20000},async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'cvpn-http-profile-'));
  const sockets=new Set();let server,child;
  try{
    const origin=await browserOrigin(dir),requests=[];
    server=tls.createServer({...origin.originTls,ALPNProtocols:['http/1.1']},socket=>{
      sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});
      let bytes='';socket.setTimeout(3000,()=>socket.destroy());
      socket.on('data',chunk=>{
        bytes+=chunk.toString('latin1');if(bytes.length>8192){socket.destroy();return;}
        if(!bytes.includes('\r\n\r\n'))return;
        const lines=bytes.split('\r\n\r\n',1)[0].split('\r\n');
        assert.equal(lines[0],'POST /clean-vpn HTTP/1.1');
        const headers=Object.fromEntries(lines.slice(1).map(line=>{const at=line.indexOf(':');return[line.slice(0,at).toLowerCase(),line.slice(at+1).trim()];}));
        // Only keep the explicitly public UA and the presence of authentication.
        requests.push({userAgent:headers['user-agent'],authenticated:/^Bearer /.test(headers.authorization??'')});
        socket.removeAllListeners('data');socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
      });
    });
    server.listen(0,'127.0.0.1');await once(server,'listening');
    await fs.writeFile(dir+'/psk',randomBytes(32),{mode:0o600});
    await fs.copyFile(profilePath,dir+'/profile.json');
    await fs.writeFile(dir+'/client.json',JSON.stringify({version:1,role:'client',address:'127.0.0.1',port:server.address().port,
      tun:'cvtest0',secret_path:dir+'/psk',server_name:'localhost',ca:origin.caPath,tls_profile_path:dir+'/profile.json',http_version:'auto'}),{mode:0o600});
    const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
    child=spawn(build+'/integration-test',[build+'/clean-vpn-engine-fixture',dir+'/client.json','client-reject:vpn_response_rejected'],{stdio:['ignore','pipe','pipe']});
    let bytes=0;for(const stream of[child.stdout,child.stderr])stream.on('data',b=>{bytes+=b.length;if(bytes>65536)child.kill('SIGKILL');});
    const timeout=setTimeout(()=>child.kill('SIGKILL'),12000);
    let code;try{[code]=await once(child,'close');}finally{clearTimeout(timeout);}
    assert.equal(code,0);assert.ok(requests.length>0&&requests.length<=4);
    for(const request of requests)assert.deepEqual(request,{userAgent:profile.http.user_agent,authenticated:true});
  }finally{
    if(child?.pid&&child.exitCode===null&&child.signalCode===null){child.kill('SIGKILL');await once(child,'close').catch(()=>{});}
    for(const socket of sockets)socket.destroy();
    if(server?.listening)await new Promise(r=>server.close(r));
    await fs.rm(dir,{recursive:true,force:true});
  }
});

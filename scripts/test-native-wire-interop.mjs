// Reference legacy endpoint is used only by this compatibility test. The new
// engine/control runtime never bridges TLS, H2 or packet payloads through Node.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import net from 'node:net';
import http2 from 'node:http2';
import { loadTlsDateFixture,startDateExit,fixtureCert } from './lib/vpn-http-date-fixture.mjs';
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
function driver(config,mode,t){
  const p=spawn(path.join(build,'integration-test'),[path.join(build,'clean-vpn-engine-fixture'),config,mode],{stdio:['ignore','pipe','pipe']});
  let output='';for(const s of [p.stdout,p.stderr])s.on('data',b=>{output+=b;});
  const timer=setTimeout(()=>p.kill('SIGKILL'),15000);t.after(()=>{clearTimeout(timer);p.kill('SIGKILL');});
  const done=once(p,'close').then(([code])=>{clearTimeout(timer);assert.equal(code,0,output);return output;});
  return {p,done,output:()=>output};
}
for(const direction of ['native-client','native-exit','malformed-frame','missing-auth','oversized-headers'])test(`TLS/H2/exporter auth interop: ${direction}`,{timeout:20000},async t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-interop-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const secret=randomBytes(32),secretPath=path.join(dir,'psk');fs.writeFileSync(secretPath,secret,{mode:0o600});
  const config=path.join(dir,'config.json');const cert=fileURLToPath(new URL('./fixtures/boring-tls-local.cert.pem',import.meta.url));
  const common={version:1,address:'127.0.0.1',tun:'cvtest0',secret_path:secretPath};
  if(direction==='native-client'){
    const server=await startDateExit({protocol:'h2',secret});t.after(()=>server.close());
    fs.writeFileSync(config,JSON.stringify({...common,role:'client',port:server.port,server_name:'localhost',ca:cert}));
    const run=driver(config,'client-handshake',t);assert.match(await run.done,/legacy exit handshake PASS/);assert.equal(server.bridges(),1);
  }else{
    const listener=net.createServer();listener.listen(0,'127.0.0.1');await once(listener,'listening');const port=listener.address().port;await new Promise(r=>listener.close(r));
    const key=fileURLToPath(new URL('./fixtures/boring-tls-local.key.pem',import.meta.url));
    fs.writeFileSync(config,JSON.stringify({...common,role:'exit',port,cert,key}));
    const denied=['missing-auth','oversized-headers'].includes(direction);
    const run=driver(config,denied?'exit-denied':direction==='malformed-frame'?'exit-malformed':'exit-handshake',t);
    await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(Error('native listener deadline')),5000);
      const check=()=>{if(run.output().includes('native exit listening')){clearTimeout(timer);run.p.stdout.off('data',check);resolve();}};
      run.p.stdout.on('data',check);check();
    });
    if(denied){
      const session=http2.connect(`https://127.0.0.1:${port}`,{ca:fixtureCert,servername:'localhost'});session.on('error',()=>{});t.after(()=>session.destroy());
      await once(session,'connect');
      const req=session.request({':method':'POST',':path':'/clean-vpn',...(direction==='oversized-headers'?{'x-oversized':'x'.repeat(9000)}:{})});req.on('error',()=>{});
      assert.match(await run.done,/unauthenticated H2 rejected PASS/);return;
    }
    const client=loadTlsDateFixture();const wire=await client.connectCleanVpnTlsClient({host:'127.0.0.1',port,ca:fixtureCert,servername:'localhost',vpnSecret:secret});
    wire.on('error',()=>{});t.after(()=>wire.destroy());
    if(direction==='malformed-frame')wire.write(Buffer.from([0xff,0xff,0xff,0xff]));
    assert.match(await run.done,direction==='malformed-frame'?/malformed.*PASS/:/legacy client handshake PASS/);
  }
});

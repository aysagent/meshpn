#!/usr/bin/env node
/** Local measurement of the test engine, no TUN, routes, system DNS or packets. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { browserOrigin } from './lib/browser-lab-origin.mjs';
import { startBrowserCapture } from './lib/native-browser-capture-server.mjs';
import { readCaptureFile } from './clean-vpn-native-browser-capture.mjs';
export async function probeNativeHttp2(profilePath) {
  assert.equal(process.platform,'linux','Linux test engine required');
  const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
  const executable=path.join(build,'clean-vpn-engine-fixture');
  const engineSha256=createHash('sha256').update(await fs.readFile(executable)).digest('hex');
  const profileBytes=readCaptureFile(profilePath,16384),profile=JSON.parse(profileBytes);
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'cvpn-native-h2-probe-'));
  let server,child;
  try {
    const origin=await browserOrigin(dir);
    const metadata={schema:1,id:'native-cold-h2-probe',identity:{browser:'native-clean-vpn-engine-fixture',
      version:`sha256:${engineSha256}`,versionSource:'operator-declared',platform:process.platform,architecture:process.arch},
      context:{scenario:'cold',isolation:'fresh-process-per-sample',certificateValidation:'enabled',http:'h2',proxy:'none',
        echMode:profile.tls.ech_grease?'grease':'disabled',extensionOrder:profile.tls.permute_extensions?'permuted':'fixed',
        padding:profile.tls.optional_extension_types.includes(21)?'optional':'exact'}};
    server=await startBrowserCapture({...origin.originTls,metadata,nativeProbe:true,maxSamples:32,lifetimeMs:60000});
    const secret=path.join(dir,'psk'),config=path.join(dir,'client.json'),savedProfile=path.join(dir,'profile.json');
    await fs.writeFile(secret,randomBytes(32),{mode:0o600});await fs.writeFile(savedProfile,profileBytes,{mode:0o600});
    await fs.writeFile(config,JSON.stringify({version:1,role:'client',address:'127.0.0.1',port:Number(new URL(server.url).port),
      tun:'cvtest0',secret_path:secret,server_name:'localhost',ca:origin.caPath,tls_profile_path:savedProfile}),{mode:0o600});
    for(let i=0;i<3;i++) {
      child=spawn(path.join(build,'integration-test'),[executable,config,'client-reject:vpn_response_rejected'],{stdio:['ignore','pipe','pipe']});
      let output='';for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{output+=b;if(output.length>65536)child.kill('SIGKILL');});
      const timeout=setTimeout(()=>child.kill('SIGKILL'),12000);
      let code;try {[code]=await once(child,'close');}finally {clearTimeout(timeout);}
      assert.equal(code,0,'native probe failed');child=null;
    }
    const bundle=server.snapshot();
    assert.ok(bundle.samples.length>=3 && bundle.samples.length<=12);
    assert.ok(bundle.samples.every(s=>s.http2?.status==='complete'));
    assert.ok(bundle.samples.every(s=>s.http2.headers.names.includes('authorization')));
    assert.doesNotMatch(JSON.stringify(bundle),/Bearer /);
    return {schema:1,kind:'clean-vpn-native-h2-probe-report',engineSha256,
      profileSha256:createHash('sha256').update(profileBytes).digest('hex'),
      captureEndpoint:{implementation:'Node TLS -> loopback cleartext H2',node:process.version,openssl:process.versions.openssl,
        settings:{maxConcurrentStreams:4,maxHeaderListSize:8192},alps:'not-negotiated',tls:'TLSv1.3-only'},
      validation:{expectedHttp403:true,packetInjection:false,systemSettingsChanged:false,physicalHostsTouched:false},bundle};
  } finally {
    if(child?.pid && child.exitCode===null && child.signalCode===null){child.kill('SIGKILL');await once(child,'close').catch(()=>{});}
    await server?.close();await fs.rm(dir,{recursive:true,force:true});
  }
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    const [output,profile,...extra]=process.argv.slice(2);assert.ok(output&&profile&&!extra.length);
    const report=await probeNativeHttp2(profile);
    await fs.writeFile(output,JSON.stringify(report,null,2)+'\n',{mode:0o600,flag:'wx'});
    console.log(JSON.stringify({status:'measured',samples:report.bundle.samples.length,output,profileActivated:false}));
  }catch {console.error('Native H2 probe failed. Usage: node scripts/clean-vpn-native-h2-probe.mjs NEW_OUTPUT.json PROFILE.json (Linux fixture build required)');process.exitCode=1;}
}

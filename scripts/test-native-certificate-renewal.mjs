import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import net from 'node:net';
import {once} from 'node:events';
import {execFileSync} from 'node:child_process';
import {X509Certificate,randomBytes} from 'node:crypto';
import {prepareCertificateRenewal} from './lib/native-certificate-renewal.mjs';
const openssl=args=>execFileSync('openssl',args,{stdio:'pipe',timeout:30000});
function fixture(t,{ec=false}={}){
 const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-renew-')));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 openssl(['req','-x509','-newkey','rsa:2048','-nodes','-days','3','-subj','/CN=renewal-test-CA','-addext','basicConstraints=critical,CA:TRUE,pathlen:0','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',dir+'/ca.key','-out',dir+'/ca.pem']);fs.chmodSync(dir+'/ca.key',0o600);
 openssl(['req','-new',...(ec?['-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1']:['-newkey','rsa:2048']),'-nodes','-subj','/CN=vpn.example','-keyout',dir+'/old.key','-out',dir+'/old.csr']);
 fs.writeFileSync(dir+'/ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:vpn.example,DNS:backup.example\n');
 openssl(['x509','-req','-in',dir+'/old.csr','-CA',dir+'/ca.pem','-CAkey',dir+'/ca.key','-set_serial','12345','-days','2','-extfile',dir+'/ext','-out',dir+'/old.pem']);
 fs.writeFileSync(dir+'/psk',randomBytes(32),{mode:0o600});
 const config={version:1,role:'exit',tun:'cvpn0',address:'127.0.0.1',port:3443,secret_path:dir+'/psk',cert:dir+'/old.pem',key:dir+'/old.key'};
 fs.writeFileSync(dir+'/engine.json',JSON.stringify(config),{mode:0o600});
 const options={config:dir+'/engine.json',caCert:dir+'/ca.pem',caKey:dir+'/ca.key',serverName:'vpn.example',output:dir+'/candidate',engine:process.env.CVPN_ENGINE??process.execPath,days:1};
 const validator=process.env.CVPN_ENGINE?{}:{validateCandidate:file=>{const c=JSON.parse(fs.readFileSync(file));assert.equal(c.cert,options.output+'/cert.pem');assert.equal(c.secret_path,config.secret_path);}};
 return{dir,options,validator,config};
}
async function handshake(key,cert,ca){
 const server=tls.createServer({key,cert},s=>s.end('renewed'));server.listen(0,'127.0.0.1');await once(server,'listening');
 try{return await new Promise((resolve,reject)=>{const s=tls.connect({host:'127.0.0.1',port:server.address().port,servername:'vpn.example',ca,rejectUnauthorized:true});let data='';const timer=setTimeout(()=>s.destroy(Error('TLS timeout')),3000);s.on('error',reject);s.on('data',b=>data+=b);s.on('end',()=>resolve(data));s.on('close',()=>clearTimeout(timer));});}finally{await new Promise(r=>server.close(r));}
}
for(const ec of [false,true])test(`offline renewal preserves ${ec?'EC':'RSA'} leaf and SAN; existing CA verifies real TLS`,async t=>{
 const f=fixture(t,{ec}),before=fs.readFileSync(f.options.config),caKey=fs.readFileSync(f.options.caKey),old=fs.readFileSync(f.config.cert);
 const m=prepareCertificateRenewal(f.options,f.validator);assert.equal(m.installed,false);assert.equal(m.trustChanged,false);assert.equal(m.nativeConfigValidated,true);assert.deepEqual(m.sans,['DNS:vpn.example','DNS:backup.example']);assert.notEqual(m.previousLeafSha256,m.candidateLeafSha256);
 assert.ok(fs.readFileSync(f.options.config).equals(before));assert.ok(fs.readFileSync(f.options.caKey).equals(caKey));assert.ok(fs.readFileSync(f.config.cert).equals(old));
 const candidate=JSON.parse(fs.readFileSync(f.options.output+'/engine.json'));assert.equal(new X509Certificate(fs.readFileSync(candidate.cert)).publicKey.asymmetricKeyType,ec?'ec':'rsa');
 for(const name of fs.readdirSync(f.options.output)){const b=fs.readFileSync(f.options.output+'/'+name);assert.equal(b.equals(caKey),false);assert.equal(fs.statSync(f.options.output+'/'+name).mode&0o077,0);}
 assert.equal(await handshake(fs.readFileSync(candidate.key),fs.readFileSync(candidate.cert),fs.readFileSync(f.options.caCert)),'renewed');
 assert.equal(await handshake(fs.readFileSync(f.config.key),old,fs.readFileSync(f.options.caCert)),'renewed'); // old files remain a working rollback.
});
test('wrong name, insufficient CA lifetime and existing output fail before mutation',t=>{
 const f=fixture(t);for(const patch of [{serverName:'wrong.example'},{days:4}]){assert.throws(()=>prepareCertificateRenewal({...f.options,...patch},f.validator));assert.equal(fs.existsSync(f.options.output),false);}
 fs.mkdirSync(f.options.output);fs.writeFileSync(f.options.output+'/keep','owned');assert.throws(()=>prepareCertificateRenewal(f.options,f.validator),/new_output_directory/);assert.equal(fs.readFileSync(f.options.output+'/keep','utf8'),'owned');
});
test('foreign signer key and foreign client trust are refused, failed candidate is removed',t=>{
 const f=fixture(t),g=fixture(t);assert.throws(()=>prepareCertificateRenewal({...f.options,caKey:g.options.caKey},f.validator),/CA_key_mismatch/);
 assert.throws(()=>prepareCertificateRenewal({...f.options,trust:g.options.caCert},f.validator),/certificate_command_failed/);assert.equal(fs.existsSync(f.options.output),false);
});
test('native rejection cleans only newly owned output and preserves source',t=>{
 const f=fixture(t),before=fs.readFileSync(f.options.config);assert.throws(()=>prepareCertificateRenewal(f.options,{validateCandidate(){throw Error('injected_native_rejection');}}),/injected_native_rejection/);assert.equal(fs.existsSync(f.options.output),false);assert.ok(fs.readFileSync(f.options.config).equals(before));
});
test('client role and unsafe CA key permissions are refused',t=>{
 const f=fixture(t);fs.chmodSync(f.options.caKey,0o644);assert.throws(()=>prepareCertificateRenewal(f.options,f.validator),/bounded_private_material/);fs.chmodSync(f.options.caKey,0o600);fs.writeFileSync(f.options.config,JSON.stringify({...f.config,role:'client'}));assert.throws(()=>prepareCertificateRenewal(f.options,f.validator),/TLS_exit_config/);
});
test('openssl sslserver purpose rejects an existing clientAuth-only leaf',t=>{
 const f=fixture(t);fs.writeFileSync(f.dir+'/bad-ext','basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:vpn.example\n');openssl(['x509','-req','-in',f.dir+'/old.csr','-CA',f.options.caCert,'-CAkey',f.options.caKey,'-set_serial','12346','-days','2','-extfile',f.dir+'/bad-ext','-out',f.config.cert]);assert.throws(()=>prepareCertificateRenewal(f.options,f.validator),/certificate_command_failed/);assert.equal(fs.existsSync(f.options.output),false);
});
test('every retained chain certificate bounds requested validity',t=>{
 const f=fixture(t);openssl(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=short-chain-ca','-addext','basicConstraints=critical,CA:TRUE','-keyout',f.dir+'/short.key','-out',f.dir+'/short.pem']);fs.appendFileSync(f.config.cert,fs.readFileSync(f.dir+'/short.pem'));assert.throws(()=>prepareCertificateRenewal(f.options,f.validator),/CA_validity_insufficient/);assert.equal(fs.existsSync(f.options.output),false);
});

for(const http_version of ['2','1.1'])test(`renewed leaf authenticates native H${http_version} tunnel with unchanged client CA`,{skip:!process.env.CVPN_ENGINE,timeout:60000},async t=>{
 const f=fixture(t);const probe=net.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(r=>probe.close(r));
 const server={...f.config,http_version,port};fs.writeFileSync(f.options.config,JSON.stringify(server));prepareCertificateRenewal(f.options,f.validator);
 const client={version:1,role:'client',tun:'cvtest0',address:'127.0.0.1',port,http_version,secret_path:f.config.secret_path,ca:f.options.caCert,server_name:'vpn.example'};fs.writeFileSync(f.dir+'/client.json',JSON.stringify(client),{mode:0o600});
 const build=path.dirname(process.env.CVPN_ENGINE);const output=execFileSync(build+'/integration-test',[build+'/clean-vpn-engine-fixture',f.dir+'/client.json',f.options.output+'/engine.json'],{encoding:'utf8',timeout:50000,maxBuffer:1024*1024});assert.match(output,/2000 packets PASS/);assert.match(output,/blackhole recovery/);
});

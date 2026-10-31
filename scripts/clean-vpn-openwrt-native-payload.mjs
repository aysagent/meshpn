#!/usr/bin/env node
// Generates PRIVATE lab media inputs, including fresh test-only credentials.
import fs from 'node:fs';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const {values:v}=parseArgs({options:Object.fromEntries(['architecture','engine','fixture','integration','directory','profile','package','tun-helper','tun-module','tun-index'].map(k=>[k,{type:'string'}]))});
assert.ok(v.directory&&path.isAbsolute(v.directory)&&!fs.existsSync(v.directory),'new_absolute_directory');
const architecture=v.architecture??'amd64';assert.ok(['amd64','arm64'].includes(architecture),'payload_architecture');const machine=architecture==='amd64'?62:183;
const tunOptions=['tun-helper','tun-module','tun-index'],enableTun=tunOptions.some(k=>v[k]);
assert.ok(!enableTun||tunOptions.every(k=>v[k]),'all_tun_inputs_required');
const sha=b=>createHash('sha256').update(b).digest('hex'),binaries={};
for(const name of['engine','fixture','integration',...(enableTun?['tun-device']:[])]){
 const input=v[name==='tun-device'?'tun-helper':name];
 assert.ok(input&&path.isAbsolute(input));const fd=fs.openSync(input,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=32*1024*1024);const b=fs.readFileSync(fd);
  assert.ok(b.length>=64&&b.subarray(0,4).equals(Buffer.from([127,69,76,70]))&&b[4]===2&&b[5]===1&&b.readUInt16LE(18)===machine,'matching_ELF_architecture_required');
  const offset=Number(b.readBigUInt64LE(32)),size=b.readUInt16LE(54),count=b.readUInt16LE(56);
  assert.ok(Number.isSafeInteger(offset)&&size>=56&&count<=128&&offset+size*count<=b.length);
  for(let i=0;i<count;i++)assert.notEqual(b.readUInt32LE(offset+i*size),3,'static_ELF_required');
  binaries[name]=b;
 }finally{fs.closeSync(fd);}
}
let packageBytes=null;
if(v.package){
 assert.ok(path.isAbsolute(v.package));const fd=fs.openSync(v.package,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=16*1024*1024);packageBytes=fs.readFileSync(fd);}finally{fs.closeSync(fd);}
}
const tunInputs={};
if(enableTun)for(const key of['tun-module','tun-index']){
 assert.ok(path.isAbsolute(v[key]));const fd=fs.openSync(v[key],fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=256*1024);tunInputs[key]=fs.readFileSync(fd);}finally{fs.closeSync(fd);}
 const expected=architecture==='amd64'?{'tun-module':'7cd0d957458e6feb37afffed1a972532977bbb4a5acc1349a7aeb2366a91a074','tun-index':'ce8105f6fe7a6070c5964fd02174d637606ccf96d6d8f42078e6efe726a0c6cb'}:
 {'tun-module':'cf50e6c6a97f086810871daefae92cf18b0f3bc0da89550abd9c6e9887eab7ab','tun-index':'a9a137f0e30c823ec9a142aedafc2d34029bc6739e33ce4778d644ba32473da3'};
 assert.equal(sha(tunInputs[key]),expected[key],'official_tun_input_sha256');
}
const profile=fs.readFileSync(v.profile??'fixtures/native-tls-profiles/chromium-156-bounded-http.json');assert.ok(profile.length<=16384);JSON.parse(profile);
assert.ok(Object.values(binaries).reduce((n,b)=>n+b.length,0)<48*1024*1024);
fs.mkdirSync(v.directory,{mode:0o700});
const write=(name,data,mode=0o600)=>fs.writeFileSync(path.join(v.directory,name),data,{mode,flag:'wx'});
for(const[name,b]of Object.entries(binaries))write(name,b,0o755);
if(packageBytes)write('engine.apk',packageBytes);
if(enableTun){
 write('kmod-tun-6.12.112-r1.apk',tunInputs['tun-module']);write('packages.adb',tunInputs['tun-index']);
 write('tun-smoke.sh',fs.readFileSync(fileURLToPath(new URL('../openwrt/lab/tun-smoke.sh',import.meta.url))));
}
write('profile.json',profile);write('psk',randomBytes(32));write('wrong.psk',randomBytes(32));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
 '-keyout',v.directory+'/key.pem','-out',v.directory+'/cert.pem'],{stdio:'pipe',timeout:15000});
fs.chmodSync(v.directory+'/key.pem',0o600);
const root='/tmp/cvpn-openwrt-native';
const common={version:1,address:'127.0.0.1',port:3443,tun:'cvtest0',secret_path:root+'/psk'};
const client={...common,role:'client',http_version:'auto',server_name:'localhost',ca:root+'/cert.pem',tls_profile_path:root+'/profile.json'};
write('client.json',JSON.stringify(client));write('bad-client.json',JSON.stringify({...client,secret_path:root+'/wrong.psk'}));
for(const version of['2','1.1'])write('exit-'+version+'.json',JSON.stringify({...common,role:'exit',http_version:version,cert:root+'/cert.pem',key:root+'/key.pem',alps:true}));
if(enableTun){
 write('tun-client.json',JSON.stringify({...client,tun:'cvctun0',connection_mode:'persistent'}));
 for(const version of['2','1.1'])write('tun-exit-'+version+'.json',JSON.stringify({...common,tun:'cvetun0',role:'exit',http_version:version,cert:root+'/cert.pem',key:root+'/key.pem',alps:true}));
}
const installPackage=packageBytes?String.raw`
apk --no-network --allow-untrusted add "$media/engine.apk"
test "$(sha256sum /usr/sbin/clean-vpn-engine | cut -d ' ' -f 1)" = '${sha(binaries.engine)}'
/usr/sbin/clean-vpn-engine --check-config "$work/client.json" >/dev/null
/usr/sbin/clean-vpn-engine --capabilities >"$work/installed-capabilities.json"
test "$(jsonfilter -i "$work/installed-capabilities.json" -e '@.packet_ipc')" = false
printf 'CVPN_OPENWRT_PACKAGE=installed-and-checked\n'
`:'';
write('run.sh',String.raw`#!/bin/sh
set -eu
media=/mnt/cvpn-payload
work=/tmp/cvpn-openwrt-native
mkdir -m 700 "$work"
for file in psk wrong.psk key.pem cert.pem profile.json client.json bad-client.json exit-2.json exit-1.1.json${enableTun?' tun-client.json tun-exit-2.json tun-exit-1.1.json':''}; do cp "$media/$file" "$work/$file"; done
chmod 600 "$work"/*
${installPackage}
"$media/engine" --capabilities >"$work/capabilities.json"
test "$(jsonfilter -i "$work/capabilities.json" -e '@.packet_ipc')" = false
test "$(jsonfilter -i "$work/capabilities.json" -e '@.experimental_tls_profiles.prewire_check')" = true
"$media/engine" --check-config "$work/client.json" >/dev/null
"$media/integration" "$media/fixture" "$work/client.json" "$work/exit-2.json" service
printf 'CVPN_OPENWRT_NATIVE_H2=passed
'
"$media/integration" "$media/fixture" "$work/client.json" "$work/exit-1.1.json" service
printf 'CVPN_OPENWRT_NATIVE_H1=passed
'
"$media/integration" "$media/fixture" "$work/bad-client.json" "$work/exit-2.json" reject
printf 'CVPN_OPENWRT_NATIVE_PSK_REJECTION=passed\n'
${enableTun?'sh "$media/tun-smoke.sh"':''}
printf 'CVPN_OPENWRT_NATIVE=passed\n'
rm -rf "$work"
`);
write('manifest.json',JSON.stringify({schema:1,kind:'openwrt-native-lab-payload',architecture,
 binaries:Object.fromEntries(Object.entries(binaries).map(([n,b])=>[n,{sha256:sha(b),bytes:b.length}])),profileSha256:sha(profile),packageSha256:packageBytes?sha(packageBytes):null,
 tun:enableTun?{moduleSha256:sha(tunInputs['tun-module']),indexSha256:sha(tunInputs['tun-index']),scriptSha256:sha(fs.readFileSync(fileURLToPath(new URL('../openwrt/lab/tun-smoke.sh',import.meta.url))))}:null,
 credentials:'fresh-test-only-never-production',scope:enableTun?'static engine and fixture FD TLS plus normal TUN H1/H2 with isolated source-policy routing; no WAN/LuCI/browser-equivalence claim':'static engine check-config and fixture FD TLS; no TUN/routing/browser-equivalence claim'},null,2)+'\n');
console.log(JSON.stringify({status:'prepared',directory:v.directory,privateTestCredentials:true,physicalHostsTouched:false}));

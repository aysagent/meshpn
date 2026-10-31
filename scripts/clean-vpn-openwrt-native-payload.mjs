#!/usr/bin/env node
// Generates PRIVATE lab media inputs, including fresh test-only credentials.
import fs from 'node:fs';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
const {values:v}=parseArgs({options:Object.fromEntries(['engine','fixture','integration','directory','profile'].map(k=>[k,{type:'string'}]))});
assert.ok(v.directory&&path.isAbsolute(v.directory)&&!fs.existsSync(v.directory),'new_absolute_directory');
const sha=b=>createHash('sha256').update(b).digest('hex'),binaries={};
for(const name of['engine','fixture','integration']){
 assert.ok(v[name]&&path.isAbsolute(v[name]));const fd=fs.openSync(v[name],fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=32*1024*1024);const b=fs.readFileSync(fd);
  assert.ok(b.length>=64&&b.subarray(0,4).equals(Buffer.from([127,69,76,70]))&&b[4]===2&&b[5]===1&&b.readUInt16LE(18)===62,'amd64_ELF_required');
  const offset=Number(b.readBigUInt64LE(32)),size=b.readUInt16LE(54),count=b.readUInt16LE(56);
  assert.ok(Number.isSafeInteger(offset)&&size>=56&&count<=128&&offset+size*count<=b.length);
  for(let i=0;i<count;i++)assert.notEqual(b.readUInt32LE(offset+i*size),3,'static_ELF_required');
  binaries[name]=b;
 }finally{fs.closeSync(fd);}
}
const profile=fs.readFileSync(v.profile??'fixtures/native-tls-profiles/chromium-156-bounded-http.json');assert.ok(profile.length<=16384);JSON.parse(profile);
assert.ok(Object.values(binaries).reduce((n,b)=>n+b.length,0)<48*1024*1024);
fs.mkdirSync(v.directory,{mode:0o700});
const write=(name,data,mode=0o600)=>fs.writeFileSync(path.join(v.directory,name),data,{mode,flag:'wx'});
for(const[name,b]of Object.entries(binaries))write(name,b,0o755);
write('profile.json',profile);write('psk',randomBytes(32));write('wrong.psk',randomBytes(32));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
 '-keyout',v.directory+'/key.pem','-out',v.directory+'/cert.pem'],{stdio:'pipe',timeout:15000});
fs.chmodSync(v.directory+'/key.pem',0o600);
const root='/tmp/cvpn-openwrt-native';
const common={version:1,address:'127.0.0.1',port:3443,tun:'cvtest0',secret_path:root+'/psk'};
const client={...common,role:'client',http_version:'auto',server_name:'localhost',ca:root+'/cert.pem',tls_profile_path:root+'/profile.json'};
write('client.json',JSON.stringify(client));write('bad-client.json',JSON.stringify({...client,secret_path:root+'/wrong.psk'}));
for(const version of['2','1.1'])write('exit-'+version+'.json',JSON.stringify({...common,role:'exit',http_version:version,cert:root+'/cert.pem',key:root+'/key.pem',alps:true}));
write('run.sh',String.raw`#!/bin/sh
set -eu
media=/mnt/cvpn-payload
work=/tmp/cvpn-openwrt-native
mkdir -m 700 "$work"
for file in psk wrong.psk key.pem cert.pem profile.json client.json bad-client.json exit-2.json exit-1.1.json; do cp "$media/$file" "$work/$file"; done
chmod 600 "$work"/*
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
printf 'CVPN_OPENWRT_NATIVE_PSK_REJECTION=passed
CVPN_OPENWRT_NATIVE=passed
'
rm -rf "$work"
`);
write('manifest.json',JSON.stringify({schema:1,kind:'openwrt-native-lab-payload',
 binaries:Object.fromEntries(Object.entries(binaries).map(([n,b])=>[n,{sha256:sha(b),bytes:b.length}])),profileSha256:sha(profile),
 credentials:'fresh-test-only-never-production',scope:'static engine check-config and fixture FD TLS; no TUN/routing/browser-equivalence claim'},null,2)+'\n');
console.log(JSON.stringify({status:'prepared',directory:v.directory,privateTestCredentials:true,physicalHostsTouched:false}));

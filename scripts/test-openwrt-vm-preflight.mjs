import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

test('OpenWrt runner refuses unverified images and symlinks before creating outputs or invoking Podman',t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-openwrt-preflight-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));
 const image=d+'/image.gz';fs.writeFileSync(image,'unverified image');fs.symlinkSync(image,d+'/link.gz');
 for(const file of[image,d+'/link.gz']){
  const r=spawnSync(process.execPath,['scripts/clean-vpn-openwrt-vm-smoke.mjs','--connection=nonexistent-test-only',
   '--qemu-image=localhost/nonexistent:test','--image-gz='+file,'--kernel='+d+'/missing-kernel',
   '--directory='+d+'/new','--report='+d+'/report.json'],{encoding:'utf8',timeout:5000});
  assert.equal(r.status,1);assert.match(r.stderr,/official_download_sha256|ELOOP/);
  assert.equal(fs.existsSync(d+'/new'),false);assert.equal(fs.existsSync(d+'/report.json'),false);
 }
});
test('OpenWrt runner rejects option/connection injection before filesystem or container operations',()=>{
 const r=spawnSync(process.execPath,['scripts/clean-vpn-openwrt-vm-smoke.mjs','--connection=bad;id','--qemu-image=--help'],{encoding:'utf8',timeout:5000});
 assert.equal(r.status,1);assert.match(r.stderr,/ERR_ASSERTION/);assert.equal(r.stdout,'');
});
test('native test payload refuses dynamic or foreign ELF before generating test credentials',t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-payload-preflight-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));
 const file=d+'/candidate';
 for(const dynamic of[false,true]){
  const b=Buffer.alloc(120);Buffer.from([127,69,76,70,2,1]).copy(b);b.writeUInt16LE(dynamic?62:183,18);
  b.writeBigUInt64LE(64n,32);b.writeUInt16LE(56,54);b.writeUInt16LE(1,56);b.writeUInt32LE(3,64);fs.writeFileSync(file,b);
  const r=spawnSync(process.execPath,['scripts/clean-vpn-openwrt-native-payload.mjs','--engine='+file,'--fixture='+file,
   '--integration='+file,'--directory='+d+'/new'],{encoding:'utf8',timeout:5000});
  assert.equal(r.status,1);assert.match(r.stderr,dynamic?/static_ELF_required/:/matching_ELF_architecture_required/);assert.equal(fs.existsSync(d+'/new'),false);
 }
});
test('TUN payload rejects incomplete inputs and unpinned kernel media before generating credentials',t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-tun-media-preflight-'));t.after(()=>fs.rmSync(d,{recursive:true,force:true}));
 const file=d+'/static';const b=Buffer.alloc(120);Buffer.from([127,69,76,70,2,1]).copy(b);b.writeUInt16LE(62,18);
 b.writeBigUInt64LE(64n,32);b.writeUInt16LE(56,54);b.writeUInt16LE(1,56);fs.writeFileSync(file,b);
 fs.writeFileSync(d+'/unverified','not official kernel media');
 const args=['scripts/clean-vpn-openwrt-native-payload.mjs','--engine='+file,'--fixture='+file,'--integration='+file,
  '--directory='+d+'/new','--tun-helper='+file];
 for(const extra of[[],['--tun-module='+d+'/unverified','--tun-index='+d+'/unverified']]){
  const r=spawnSync(process.execPath,[...args,...extra],{encoding:'utf8',timeout:5000});
  assert.equal(r.status,1);assert.match(r.stderr,extra.length?/official_tun_input_sha256/:/all_tun_inputs_required/);
  assert.equal(fs.existsSync(d+'/new'),false);
 }
});

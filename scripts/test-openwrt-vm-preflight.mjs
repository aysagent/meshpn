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

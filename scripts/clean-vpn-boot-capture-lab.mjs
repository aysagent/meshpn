#!/usr/bin/env node
/** Disposable NIC-less VM only. No host network writes or shared host filesystem. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
const [base, tools] = process.argv.slice(2);
assert.ok(base?.startsWith('/') && tools?.startsWith('/'), 'absolute passed host-boot artifacts and extracted QEMU tools required');
const previous=JSON.parse(fs.readFileSync(join(base,'report.json')));
assert.equal(previous.status,'passed'); assert.equal(previous.nic,'none'); assert.equal(previous.hostSharedFilesystem,false);
const hash=b=>createHash('sha256').update(b).digest('hex');
assert.equal(hash(fs.readFileSync(join(base,'guest-kernel'))),previous.image.kernelSha256);
const space=fs.statfsSync('/var/tmp'); assert.ok(space.bavail*space.bsize>768*1024*1024);
const root=fs.mkdtempSync('/var/tmp/meshpn-boot-capture-lab-'); console.error(root);
const guest=join(root,'guest');
const phases=['control','guard','failure','early-up','mid-failure'];
const sources=['scripts/clean-vpn-boot-capture.mjs','scripts/lib/host-boot-capture.mjs','scripts/lib/host-boot-capture-vm.mjs','scripts/autostart/killswitch.sh'];
const report={kind:'clean-vpn-boot-capture-lab',status:'failed',nic:'none',hostSharedFilesystem:false,base,
  sourceHashes:Object.fromEntries(sources.map(p=>[p,hash(fs.readFileSync(p))])),boots:[]};
const put=(p,s,mode=0o644)=>{const dst=join(guest,p);fs.mkdirSync(dst.slice(0,dst.lastIndexOf('/')),{recursive:true});fs.writeFileSync(dst,s,{mode});};
try {
  fs.cpSync(join(base,'guest'),guest,{recursive:true,verbatimSymlinks:true});
  for(const path of sources) put('/project/'+path,fs.readFileSync(path));
  put('/usr/local/lib/clean-vpn-boot-capture.mjs',fs.readFileSync('scripts/lib/host-boot-capture.mjs'));
  for(const path of ['/usr/bin/tcpdump','/usr/bin/systemd-notify','/usr/bin/systemd-analyze']) {
    put(path,fs.readFileSync(path),0o755);
    for(const lib of execFileSync('ldd',[path],{encoding:'utf8'}).match(/\/[^\s()]+/g)??[]) put(lib,fs.readFileSync(lib),0o755);
  }
  if (!fs.existsSync(join(guest,'usr/bin/which'))) fs.symlinkSync('/bin/busybox',join(guest,'usr/bin/which'));
  if (!fs.existsSync(join(guest,'usr/bin/awk'))) fs.symlinkSync('/bin/busybox',join(guest,'usr/bin/awk'));
  put('/etc/systemd/system/default.target','[Unit]\nDefaultDependencies=no\nWants=capture-test.service systemd-networkd.service netplan-wpa-wlan0.service systemd-udev-trigger.service multi-user.target\n');
  put('/etc/systemd/system/netplan-wpa-wlan0.service','[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/node /project/scripts/lib/host-boot-capture-vm.mjs wifi\nRemainAfterExit=yes\n');
  put('/etc/systemd/system/capture-test.service','[Unit]\nWants=dbus.service\nAfter=dbus.service systemd-networkd.service netplan-wpa-wlan0.service\n[Service]\nType=oneshot\nEnvironment=PATH=/usr/bin:/usr/sbin:/bin:/sbin\nEnvironmentFile=/etc/capture-phase.env\nExecStart=/usr/bin/node /project/scripts/lib/host-boot-capture-vm.mjs test\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=150\n');
  const old=fs.readFileSync(join(guest,'init'),'utf8'); assert.ok(old.includes('mount -t ext4'));
  for(const phase of phases) {
    put('/etc/capture-phase.env',`CAPTURE_PHASE=${phase}\n`);
    put('/init',old.slice(0,old.indexOf('mount -t ext4'))+`export CAPTURE_PHASE=${phase}\nnode scripts/lib/host-boot-capture-vm.mjs prepare\nmkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=info --show-status=no\n`,0o755);
    const files=['.']; const walk=p=>{for(const n of fs.readdirSync(join(guest,p))){const q=p?p+'/'+n:n;files.push(q);if(fs.lstatSync(join(guest,q)).isDirectory())walk(q);}};walk('');
    const archive=execFileSync('cpio',['-o','-H','newc','--owner=0:0','--quiet'],{cwd:guest,input:files.join('\n')+'\n',maxBuffer:256*1024*1024});
    const initrd=join(root,phase+'.gz');fs.writeFileSync(initrd,gzipSync(archive,{level:1}));
    const env={...process.env,LD_LIBRARY_PATH:`${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`,QEMU_MODULE_DIR:`${tools}/usr/lib/x86_64-linux-gnu/qemu`};delete env.LD_PRELOAD;delete env.LD_AUDIT;
    const p=spawn(join(tools,'usr/bin/qemu-system-x86_64'),['-nodefaults','-no-user-config','-nic','none','-display','none','-monitor','none','-no-reboot','-serial','stdio','-accel','tcg','-cpu','max','-m','1024','-smp','1','-bios',`${tools}/usr/share/seabios/bios-256k.bin`,'-L',`${tools}/usr/share/qemu`,'-kernel',join(base,'guest-kernel'),'-initrd',initrd,'-append','console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on meshpn.boot-capture-lab=1'],{env,stdio:['ignore','pipe','pipe']});
    let output='';const fd=fs.openSync(join(root,phase+'.log'),'wx');const timer=setTimeout(()=>p.kill('SIGKILL'),220000);
    for(const s of [p.stdout,p.stderr])s.on('data',b=>{fs.writeSync(fd,b);output+=b;if(output.length>1024*1024||output.includes('Kernel panic'))p.kill('SIGKILL');});
    let code;try{code=await new Promise((res,rej)=>{p.once('error',rej);p.once('close',res);});}finally{clearTimeout(timer);fs.closeSync(fd);}
    report.boots.push({phase,code,checks:output.split('\n').filter(l=>l.includes('BOOT_CAPTURE_CHECK'))});console.error(JSON.stringify(report.boots.at(-1)));
    assert.equal(code,0);assert.ok(output.includes('BOOT_CAPTURE_PASS')&&!output.includes('BOOT_CAPTURE_FAIL'),`inspect ${root}/${phase}.log`);
  }
  report.status='passed';
} finally {
  fs.writeFileSync(join(root,'report.json'),JSON.stringify(report,null,2));
  fs.rmSync(guest,{recursive:true,force:true});for(const p of phases)fs.rmSync(join(root,p+'.gz'),{force:true});
  console.error('Report: '+join(root,'report.json'));
}

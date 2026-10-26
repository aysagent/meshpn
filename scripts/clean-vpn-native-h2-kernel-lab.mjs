#!/usr/bin/env node
// Build a minimal initramfs from the cached Linux toolchain; QEMU has no NIC,
// disks, host filesystem shares or listeners. Never creates a host TUN/netem.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {once} from 'node:events';
import {gzipSync} from 'node:zlib';
assert.equal(process.platform,'linux');
assert.equal(process.arch,'x64');
const goodput=process.argv[3]==='--goodput';
assert.ok(process.argv.length===3||(process.argv.length===4&&goodput),'Usage: node scripts/clean-vpn-native-h2-kernel-lab.mjs NEW_REPORT.json [--goodput]');
const output=path.resolve(process.argv[2]);assert.equal(fs.existsSync(output),false,'output exists');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-h2-kernel-')),guest=path.join(root,'guest');
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
const hash=b=>createHash('sha256').update(b).digest('hex');
const put=(p,data,mode=0o644)=>{const dest=path.join(guest,p);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,data,{mode});};
const binary=(source,dest=source)=>{
  put(dest,fs.readFileSync(source),0o755);
  for(const lib of execFileSync('ldd',[source],{encoding:'utf8'}).match(/\/[^\s()]+/g)??[])put(lib,fs.readFileSync(lib),0o755);
};
let active=null;
const cancel=()=>active?.kill('SIGKILL');
process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
try{
  const release=fs.readFileSync('/opt/meshpn-kernel-release','utf8').trim();assert.match(release,/^[a-zA-Z0-9._-]+$/);
  const kernel='/boot/vmlinuz-'+release;
  const modules=[...new Set(['sch_netem',...(goodput?['tun','veth']:[])].flatMap(name=>execFileSync('modprobe',['--set-version',release,'--show-depends',name],{encoding:'utf8'})
    .trim().split('\n').filter(line=>!/^builtin [a-zA-Z0-9_]+$/.test(line)).map(line=>{assert.match(line,/^insmod \/lib\/modules\/[a-zA-Z0-9_./-]+\.ko\s*$/);return line.split(/\s+/)[1];})))];
  for(const m of modules)put(m,fs.readFileSync(m));
  put('/bin/busybox',fs.readFileSync('/bin/busybox'),0o755);
  fs.symlinkSync('busybox',path.join(guest,'bin/sh'));
  for(const file of ['/usr/local/bin/node','/usr/bin/openssl','/usr/sbin/ip','/usr/sbin/tc'])binary(file);
  for(const name of ['clean-vpn-engine','clean-vpn-engine-fixture',goodput?'h2-goodput-test':'integration-test'])binary(path.join(build,name),'/project/native/clean_vpn/build/'+name);
  put('/etc/ssl/openssl.cnf',fs.readFileSync('/etc/ssl/openssl.cnf'));
  const worker=goodput?'scripts/lib/native-h2-goodput-worker.mjs':'scripts/lib/native-h2-kernel-worker.mjs';
  for(const file of ['scripts/clean-vpn-native-h2-budget.mjs',worker,'fixtures/native-tls-profiles/cold-alps.json'])put('/project/'+file,fs.readFileSync(file));
  put('/init',`#!/bin/sh
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin
export OPENSSL_CONF=/etc/ssl/openssl.cnf
export LANG=C LC_ALL=C
/bin/busybox --install -s /bin
mkdir -p /proc /sys /dev /run /tmp
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
chmod 1777 /tmp
${modules.map(m=>'insmod '+m+' || poweroff -f').join('\n')}
ip link set lo up
cd /project
if node ${worker}; then echo H2_KERNEL_OK; else echo H2_KERNEL_FAILED; fi
sync
poweroff -f
`,0o755);
  const paths=['.'];const walk=p=>{for(const entry of fs.readdirSync(path.join(guest,p),{withFileTypes:true})){const q=path.join(p,entry.name);paths.push(q);if(entry.isDirectory())walk(q);}};walk('');
  const initrd=path.join(root,'initrd.gz');
  fs.writeFileSync(initrd,gzipSync(execFileSync('cpio',['-o','-H','newc','--owner=0:0','--quiet'],{cwd:guest,input:paths.join('\n')+'\n',maxBuffer:512*1024*1024}),{level:1}));
  const tools='/opt/meshpn-vm-tools/root';
  const child=spawn('/opt/meshpn-native-qemu/qemu-system-x86_64',['-nodefaults','-no-user-config','-nic','none',
    '-display','none','-monitor','none','-serial','stdio','-no-reboot','-accel','tcg','-cpu','qemu64','-smp','2','-m','1536',
    '-bios',tools+'/usr/share/seabios/bios-256k.bin','-L',tools+'/usr/share/qemu','-kernel',kernel,'-initrd',initrd,
    '-append','console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on meshpn.h2-kernel=1'+(goodput?' meshpn.h2-goodput=1':'')],{stdio:['ignore','pipe','pipe']});
  active=child;let serial='',progress='';const log=fs.openSync(output+'.serial.log','wx',0o600);
  const timer=setTimeout(cancel,20*60*1000);
  for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{
    fs.writeSync(log,b);serial+=b.toString();if(serial.length>4*1024*1024)cancel();
    progress+=b.toString();let end;
    while((end=progress.indexOf('\n'))>=0){
      const line=progress.slice(0,end);progress=progress.slice(end+1);
      if(line.startsWith('H2_KERNEL_STEP=')||line.startsWith('H2 budget ')||line.startsWith('H2_GOODPUT_CASE='))console.error(line.trim());
    }
  });
  let code;try{[code]=await once(child,'close');}finally{active=null;clearTimeout(timer);fs.closeSync(log);}
  assert.equal(code,0,serial.slice(-4000));
  assert.ok(serial.includes('H2_KERNEL_OK')&&!serial.includes('H2_KERNEL_FAILED'),serial.slice(-6000));
  const matches=[...serial.matchAll(/H2_KERNEL_REPORT=(\{[^\r\n]+\})/g)];assert.equal(matches.length,1);
  const report=JSON.parse(matches[0][1]);assert.equal(report.status,'passed');
  if(goodput){assert.equal(report.kind,'clean-vpn-native-h2-goodput-report');assert.equal(report.cases.length,24);}
  else assert.equal(report.reports.length,3);
  report.vm={kernel:release,kernelSha256:hash(fs.readFileSync(kernel)),accelerator:'TCG',vcpus:2,memoryMiB:1536};
  fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('H2_KERNEL=passed REPORT='+output);
}finally{cancel();process.off('SIGINT',cancel);process.off('SIGTERM',cancel);fs.rmSync(root,{recursive:true,force:true});}

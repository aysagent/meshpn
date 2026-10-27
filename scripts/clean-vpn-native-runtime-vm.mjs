#!/usr/bin/env node
// Build a minimal initramfs from the cached Linux toolchain; QEMU has no NIC,
// host filesystem shares or listeners. --reboot adds a private disposable ext4
// disk. Never creates a host TUN/netem.
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
assert.ok(process.argv.length===3||(process.argv.length===4&&['--host-wiring','--systemd','--reboot'].includes(process.argv[3])),
  'Usage: node scripts/clean-vpn-native-runtime-vm.mjs NEW_REPORT.json [--host-wiring|--systemd|--reboot]');
const reboot=process.argv[3]==='--reboot',systemd=reboot||process.argv[3]==='--systemd',hostWiring=systemd||process.argv[3]==='--host-wiring';
const output=path.resolve(process.argv[2]);assert.equal(fs.existsSync(output),false,'output exists');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-runtime-vm-')),guest=path.join(root,'guest');
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
const disk=path.join(root,'state.ext4');
if(reboot){const fd=fs.openSync(disk,'wx',0o600);fs.ftruncateSync(fd,64*1024*1024);fs.closeSync(fd);execFileSync('mkfs.ext4',['-F','-q',disk]);}
const hash=b=>createHash('sha256').update(b).digest('hex');
const sources={'runner':hash(fs.readFileSync(new URL(import.meta.url)))};
const put=(p,data,mode=0o644)=>{
  if(p.startsWith('/project/')||p.startsWith('/opt/clean-vpn/')||p==='/usr/local/bin/clean-vpn-engine')sources[p]=hash(data);
  const dest=path.join(guest,p);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,data,{mode});
};
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
  const modules=[...new Set(['tun','veth','bridge','nf_tables','nft_compat','nft_chain_nat','nft_nat','nft_masq','xt_conntrack','xt_tcpudp','xt_nat','xt_MASQUERADE','iptable_filter','ip6table_filter','iptable_nat','xt_mark',...(hostWiring?['xt_comment','xt_owner','xt_REDIRECT','xt_TCPMSS','iptable_mangle']:[]),...(reboot?['virtio_pci','virtio_blk','ext4']:[])].flatMap(name=>execFileSync('modprobe',['--set-version',release,'--show-depends',name],{encoding:'utf8'})
    .trim().split('\n').filter(line=>!/^builtin [a-zA-Z0-9_]+$/.test(line)).map(line=>{assert.match(line,/^insmod \/lib\/modules\/[a-zA-Z0-9_./-]+\.ko\s*$/);return line.split(/\s+/)[1];})))];
  for(const m of modules)put(m,fs.readFileSync(m));
  put('/bin/busybox',fs.readFileSync('/bin/busybox'),0o755);
  fs.symlinkSync('busybox',path.join(guest,'bin/sh'));
  for(const file of ['/usr/local/bin/node','/usr/bin/openssl','/usr/sbin/ip','/usr/bin/tcpdump',...['iptables-nft','ip6tables-nft','iptables-nft-save','ip6tables-nft-save','iptables-nft-restore','ip6tables-nft-restore'].map(n=>'/usr/sbin/'+n)])binary(file);
  binary(path.join(build,'clean-vpn-engine'),'/usr/local/bin/clean-vpn-engine');
  if(hostWiring)for(const file of ['/usr/sbin/dnsmasq','/usr/bin/flock'])binary(file);
  if(systemd){
    for(const file of ['/usr/lib/systemd/systemd','/usr/lib/systemd/systemd-executor','/usr/bin/systemctl'])binary(file);
    put('/etc/machine-id','1bb980253a274c03ac43bd6eb7cc22b1\n');
    put('/etc/os-release','ID=ubuntu\nPRETTY_NAME="clean-vpn disposable runtime VM"\n');
    put('/etc/systemd/system/default.target','[Unit]\nDefaultDependencies=no\nWants=runtime-driver.service\n');
    put('/etc/systemd/system/runtime-driver.service','[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/sh /runtime-driver.sh\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=15min\n');
    put('/runtime-driver.sh','#!/bin/sh\nexport PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin\ncd /project\nif node scripts/lib/native-runtime-vm-worker.mjs; then echo RUNTIME_VM_OK; if test -e /state/request-reboot; then rm /state/request-reboot; sync; reboot -f; fi; else echo RUNTIME_VM_FAILED; fi\nsync\npoweroff -f\n',0o755);
  }
  for(const name of fs.readdirSync('/usr/lib/x86_64-linux-gnu/xtables')) if(name.endsWith('.so')) binary('/usr/lib/x86_64-linux-gnu/xtables/'+name);
  put('/etc/passwd','root:x:0:0:root:/root:/bin/sh\ntcpdump:x:108:112:tcpdump:/:/bin/false\ndnslab:x:61453:61453:dnsmasq:/run:/bin/false\n');
  put('/etc/group','root:x:0:\ntcpdump:x:112:\ndnslab:x:61453:\n');
  put('/etc/ssl/openssl.cnf',fs.readFileSync('/etc/ssl/openssl.cnf'));
  put('/usr/lib/ssl/openssl.cnf',fs.readFileSync('/etc/ssl/openssl.cnf'));
  const worker='scripts/lib/native-runtime-vm-worker.mjs';
  for(const file of [worker,'scripts/lib/native-runtime-host-wiring-vm.mjs','scripts/lib/native-runtime-host-wiring-fixture.mjs','scripts/lib/native-runtime-lab-origin.mjs','scripts/clean-vpn-pcap-fingerprints.mjs','scripts/lib/tls-clienthello-ja3.mjs','scripts/lib/tls-clienthello-ja4.mjs','scripts/lib/native-tls-profile-observer.mjs','fixtures/native-tls-profiles/chromium-156-bounded-cold.json'])put('/project/'+file,fs.readFileSync(file));
  for(const file of ['clean-vpn-native-runtime-config.mjs','clean-vpn-native-gateway.mjs','clean-vpn-native-runtime-health.mjs','clean-vpn-native-runtime-preflight.mjs','lib/native-runtime-preflight-config.mjs','lib/native-runtime-gateway-plan.mjs','lib/native-runtime-plan.mjs','lib/native-runtime-units.mjs','lib/native-runtime-dhcp-probe.mjs'])put('/project/scripts/'+file,fs.readFileSync('scripts/'+file));
  for(const file of ['clean-vpn-native-runtime.mjs','clean-vpn-native-runtime-health.mjs','lib/native-runtime-plan.mjs'])put('/opt/clean-vpn/'+file,fs.readFileSync('scripts/'+file));
  put('/usr/local/bin/native-runtime',fs.readFileSync('scripts/containers/native-runtime-entrypoint.sh'),0o755);
  put('/opt/clean-vpn/containers/native-runtime-entrypoint.sh',fs.readFileSync('scripts/containers/native-runtime-entrypoint.sh'),0o755);
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
${reboot?'mkdir -p /state\nmount -t ext4 /dev/vda /state || poweroff -f':''}
ip link set lo up
cd /project
${systemd?'mkdir -p /sys/fs/cgroup\nmount -t cgroup2 none /sys/fs/cgroup\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=warning --show-status=no':''}
if node ${worker}; then echo RUNTIME_VM_OK; else echo RUNTIME_VM_FAILED; fi
sync
poweroff -f
`,0o755);
  const paths=['.'];const walk=p=>{for(const entry of fs.readdirSync(path.join(guest,p),{withFileTypes:true})){const q=path.join(p,entry.name);paths.push(q);if(entry.isDirectory())walk(q);}};walk('');
  const initrd=path.join(root,'initrd.gz');
  fs.writeFileSync(initrd,gzipSync(execFileSync('cpio',['-o','-H','newc','--owner=0:0','--quiet'],{cwd:guest,input:paths.join('\n')+'\n',maxBuffer:512*1024*1024}),{level:1}));
  const tools='/opt/meshpn-vm-tools/root';
  const boots=[];
  for(let boot=0;boot<(reboot?2:1);boot++){
  const child=spawn('/opt/meshpn-native-qemu/qemu-system-x86_64',['-nodefaults','-no-user-config','-nic','none',
    '-display','none','-monitor','none','-serial','stdio','-no-reboot','-accel','tcg','-cpu','qemu64','-smp','2','-m','1536',
    '-bios',tools+'/usr/share/seabios/bios-256k.bin','-L',tools+'/usr/share/qemu','-kernel',kernel,'-initrd',initrd,
    '-append','console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on meshpn.runtime-vm=1'+(hostWiring?' meshpn.runtime-host-wiring=1':'')+(reboot?' meshpn.runtime-reboot=1':''),
    ...(reboot?['-drive',`file=${disk},format=raw,if=virtio,cache=writeback`]:[])],{stdio:['ignore','pipe','pipe']});
  active=child;let serial='',progress='';const log=fs.openSync(output+(reboot?`.boot-${boot}`:'')+'.serial.log','wx',0o600);
  const timer=setTimeout(cancel,20*60*1000);
  for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{
    fs.writeSync(log,b);serial+=b.toString();if(serial.length>4*1024*1024)cancel();
    progress+=b.toString();let end;
    while((end=progress.indexOf('\n'))>=0){
      const line=progress.slice(0,end);progress=progress.slice(end+1);
      if(line.startsWith('RUNTIME_VM_STEP=')||line.startsWith('RUNTIME_STEP=')||line.startsWith('RUNTIME_STEP='))console.error(line.trim());
    }
  });
  let code;try{[code]=await once(child,'close');}finally{active=null;clearTimeout(timer);fs.closeSync(log);}
  assert.equal(code,0,serial.slice(-4000));
  assert.ok(serial.includes('RUNTIME_VM_OK')&&!serial.includes('RUNTIME_VM_FAILED'),serial.slice(-6000));
  const matches=[...serial.matchAll(/RUNTIME_VM_REPORT=(\{[^\r\n]+\})/g)];assert.equal(matches.length,1);
  const report=JSON.parse(matches[0][1]);assert.equal(report.status,'passed');
  assert.equal(report.kind,'native-runtime-standalone-vm');
  const captures=[...serial.matchAll(/RUNTIME_VM_PCAP=([A-Za-z0-9+/=]+)\r?\n/g)];assert.equal(captures.length,1);
  const pcap=Buffer.from(captures[0][1],'base64');assert.equal(hash(pcap),report.wire.pcapSha256);
  fs.writeFileSync(output+(reboot?`.boot-${boot}`:'')+'.pcap',pcap,{flag:'wx',mode:0o600});
  report.vm={kernel:release,kernelSha256:hash(fs.readFileSync(kernel)),accelerator:'TCG',vcpus:2,memoryMiB:1536};
  report.sourceHashes=sources;
  if(reboot){assert.equal(report.rebootPhase,boot);if(boot===0)assert.match(serial,/reboot: Restarting system/);}
  boots.push(report);
  }
  const report=structuredClone(boots.at(-1));
  if(reboot){assert.notEqual(boots[0].bootId,boots[1].bootId);assert.equal(boots[0].bundleFingerprint,boots[1].bundleFingerprint);report.boots=boots;report.vm.reboots=1;}
  fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log('RUNTIME_VM=passed REPORT='+output);
}finally{cancel();process.off('SIGINT',cancel);process.off('SIGTERM',cancel);fs.rmSync(root,{recursive:true,force:true});}

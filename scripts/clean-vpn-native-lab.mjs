#!/usr/bin/env node
// Explicit, NIC-less VM only. No host TUN, routes, firewall or production access.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import { compileTunnelDnsPlan } from './lib/dns-tunnel-plan.mjs';
import { usbSnatRule,usbMssRules } from './clean-vpn-usb-snat.mjs';
import { addUsbMssVmImage } from './lib/usb-mss-vm-image.mjs';
const [base,tools]=process.argv.slice(2);
assert.equal(process.argv.length,4,'usage: verified HOST_BOOT_BASE QEMU_TOOLS_ROOT');
for(const p of [base,tools])assert.ok(p?.startsWith('/')&&resolve(p)===p&&!/[\r\n,]/.test(p));
const hash=b=>createHash('sha256').update(b).digest('hex');
const prior=JSON.parse(fs.readFileSync(join(base,'report.json')));
assert.equal(prior.status,'passed');assert.equal(prior.nic,'none');assert.equal(prior.hostSharedFilesystem,false);
assert.equal(hash(fs.readFileSync(join(base,'guest-kernel'))),prior.image.kernelSha256);
const root=fs.mkdtempSync('/var/tmp/meshpn-native-lab-'),guest=join(root,'guest');
console.error('Native lab artifacts: '+root);
const report={status:'failed',nic:'none',hostSharedFilesystem:false,realTun:true,packetOwner:'C++',
  kernelSha256:prior.image.kernelSha256,accelerator:'TCG',vcpus:1,memoryMiB:1536,tunMtu:1400,
  guard:'existing-cvks4-usb-strict',benchmark:'three sequential 16 MiB-per-direction TCP echo rounds and 100 small echo RTTs; summed process-tree RSS, sampled CPU ticks',
  limitations:['fixture-PKI-and-origins','local-capture-not-on-wire-proof','not-systemd-installer-or-boot-acceptance','not-physical-Radxa-or-arm64','emulator-not-production-performance','RSS-not-PSS; sampling-may-miss-short-lived-processes','DNS-disabled-only-in-legacy-comparison']};
const put=(name,b,mode=0o644)=>{const p=join(guest,name);fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,b,{mode});fs.chmodSync(p,mode);};
try {
  fs.cpSync(join(base,'guest'),guest,{recursive:true,verbatimSymlinks:true});
  const copyScripts=dir=>{for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const p=join(dir,entry.name);if(entry.isDirectory())copyScripts(p);else if(/\.(m?js|sh)$/.test(p))put('/project/'+p,fs.readFileSync(p),p.endsWith('.sh')?0o755:0o644);}};copyScripts('scripts');
  report.legacyCliSha256=hash(fs.readFileSync('scripts/clean-vpn.js'));
  report.legacyHelperSha256=hash(fs.readFileSync(join(guest,'project/native/boring_tls/build/boring-tls-helper')));
  report.labScriptSha256=hash(fs.readFileSync('scripts/lib/native-tun-vm.sh'));
  put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('scripts/autostart/killswitch.sh'),0o755);
  for(const name of ['clean-vpn-engine','socket-test']){
    const bin=resolve('native/clean_vpn/build',name);put('/native/'+name,fs.readFileSync(bin),0o755);
    if(name==='clean-vpn-engine')put('/project/native/clean_vpn/build/'+name,fs.readFileSync(bin),0o755);
    report[name+'Sha256']=hash(fs.readFileSync(bin));
    for(const lib of execFileSync('ldd',[bin],{encoding:'utf8'}).match(/\/[^\s()]+/g)??[])put(lib,fs.readFileSync(lib),0o755);
  }
  for(const name of ['scripts/clean-vpn-native.mjs','scripts/lib/native-engine-controller.mjs'])put('/project/'+name,fs.readFileSync(name));
  for(const bin of ['/usr/sbin/sshd','/usr/bin/ssh','/usr/bin/ssh-keygen','/usr/bin/tcpdump']){
    put(bin,fs.readFileSync(bin),0o755);for(const lib of execFileSync('ldd',[bin],{encoding:'utf8'}).match(/\/[^\s()]+/g)??[])put(lib,fs.readFileSync(lib),0o755);
  }
  for(const name of ['admin','host'])execFileSync('ssh-keygen',['-q','-t','ed25519','-N','','-f',join(root,name)]);
  put('/native/admin',fs.readFileSync(join(root,'admin')),0o600);put('/native/host',fs.readFileSync(join(root,'host')),0o600);
  put('/root/.ssh/authorized_keys',fs.readFileSync(join(root,'admin.pub')),0o600);fs.chmodSync(join(guest,'root/.ssh'),0o700);
  put('/etc/shadow','root::20000:0:99999:7:::\n',0o600);
  put('/etc/passwd','root:x:0:0:root:/root:/bin/sh\nsshd:x:100:100:sshd:/run/sshd:/bin/false\n');
  put('/etc/group','root:x:0:\nsshd:x:100:\n');
  const pub=fs.readFileSync(join(root,'host.pub'),'utf8').trim().split(' ').slice(0,2).join(' ');
  put('/native/known_hosts','[192.168.7.1]:2222 '+pub+'\n');
  put('/native/sshd_config','HostKey /native/host\nAuthorizedKeysFile /root/.ssh/authorized_keys\nPasswordAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin yes\nUsePAM no\nUseDNS no\nDisableForwarding yes\nPermitTunnel no\nListenAddress 192.168.7.1\nPort 2222\n');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(root,'key.pem'),'-out',join(root,'cert.pem'),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],{stdio:'pipe'});
  put('/native/key.pem',fs.readFileSync(join(root,'key.pem')),0o600);put('/native/cert.pem',fs.readFileSync(join(root,'cert.pem')));put('/native/psk',randomBytes(32),0o600);
  put('/native/certs/fullchain.pem',fs.readFileSync(join(root,'cert.pem')));put('/native/certs/privkey.pem',fs.readFileSync(join(root,'key.pem')),0o600);
  const common={version:1,address:'154.62.226.216',port:443,tun:'tun0',secret_path:'/native/psk'};
  put('/native/client.json',JSON.stringify({...common,role:'client',dns:true,server_name:'localhost',ca:'/native/cert.pem'}));
  put('/native/exit.json',JSON.stringify({...common,role:'exit',cert:'/native/cert.pem',key:'/native/key.pem'}));
  put('/native/lab.sh',fs.readFileSync('scripts/lib/native-tun-vm.sh'),0o755);
  const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
  const plan=compileTunnelDnsPlan({tun:'tun0',lanInterface:'usb0',lanSubnet:'192.168.7.0/24'});
  put('/native/dns-plan.sh','#!/bin/sh\nset -eu\n'+plan.operations.map(op=>[op.file==='ip'?'/usr/bin/ip':op.file,...op.args].map(quote).join(' ')).join('\n')+'\n',0o755);
  put('/native/snat.sh','#!/bin/sh\nset -eu\n'+[['iptables','-w','5','-t','nat','-A','POSTROUTING',...usbSnatRule],...usbMssRules.map(r=>['iptables','-w','5','-t','mangle','-A','FORWARD',...r])].map(a=>a.map(quote).join(' ')).join('\n')+'\n',0o755);
  let init=addUsbMssVmImage(fs.readFileSync(join(base,'guest/init'),'utf8'),put).init;assert.ok(init.includes('cd /project'));
  const release=init.match(/insmod \/lib\/modules\/([^/]+)\//)[1];
  const mod=`/lib/modules/${release}/kernel/net/ipv4/netfilter/iptable_mangle.ko`;put(mod,fs.readFileSync(mod));init=init.replace('cd /project',`insmod ${mod}\ncd /project`);
  put('/init',init.slice(0,init.indexOf('cd /project'))+'\nif /bin/sh /native/lab.sh; then echo NATIVE_LAB_OK; else echo NATIVE_LAB_FAILED; fi\nsync\npoweroff -f\n',0o755);
  const paths=['.'];const walk=p=>{for(const name of fs.readdirSync(join(guest,p))){const q=p?p+'/'+name:name;paths.push(q);if(fs.lstatSync(join(guest,q)).isDirectory())walk(q);}};walk('');
  const initrd=join(root,'initrd.gz');fs.writeFileSync(initrd,gzipSync(execFileSync('cpio',['-o','-H','newc','--owner=0:0','--quiet'],{cwd:guest,input:paths.join('\n')+'\n',maxBuffer:320*1024*1024}),{level:1}));
  const env={...process.env,LD_LIBRARY_PATH:`${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`,QEMU_MODULE_DIR:`${tools}/usr/lib/x86_64-linux-gnu/qemu`};delete env.LD_PRELOAD;delete env.LD_AUDIT;
  const child=spawn(join(tools,'usr/bin/qemu-system-x86_64'),['-nodefaults','-no-user-config','-nic','none','-display','none','-monitor','none','-no-reboot','-serial','stdio','-accel','tcg','-cpu','max','-m','1536','-smp','1','-bios',`${tools}/usr/share/seabios/bios-256k.bin`,'-L',`${tools}/usr/share/qemu`,'-kernel',join(base,'guest-kernel'),'-initrd',initrd,'-append','console=ttyS0 loglevel=4 panic=-1 reboot=t random.trust_cpu=on meshpn.native-lab=1'],{env,stdio:['ignore','pipe','pipe']});
  let output='';const timer=setTimeout(()=>child.kill('SIGKILL'),1200000);const stop=()=>child.kill('SIGKILL');process.on('SIGINT',stop);process.on('SIGTERM',stop);
  const serial=fs.openSync(join(root,'serial.log'),'wx',0o600);
  for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{fs.writeSync(serial,b);output+=b;if(output.length>1024*1024)stop();});
  try {report.code=await new Promise((r,j)=>{child.once('error',j);child.once('close',r);});}
  finally{clearTimeout(timer);process.off('SIGINT',stop);process.off('SIGTERM',stop);fs.closeSync(serial);}
  assert.equal(report.code,0);assert.ok(output.includes('NATIVE_TUN_VM_PASS')&&output.includes('NATIVE_LAB_OK')&&!output.includes('NATIVE_LAB_FAILED'),output.slice(-10000));
  const checks=['NATIVE_DIRECT_POSITIVE_CONTROL_PASS','NATIVE_USB_DNS_ADMIN_PASS','NATIVE_DNS_UPSTREAM_FALLBACK_PASS',
    'NATIVE_USB_PRIVATE_IPV6_AND_DNS_UPLINK_BLOCK_PASS','NATIVE_TUN_RECONNECT_PASS','NATIVE_TUN_STOP_BLOCKS_PASS',
    'NATIVE_PRODUCTION_GUARD_RETAINED_PASS','NATIVE_CLIENT_OLD_EXIT_PACKETS_PASS','OLD_CLIENT_NATIVE_EXIT_PACKETS_PASS',
    'NATIVE_CLIENT_CRASH_GUARD_ADMIN_PASS','NATIVE_PROCESS_CLEANUP_PASS'];
  report.checks=Object.fromEntries(checks.map(name=>[name,output.includes(name)]));assert.ok(Object.values(report.checks).every(Boolean));
  report.benchmarks=[...output.matchAll(/^NATIVE_BENCH (\{[^\r\n]+\})/gm)].map(m=>JSON.parse(m[1]));
  assert.equal(report.benchmarks.length,6);
  assert.deepEqual(report.benchmarks.map(b=>b.label),['native-1','native-2','native-3','legacy-1','legacy-2','legacy-3']);
  assert.ok(report.benchmarks.every(b=>b.latencyMedianMs>0&&b.latencyP95Ms>0));
  report.status='passed';console.log(output.slice(-8000));
} catch(e){report.error=e.message;process.exitCode=1;console.error(e.message);}
finally{
  fs.writeFileSync(join(root,'report.json'),JSON.stringify(report,null,2));console.error(JSON.stringify(report));
  // Only this invocation's disposable expanded image; initrd/report/log remain.
  fs.rmSync(guest,{recursive:true,force:true});
}

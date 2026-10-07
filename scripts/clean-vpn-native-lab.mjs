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
import { addNativeSystemdImage, nativeSystemdChecks, nativeRouteChecks } from './lib/native-systemd-vm-image.mjs';
import { assertNativeBootEvidence } from './lib/native-boot-evidence.mjs';
import { addNativeNetworkImage, nativeNetworkChecks } from './lib/native-network-vm-image.mjs';
const [base,tools,mode]=process.argv.slice(2);
const nativeBoot=mode==='--native-boot';
const nativeRoutes=mode==='--native-routes';
const nativeSiteBoot=mode==='--native-site-boot';
const nativeNetwork=mode==='--native-network'||nativeSiteBoot;
const persistentBoot=nativeBoot||nativeSiteBoot;
const systemdNative=mode==='--native-systemd'||nativeBoot||nativeRoutes||nativeNetwork;
const nativeOnly=mode==='--native-only'||systemdNative;
assert.ok(process.argv.length===4||(process.argv.length===5&&nativeOnly),'usage: verified HOST_BOOT_BASE QEMU_TOOLS_ROOT [--native-only|--native-systemd|--native-boot|--native-routes|--native-network|--native-site-boot]');
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
if(nativeOnly){report.nativeOnly=true;report.benchmark='not-requested';report.limitations=report.limitations.filter(s=>s!=='DNS-disabled-only-in-legacy-comparison');}
const put=(name,b,mode=0o644)=>{const p=join(guest,name);fs.mkdirSync(p.slice(0,p.lastIndexOf('/')),{recursive:true});fs.writeFileSync(p,b,{mode});fs.chmodSync(p,mode);};
try {
  fs.cpSync(join(base,'guest'),guest,{recursive:true,verbatimSymlinks:true});
  if(nativeNetwork) for(const name of ['iptables-save','ip6tables-save']) put('/usr/sbin/'+name,fs.readFileSync('/usr/sbin/xtables-legacy-multi'),0o755);
  if(nativeNetwork){const p='/usr/lib/x86_64-linux-gnu/xtables/libxt_mark.so';put(p,fs.readFileSync(p),0o755);}
  const copyScripts=dir=>{for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const p=join(dir,entry.name);if(entry.isDirectory())copyScripts(p);else if(/\.(m?js|sh)$/.test(p))put('/project/'+p,fs.readFileSync(p),p.endsWith('.sh')?0o755:0o644);}};copyScripts('scripts');
  report.legacyCliSha256=hash(fs.readFileSync('scripts/clean-vpn.js'));
  report.legacyHelperSha256=hash(fs.readFileSync(join(guest,'project/native/boring_tls/build/boring-tls-helper')));
  report.labScriptSha256=hash(fs.readFileSync(systemdNative?'scripts/lib/native-systemd-vm.sh':'scripts/lib/native-tun-vm.sh'));
  if(systemdNative)report.serviceUnitRendererSha256=hash(fs.readFileSync('scripts/lib/native-service-unit.mjs'));
  put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('scripts/autostart/killswitch.sh'),0o755);
  for(const name of ['clean-vpn-engine','socket-test']){
    const bin=resolve('native/clean_vpn/build',name);put('/native/'+name,fs.readFileSync(bin),0o755);
    if(name==='clean-vpn-engine')put('/project/native/clean_vpn/build/'+name,fs.readFileSync(bin),0o755);
    report[name+'Sha256']=hash(fs.readFileSync(bin));
    for(const lib of execFileSync('ldd',[bin],{encoding:'utf8'}).match(/\/[^\s()]+/g)??[])put(lib,fs.readFileSync(lib),0o755);
  }
  for(const name of ['scripts/clean-vpn-native.mjs','scripts/lib/native-engine-controller.mjs'])put('/project/'+name,fs.readFileSync(name));
  for(const bin of ['/usr/sbin/sshd','/usr/bin/ssh','/usr/bin/ssh-keygen','/usr/bin/tcpdump',...(systemdNative?['/usr/bin/journalctl']:[])]){
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
  put('/native/exit.json',JSON.stringify({...common,secret_path:undefined,role:'exit',
    peers:[{ipv4:'10.99.0.2',secret_path:'/native/psk'}],cert:'/native/cert.pem',key:'/native/key.pem'}));
  put('/native/lab.sh',fs.readFileSync('scripts/lib/native-tun-vm.sh'),0o755);
  const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
  const plan=compileTunnelDnsPlan({tun:'tun0',lanInterface:'usb0',lanSubnet:'192.168.7.0/24'});
  put('/native/dns-plan.sh','#!/bin/sh\nset -eu\n'+plan.operations.map(op=>[op.file==='ip'?'/usr/bin/ip':op.file,...op.args].map(quote).join(' ')).join('\n')+'\n',0o755);
  put('/native/snat.sh','#!/bin/sh\nset -eu\n'+[['iptables','-w','5','-t','nat','-A','POSTROUTING',...usbSnatRule],...usbMssRules.map(r=>['iptables','-w','5','-t','mangle','-A','FORWARD',...r])].map(a=>a.map(quote).join(' ')).join('\n')+'\n',0o755);
  let init=addUsbMssVmImage(fs.readFileSync(join(base,'guest/init'),'utf8'),put).init;assert.ok(init.includes('cd /project'));
  const release=init.match(/insmod \/lib\/modules\/([^/]+)\//)[1];
  if(nativeNetwork){const mark=`/lib/modules/${release}/kernel/net/netfilter/xt_mark.ko`;put(mark,fs.readFileSync(mark));init=init.replace('cd /project',`insmod ${mark}\ncd /project`);}
  const mod=`/lib/modules/${release}/kernel/net/ipv4/netfilter/iptable_mangle.ko`;put(mod,fs.readFileSync(mod));init=init.replace('cd /project',`insmod ${mod}\ncd /project`);
  put('/init',init.slice(0,init.indexOf('cd /project'))+`\nexport CVPN_NATIVE_ONLY=${nativeOnly?'1':'0'}\nif /bin/sh /native/lab.sh; then echo NATIVE_LAB_OK; else echo NATIVE_LAB_FAILED; fi\nsync\npoweroff -f\n`,0o755);
  if(systemdNative){
    addNativeSystemdImage(put,{boot:nativeBoot||nativeNetwork,routes:nativeRoutes});
    if(nativeNetwork) addNativeNetworkImage(put);
    put('/init',init.slice(0,init.indexOf('cd /project'))+(persistentBoot?`\nmount -t ext4 -o rw /dev/vda /state\n/usr/bin/node /project/scripts/lib/${nativeSiteBoot?'native-site-boot-vm.mjs':'native-boot-vm.mjs'} prepare\n`:'')+'\nmkdir -p /run/dbus\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=info --show-status=no\n',0o755);
    report.systemdPid1=true;report.nativeDirectServices=true;report.realTunPeers=2;
    report.guard='fixture-persistent-per-namespace-IPv4-IPv6';
    report.limitations=report.limitations.filter(s=>s!=='not-systemd-installer-or-boot-acceptance').concat('fixture-network-provisioning-not-production-installer','single-boot-not-reboot-acceptance');
    if(nativeRoutes){
      report.dhcp='real-busybox-client-server';
      for(const [key,file] of Object.entries({routeCoordinator:'scripts/lib/native-route-service.mjs',routeJournal:'scripts/lib/vpn-host-routes.mjs',routeService:'scripts/clean-vpn-native-routes.mjs',routeDriver:'scripts/lib/native-route-vm.sh',dhcpHook:'scripts/lib/native-route-dhcp-vm.sh',routeUnit:'scripts/lib/native-route-unit.mjs'}))report[key+'Sha256']=hash(fs.readFileSync(file));
    }
    if(nativeNetwork){
      report.realTunPeers=1;report.guard='dedicated-native-profile-client-and-exit';
      report.limitations=report.limitations.filter(s=>s!=='fixture-network-provisioning-not-production-installer').concat('external-fixture-link-address-default-owner','not-live-site-upgrade-or-all-egress-capture');
      for(const [key,file] of Object.entries({sitePlan:'scripts/lib/native-site-plan.mjs',siteInstaller:'scripts/lib/native-install.mjs',siteVmInstaller:'scripts/lib/native-site-vm-install.mjs',siteBootDriver:'scripts/lib/native-site-boot-vm.mjs',routeCoordinator:'scripts/lib/native-route-service.mjs',routeJournal:'scripts/lib/vpn-host-routes.mjs',routeService:'scripts/clean-vpn-native-routes.mjs'}))report[key+'Sha256']=hash(fs.readFileSync(file));
      for(const [key,file] of Object.entries({networkPlan:'scripts/lib/native-network-profile.mjs',networkApply:'scripts/lib/native-network-apply.mjs',networkCli:'scripts/clean-vpn-native-network.mjs',networkDriver:'scripts/lib/native-network-vm.sh',networkImage:'scripts/lib/native-network-vm-image.mjs',networkUnit:'scripts/lib/native-network-unit.mjs'}))report[key+'Sha256']=hash(fs.readFileSync(file));
    }
  }
  const paths=['.'];const walk=p=>{for(const name of fs.readdirSync(join(guest,p))){const q=p?p+'/'+name:name;paths.push(q);if(fs.lstatSync(join(guest,q)).isDirectory())walk(q);}};walk('');
  const initrd=join(root,'initrd.gz');fs.writeFileSync(initrd,gzipSync(execFileSync('cpio',['-o','-H','newc','--owner=0:0','--quiet'],{cwd:guest,input:paths.join('\n')+'\n',maxBuffer:320*1024*1024}),{level:1}));
  const env={...process.env,LD_LIBRARY_PATH:`${tools}/usr/lib/x86_64-linux-gnu:${tools}/lib/x86_64-linux-gnu`,QEMU_MODULE_DIR:`${tools}/usr/lib/x86_64-linux-gnu/qemu`};delete env.LD_PRELOAD;delete env.LD_AUDIT;
  const disk=join(root,'native-state.ext4');
  if(persistentBoot){
    const fd=fs.openSync(disk,'wx',0o600);try{fs.ftruncateSync(fd,128*1024*1024);}finally{fs.closeSync(fd);}
    execFileSync('/usr/sbin/mkfs.ext4',['-q','-F',disk],{stdio:'pipe'});
    report.boots=[];report.installerSha256=hash(fs.readFileSync('scripts/lib/native-install.mjs'));
    report.bootDriverSha256=hash(fs.readFileSync(nativeSiteBoot?'scripts/lib/native-site-boot-vm.mjs':'scripts/lib/native-boot-vm.mjs'));
    report.limitations=report.limitations.filter(s=>s!=='single-boot-not-reboot-acceptance');
    report.limitations.push('persistent-artifacts-restored-into-initramfs','static-managed-links-not-DHCP','no-independent-early-boot-packet-capture');
  }
  let output='';
  for(let boot=0;boot<(nativeBoot?3:nativeSiteBoot?2:1);boot++){
  console.error(`Native lab boot ${boot}`);
  const child=spawn(join(tools,'usr/bin/qemu-system-x86_64'),['-nodefaults','-no-user-config','-nic','none','-display','none','-monitor','none','-no-reboot','-serial','stdio','-accel','tcg','-cpu','max','-m','1536','-smp','1','-bios',`${tools}/usr/share/seabios/bios-256k.bin`,'-L',`${tools}/usr/share/qemu`,'-kernel',join(base,'guest-kernel'),'-initrd',initrd,'-append',`console=ttyS0 loglevel=4 panic=-1 reboot=t random.trust_cpu=on meshpn.native-lab=1${systemdNative?' meshpn.native-systemd=1':''}${nativeBoot?' meshpn.native-boot=1':''}${nativeRoutes?' meshpn.native-routes=1':''}${nativeNetwork?' meshpn.native-network=1':''}${nativeSiteBoot?' meshpn.native-site-boot=1':''}`,...(persistentBoot?['-drive',`file=${disk},format=raw,if=virtio,cache=writeback`]:[])],{env,stdio:['ignore','pipe','pipe']});
  output='';const timer=setTimeout(()=>child.kill('SIGKILL'),1200000);const stop=()=>child.kill('SIGKILL');process.on('SIGINT',stop);process.on('SIGTERM',stop);
  const serial=fs.openSync(join(root,persistentBoot?`boot-${boot}.log`:'serial.log'),'wx',0o600);
  for(const stream of [child.stdout,child.stderr])stream.on('data',b=>{fs.writeSync(serial,b);output+=b;if(output.length>1024*1024)stop();});
  try {report.code=await new Promise((r,j)=>{child.once('error',j);child.once('close',r);});}
  finally{clearTimeout(timer);process.off('SIGINT',stop);process.off('SIGTERM',stop);fs.closeSync(serial);}
  if(nativeSiteBoot){
    const event=JSON.parse(output.match(/NATIVE_SITE_BOOT (\{[^\r\n]+\})/)?.[1]??'null');
    assert.ok(event&&event.phase===boot);assert.equal(report.code,0);
    const required=boot===0?nativeNetworkChecks.map(s=>'NATIVE_NETWORK_'+s+'_PASS'):['REBOOT_AUTOSTART_DATA','REBOOT_NATIVE_DNS','REBOOT_INVENTORY_AND_ORDER','REBOOT_TARGET_STOP_BLOCKED'].map(s=>'NATIVE_NETWORK_'+s+'_PASS');
    const checks=Object.fromEntries(required.map(key=>[key,output.includes(key)]));
    report.boots.push({...event,checks});
    assert.ok(Object.values(checks).every(Boolean),output.slice(-12000));
    assert.ok(output.includes(boot===0?'reboot: Restarting system':'reboot: Power down'),output.slice(-12000));
    console.error('Native site boot '+boot+' passed');
  }
  if(nativeBoot){
    const events=[...output.matchAll(/NATIVE_BOOT_EVENT (\{[^\r\n]+\})/g)].map(m=>JSON.parse(m[1]));
    const evidence={boot,code:report.code,events,restarted:output.includes('reboot: Restarting system'),poweredDown:output.includes('reboot: Power down')};report.boots.push(evidence);
    assert.equal(report.code,0);assert.ok(!events.some(e=>e.event==='failed'),output.slice(-10000));
    assert.ok(events.some(e=>e.phase===boot&&e.event===(boot<2?'reboot-ready':'passed')),output.slice(-10000));
    assert.ok(output.includes(boot<2?'reboot: Restarting system':'reboot: Power down'),output.slice(-10000));
    console.error(`Native boot ${boot} passed (${events.filter(e=>e.event==='check').length} checks)`);
  }
  }
  if(nativeSiteBoot){
    assert.equal(new Set(report.boots.map(b=>b.bootId)).size,2);
    report.status='passed';report.benchmarks=[];report.siteBoot=true;
  }else if(nativeBoot){
    assertNativeBootEvidence(report);
    report.status='passed';report.benchmarks=[];
  }else{
  assert.equal(report.code,0);assert.ok(nativeNetwork?output.includes('NATIVE_NETWORK_LAB_OK')&&!output.includes('NATIVE_NETWORK_LAB_FAILED'):nativeRoutes?output.includes('NATIVE_ROUTES_LAB_OK')&&!output.includes('NATIVE_ROUTES_LAB_FAILED'):systemdNative?
    output.includes('NATIVE_SYSTEMD_LAB_OK')&&!output.includes('NATIVE_SYSTEMD_LAB_FAILED'):
    output.includes('NATIVE_TUN_VM_PASS')&&output.includes('NATIVE_LAB_OK')&&!output.includes('NATIVE_LAB_FAILED'),output.slice(-10000));
  const checks=['NATIVE_DIRECT_POSITIVE_CONTROL_PASS','NATIVE_USB_DNS_ADMIN_PASS','NATIVE_DNS_UPSTREAM_FALLBACK_PASS',
    'NATIVE_USB_PRIVATE_IPV6_AND_DNS_UPLINK_BLOCK_PASS','NATIVE_TUN_RECONNECT_PASS','NATIVE_TUN_STOP_BLOCKS_PASS',
    'NATIVE_PRODUCTION_GUARD_RETAINED_PASS','NATIVE_CLIENT_OLD_EXIT_PACKETS_PASS','OLD_CLIENT_NATIVE_EXIT_PACKETS_PASS',
    'NATIVE_CLIENT_CRASH_GUARD_ADMIN_PASS','NATIVE_PROCESS_CLEANUP_PASS'];
  const required=nativeNetwork?nativeNetworkChecks.map(s=>`NATIVE_NETWORK_${s}_PASS`):nativeRoutes?nativeRouteChecks.map(s=>`NATIVE_ROUTES_${s}_PASS`):systemdNative?nativeSystemdChecks.map(s=>`NATIVE_SYSTEMD_${s}_PASS`):nativeOnly?checks.filter(n=>!['NATIVE_CLIENT_OLD_EXIT_PACKETS_PASS','OLD_CLIENT_NATIVE_EXIT_PACKETS_PASS'].includes(n)).concat('NATIVE_EXIT_RESTART_PASS'):checks;
  report.checks=Object.fromEntries(required.map(name=>[name,output.includes(name)]));assert.ok(Object.values(report.checks).every(Boolean));
  report.benchmarks=[...output.matchAll(/^NATIVE_BENCH (\{[^\r\n]+\})/gm)].map(m=>JSON.parse(m[1]));
  assert.equal(report.benchmarks.length,nativeOnly?0:6);
  assert.deepEqual(report.benchmarks.map(b=>b.label),nativeOnly?[]:['native-1','native-2','native-3','legacy-1','legacy-2','legacy-3']);
  assert.ok(report.benchmarks.every(b=>b.latencyMedianMs>0&&b.latencyP95Ms>0));
  report.status='passed';console.log(output.slice(-8000));
  }
} catch(e){report.error=e.message;process.exitCode=1;console.error(e.message);}
finally{
  fs.writeFileSync(join(root,'report.json'),JSON.stringify(report,null,2));console.error(JSON.stringify(report));
  // Only this invocation's disposable expanded image; initrd/report/log remain.
  fs.rmSync(guest,{recursive:true,force:true});
}

#!/usr/bin/env node
// Two disposable Linux kernels, connected ONLY by a private QEMU Unix stream.
// No TAP, SLIRP, host NIC, external network, filesystem share, or host clock set.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import {gzipSync} from 'node:zlib';
import {createHash,randomBytes} from 'node:crypto';
import {nativeServiceUnit} from './lib/native-service-unit.mjs';
import {nativeClockRecoveryUnit} from './lib/native-clock-unit.mjs';
assert.equal(process.platform,'linux');assert.equal(process.arch,'x64');assert.equal(process.argv.length,3);
const output=path.resolve(process.argv[2]);assert.ok(!fs.existsSync(output));
const root=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-clock-vm-'));
const build=path.resolve(process.env.CVPN_BUILD??'native/clean_vpn/build');
const run=(c,a,o={})=>execFileSync(c,a,{encoding:'utf8',stdio:['pipe','pipe','pipe'],...o});
const hash=b=>createHash('sha256').update(b).digest('hex');
const release=fs.readFileSync('/opt/meshpn-kernel-release','utf8').trim();assert.match(release,/^[a-zA-Z0-9._-]+$/);
const children=[];const cancel=()=>{for(const c of children)if(c.exitCode===null)c.kill('SIGKILL');};
process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
const sourceHashes=Object.fromEntries(['scripts/clean-vpn-native-clock-vm.mjs','scripts/lib/native-service-unit.mjs','scripts/lib/native-clock-unit.mjs'].map(p=>[p,hash(fs.readFileSync(p))]));
try{
  const pki=root+'/pki';fs.mkdirSync(pki);fs.writeFileSync(pki+'/index','');fs.writeFileSync(pki+'/serial','01\n');fs.mkdirSync(pki+'/new');
  fs.writeFileSync(pki+'/ca.cnf',`[ca]\ndefault_ca=local\n[local]\ndatabase=${pki}/index\nserial=${pki}/serial\nnew_certs_dir=${pki}/new\ndefault_md=sha256\nunique_subject=no\npolicy=policy\n[policy]\ncommonName=supplied\n[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:clock.test\n[root]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n`);
  const stamp=ms=>new Date(ms).toISOString().replace(/[-:TZ]/g,'').slice(0,14)+'Z';
  const now=Date.now(),start=stamp(now-4*86400000),end=stamp(now+4*86400000);
  for(const name of ['ca','server','expired','other'])run('openssl',['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+ (name==='ca'?'Clock fixture CA':'clock.test'),'-keyout',`${pki}/${name}.key`,'-out',`${pki}/${name}.csr`]);
  run('openssl',['ca','-selfsign','-batch','-config',pki+'/ca.cnf','-extensions','root','-keyfile',pki+'/ca.key','-in',pki+'/ca.csr','-out',pki+'/ca.pem','-startdate',start,'-enddate',end]);
  for(const name of ['server','expired'])run('openssl',['ca','-batch','-config',pki+'/ca.cnf','-extensions','server','-cert',pki+'/ca.pem','-keyfile',pki+'/ca.key','-in',`${pki}/${name}.csr`,'-out',`${pki}/${name}.pem`,'-startdate',start,'-enddate',name==='expired'?stamp(now-86400000):end]);
  run('openssl',['req','-x509','-key',pki+'/other.key','-in',pki+'/other.csr','-out',pki+'/other.pem','-days','5']);
  for(const name of ['host','identity','wrong'])run('ssh-keygen',['-q','-t','ed25519','-N','','-f',pki+'/'+name]);
  fs.writeFileSync(pki+'/psk',randomBytes(32));fs.writeFileSync(pki+'/wrong-psk',randomBytes(32));
  const disk=root+'/client.ext4';const fd=fs.openSync(disk,'wx',0o600);fs.ftruncateSync(fd,64*1024*1024);fs.closeSync(fd);run('mkfs.ext4',['-F','-q',disk]);
  // Only the exit guest sets its NTP synchronized flag for this offline test.
  // QEMU's normal RTC supplies reference time; this is not an NTP accuracy test.
  fs.writeFileSync(root+'/sync.c','#include <sys/timex.h>\nint main(){struct timex t={0};if(adjtimex(&t)<0)return 1;t.modes=ADJ_STATUS|ADJ_MAXERROR|ADJ_ESTERROR;t.maxerror=1000;t.esterror=1000;t.status&=~STA_UNSYNC;return adjtimex(&t)<0;}\n');
  run('cc',[root+'/sync.c','-o',root+'/sync']);
  const modnames=['tun','virtio_pci','virtio_net','virtio_blk','ext4','nf_tables','nft_compat','xt_conntrack','xt_tcpudp','iptable_filter','ip6table_filter'];
  const modules=[...new Set(modnames.flatMap(name=>run('modprobe',['--set-version',release,'--show-depends',name]).trim().split('\n').filter(x=>!x.startsWith('builtin ')).map(x=>{assert.match(x,/^insmod \/lib\/modules\/[a-zA-Z0-9_./-]+\.ko\s*$/);return x.trim().split(/\s+/)[1];})))];
  const pythonBase=run('/usr/bin/python3',['-c','import sys;print("/usr/lib/python%d.%d"%sys.version_info[:2])']).trim();
  const cases=['main','expired','wrongpin','skew','wrongkey','wrongname','untrusted','timeout'];
  function image(role,phase){
    const guest=root+'/'+role+'-'+phase;fs.mkdirSync(guest);
    const put=(p,b,mode=0o644)=>{const dest=guest+p;fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,b,{mode});};
    const copied=new Set();
    const binary=(src,dest=src)=>{if(copied.has(dest))return;copied.add(dest);put(dest,fs.readFileSync(src),0o755);
      for(const lib of run('ldd',[src]).match(/\/[^\s()]+/g)??[])if(!copied.has(lib)){copied.add(lib);put(lib,fs.readFileSync(lib),0o755);}};
    const source=(src,dest)=>{const b=fs.readFileSync(src);sourceHashes[src]=hash(b);put(dest,b);};
    put('/bin/busybox',fs.readFileSync('/bin/busybox'),0o755);fs.symlinkSync('busybox',guest+'/bin/sh');
    for(const src of ['/usr/local/bin/node','/usr/bin/openssl','/usr/sbin/ip','/usr/bin/date','/usr/bin/timeout','/usr/bin/python3','/usr/bin/ssh','/usr/bin/ssh-keygen','/usr/sbin/sshd','/usr/lib/systemd/systemd','/usr/lib/systemd/systemd-executor','/usr/bin/systemctl','/usr/bin/timedatectl','/usr/lib/systemd/systemd-timedated','/usr/bin/dbus-daemon','/usr/sbin/iptables-nft','/usr/sbin/ip6tables-nft'])binary(src);
    binary(build+'/clean-vpn-engine','/opt/cvpn/engine');sourceHashes.engine=hash(fs.readFileSync(build+'/clean-vpn-engine'));
    binary(root+'/sync','/opt/clock-lab-sync');
    fs.mkdirSync(guest+path.dirname(pythonBase),{recursive:true});fs.cpSync(pythonBase,guest+pythonBase,{recursive:true,dereference:true,filter:p=>!p.includes('__pycache__')});
    for(const f of fs.readdirSync(pythonBase+'/lib-dynload'))if(f.endsWith('.so'))binary(pythonBase+'/lib-dynload/'+f);
    for(const f of fs.readdirSync('/usr/lib/x86_64-linux-gnu/xtables'))if(f.endsWith('.so'))binary('/usr/lib/x86_64-linux-gnu/xtables/'+f);
    for(const f of modules)put(f,fs.readFileSync(f));
    source('scripts/clean-vpn-native-clock.py','/opt/cvpn/clock.py');source('scripts/lib/native-clock-vm-worker.mjs','/opt/cvpn/worker.mjs');
    put('/etc/passwd','root:x:0:0:root:/root:/bin/sh\nsshd:x:101:101:sshd:/run/sshd:/bin/false\ncvpn-clock:x:61001:61001:clock:/nonexistent:/bin/sh\n');
    put('/etc/group','root:x:0:\nsshd:x:101:\ncvpn-clock:x:61001:\n');
    put('/etc/shadow','root:*:19000:0:99999:7:::\nsshd:!:19000:0:99999:7:::\ncvpn-clock:*:19000:0:99999:7:::\n',0o600);
    put('/etc/nsswitch.conf','passwd: files\ngroup: files\nshadow: files\nhosts: files\n');put('/etc/hosts','127.0.0.1 localhost\n');
    put('/etc/machine-id',role==='client'?'1bb980253a274c03ac43bd6eb7cc22b1\n':'2bb980253a274c03ac43bd6eb7cc22b1\n');put('/etc/os-release','ID=ubuntu\nPRETTY_NAME="isolated clock VM"\n');
    const unit=(name,body)=>put('/etc/systemd/system/'+name,body.replace('[Unit]\n','[Unit]\nDefaultDependencies=no\n').replace('[Service]\n','[Service]\nEnvironment=PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin\n'));
    unit('cvpn-network.service',`[Unit]\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /opt/network.sh\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n`);
    put('/opt/network.sh',`#!/bin/sh\nset -eu\n/usr/sbin/ip link set lo up\n/usr/sbin/ip addr add 192.0.2.${role==='client'?'3':'2'}/24 dev eth0\n/usr/sbin/ip link set eth0 up\n/usr/sbin/ip tuntap add cvpn0 mode tun\n/usr/sbin/ip addr add 10.99.0.${role==='client'?'2':'1'}/24 dev cvpn0\n/usr/sbin/ip link set cvpn0 mtu 1400 up\n${role==='exit'?'/usr/sbin/ip tuntap add cvexp0 mode tun\n/usr/sbin/ip addr add 10.100.0.1/24 dev cvexp0\n/usr/sbin/ip link set cvexp0 up':'mkdir -p /state\n'+cases.map(c=>`mkdir -p /state/clock-${c}\nchmod 700 /state/clock-${c}`).join('\n')}\n`,0o755);
    unit('cvpn-guard.service','[Unit]\nRequires=cvpn-network.service\nAfter=cvpn-network.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh /opt/guard.sh\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n');
    put('/opt/guard.sh',role==='exit'?'#!/bin/sh\nexit 0\n':`#!/bin/sh\nset -eu\niptables-nft -P OUTPUT DROP\niptables-nft -P FORWARD DROP\nip6tables-nft -P OUTPUT DROP\nip6tables-nft -P FORWARD DROP\niptables-nft -A OUTPUT -o lo -j ACCEPT\niptables-nft -A OUTPUT -o cvpn0 -j ACCEPT\niptables-nft -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n${[22,443,444].map(p=>`iptables-nft -A OUTPUT -o eth0 -d 192.0.2.2 -p tcp --dport ${p} -j ACCEPT`).join('\n')}\n`,0o755);
    const creds=role==='client'?['identity','ca.pem','other.pem','psk','wrong-psk']:['host','server.pem','server.key','expired.pem','expired.key','psk'];
    for(const f of creds)put('/etc/cvpn/'+f,fs.readFileSync(pki+'/'+f),0o600);
    if(role==='client'){
      source('fixtures/native-tls-profiles/chromium-156-bounded-cold.json','/etc/cvpn/profile.json');
      for(const c of cases){
        const config={version:1,role:'client',address:'192.0.2.2',port:c==='timeout'?445:c==='expired'?444:443,tun:'cvpn0',server_name:c==='wrongname'?'not-clock.test':'clock.test',ca:'/etc/cvpn/'+(c==='untrusted'?'other.pem':'ca.pem'),secret_path:'/etc/cvpn/'+(c==='wrongkey'?'wrong-psk':'psk'),tls_profile_path:'/etc/cvpn/profile.json'};
        put(`/etc/cvpn/${c}.json`,JSON.stringify(config),0o600);
        put(`/etc/cvpn/pin-${c}`,'clean-vpn-clock '+fs.readFileSync(pki+'/'+(c==='wrongpin'?'wrong':'host')+'.pub','utf8').split(' ').slice(0,2).join(' ')+'\n',0o600);
        put(`/etc/cvpn/clock-${c}.json`,JSON.stringify({version:1,host:'192.0.2.2',port:22,user:'cvpn-clock',identity:'/etc/cvpn/identity',known_hosts:`/etc/cvpn/pin-${c}`,state_dir:`/state/clock-${c}`,consumer_unit:`cvpn-${c}.service`}),0o600);
        unit(`cvpn-${c}.service`,nativeServiceUnit({binary:'/opt/cvpn/engine',config:`/etc/cvpn/${c}.json`,networkUnit:'cvpn-network.service',guardUnit:'cvpn-guard.service',role:'client',clockRecoveryUnit:`clock-${c}.service`}).replace('StandardOutput=journal',`StandardOutput=append:/run/engine-${c}.log`).replace('StandardError=journal',`StandardError=append:/run/engine-${c}.log`));
        unit(`clock-${c}.service`,nativeClockRecoveryUnit({consumerUnit:`cvpn-${c}.service`,script:'/opt/cvpn/clock.py',config:`/etc/cvpn/clock-${c}.json`,stateDirectory:`/state/clock-${c}`}).replace('StandardOutput=journal',`StandardOutput=append:/run/recovery-${c}.log`).replace('StandardError=journal',`StandardError=append:/run/recovery-${c}.log`));
      }
    }else{
      for(const c of ['exit','expired']){
        put('/etc/cvpn/'+c+'.json',JSON.stringify({version:1,role:'exit',address:'192.0.2.2',port:c==='exit'?443:444,tun:c==='exit'?'cvpn0':'cvexp0',secret_path:'/etc/cvpn/psk',cert:'/etc/cvpn/'+(c==='exit'?'server':'expired')+'.pem',key:'/etc/cvpn/'+(c==='exit'?'server':'expired')+'.key'}),0o600);
        unit(`cvpn-${c}.service`,nativeServiceUnit({binary:'/opt/cvpn/engine',config:`/etc/cvpn/${c}.json`,networkUnit:'cvpn-network.service',guardUnit:'cvpn-guard.service'}));
      }
      put('/etc/cvpn/authorized','restrict,command="/usr/bin/timeout 5s /usr/bin/python3 -I /opt/cvpn/clock.py serve" '+fs.readFileSync(pki+'/identity.pub'),0o644);
      put('/etc/cvpn/sshd.conf','Port 22\nListenAddress 192.0.2.2\nHostKey /etc/cvpn/host\nPidFile /run/sshd.pid\nAuthorizedKeysFile /etc/cvpn/authorized\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nAllowUsers cvpn-clock\nUseDNS no\nLogLevel VERBOSE\n');
      unit('clock-sshd.service','[Unit]\nRequires=cvpn-network.service clock-reference.service\nAfter=cvpn-network.service clock-reference.service\n[Service]\nRuntimeDirectory=sshd\nRuntimeDirectoryMode=0755\nExecStart=/usr/sbin/sshd -D -e -f /etc/cvpn/sshd.conf\nExecStopPost=/bin/cat /run/sshd.log\nStandardError=append:/run/sshd.log\nStandardOutput=tty\nTTYPath=/dev/console\n');
      put('/etc/dbus-1/system.conf','<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd"><busconfig><type>system</type><standard_system_servicedirs/><listen>unix:path=/run/dbus/system_bus_socket</listen><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>');
      unit('dbus.socket','[Unit]\n[Socket]\nListenStream=/run/dbus/system_bus_socket\n');
      unit('dbus.service','[Unit]\nRequires=dbus.socket\nAfter=dbus.socket\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/bin/dbus-daemon --nofork --nopidfile --config-file=/etc/dbus-1/system.conf --address=systemd: --systemd-activation\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n');
      unit('systemd-timedated.service','[Unit]\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=dbus\nBusName=org.freedesktop.timedate1\nExecStart=/usr/lib/systemd/systemd-timedated\n');
      put('/usr/share/dbus-1/system-services/org.freedesktop.timedate1.service',fs.readFileSync('/usr/share/dbus-1/system-services/org.freedesktop.timedate1.service'));
      fs.symlinkSync('systemd-timedated.service',guest+'/etc/systemd/system/dbus-org.freedesktop.timedate1.service');
      unit('clock-reference.service','[Unit]\nRequires=dbus.service\nAfter=dbus.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/opt/clock-lab-sync\n');
    }
    unit('default.target','[Unit]\nWants=clock-driver.service '+(role==='client'?'cvpn-main.service':'cvpn-exit.service cvpn-expired.service clock-sshd.service')+'\n');
    unit('clock-driver.service','[Unit]\nRequires=cvpn-network.service\nAfter=cvpn-network.service\n[Service]\nType=simple\nExecStart=/bin/sh /driver.sh\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=15min\n');
    put('/driver.sh',`#!/bin/sh\nif /usr/local/bin/node /opt/cvpn/worker.mjs ${role}; then echo CLOCK_VM_OK; else echo CLOCK_VM_FAILED; fi\nsync\npoweroff -f\n`,0o755);
    put('/init',`#!/bin/sh\nexport PATH=/usr/local/bin:/usr/sbin:/usr/bin:/bin\nexport LANG=C LC_ALL=C\n/bin/busybox --install -s /bin\nmkdir -p /proc /sys /dev /run /tmp\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nchmod 1777 /tmp\nmkdir -p /run/sshd /run/dbus /root\n${modules.map(m=>'insmod '+m+' || poweroff -f').join('\n')}\n${role==='client'?'mkdir -p /state\nmount -t ext4 /dev/vda /state || poweroff -f':''}\nmkdir -p /sys/fs/cgroup\nmount -t cgroup2 none /sys/fs/cgroup\nexec /usr/lib/systemd/systemd --system --log-target=console --log-level=warning --show-status=no\n`,0o755);
    const paths=['.'];const walk=p=>{for(const e of fs.readdirSync(guest+'/'+p,{withFileTypes:true})){const q=path.join(p,e.name);paths.push(q);if(e.isDirectory())walk(q);}};walk('');
    const initrd=root+'/'+role+'-'+phase+'.gz';fs.writeFileSync(initrd,gzipSync(run('cpio',['-o','-H','newc','--owner=0:0','--quiet'],{cwd:guest,input:paths.join('\n')+'\n',encoding:null,maxBuffer:512*1024*1024}),{level:1}));return initrd;
  }
  let sshCount=0;
  const launch=(role,phase,initrd)=>{
    const serialPath=output+'.'+role+'-'+phase+'.serial.log',log=fs.openSync(serialPath,'wx',0o600);
    const args=['-nodefaults','-no-user-config','-display','none','-monitor','none','-serial','stdio','-no-reboot','-accel','tcg','-cpu','qemu64','-smp','2','-m',role==='exit'?'768':'1536',
      '-bios','/opt/meshpn-vm-tools/root/usr/share/seabios/bios-256k.bin','-L','/opt/meshpn-vm-tools/root/usr/share/qemu','-kernel','/boot/vmlinuz-'+release,'-initrd',initrd,
      '-append','console=ttyS0 loglevel=4 panic=-1 random.trust_cpu=on net.ifnames=0 meshpn.clock-vm=1 meshpn.clock-phase='+phase,
      '-netdev',`stream,id=pair,server=${role==='exit'?'on':'off'},addr.type=unix,addr.path=${root}/pair.sock`,'-device','virtio-net-pci,netdev=pair,mac=52:54:00:12:34:'+(role==='exit'?'02':'03'),
      ...(role==='client'?['-drive',`file=${disk},format=raw,if=virtio,cache=writeback`,'-rtc','base='+(phase===1?'utc':'2017-01-01T00:00:00')]:[])];
    const p=spawn('/opt/meshpn-native-qemu/qemu-system-x86_64',args,{stdio:['ignore','pipe','pipe']});children.push(p);
    const result={p,text:'',serialPath,done:null};let pending='';
    for(const s of [p.stdout,p.stderr])s.on('data',b=>{fs.writeSync(log,b);result.text+=b;if(result.text.length>4*1024*1024)p.kill('SIGKILL');pending+=b;let n;while((n=pending.indexOf('\n'))>=0){const line=pending.slice(0,n).trim();pending=pending.slice(n+1);if(line.startsWith('CLOCK_')){console.error(role+': '+line);if(role==='exit'&&/^CLOCK_EXIT_SSH_COUNT=\d+$/.test(line))sshCount=Number(line.split('=')[1]);}}});
    result.done=once(p,'close').then(([code])=>{fs.closeSync(log);return code;});return result;
  };
  console.error('CLOCK_LAB=building-images');
  const serverImage=image('exit',0),clientImage=image('client',0),clientImages=[clientImage,clientImage,clientImage];
  const server=launch('exit',0,serverImage);
  const awaitCondition=async(fn,ms=180000)=>{const end=performance.now()+ms;while(performance.now()<end){if(fn())return;await delay(200);}throw Error('clock_vm_deadline');};
  await awaitCondition(()=>{if(server.p.exitCode!==null||server.p.signalCode!==null)throw Error(server.text.slice(-6000));if(/cvpn-network.service: Failed|clock-reference.service: Failed|CLOCK_VM_FAILED/.test(server.text))throw Error(server.text.slice(-6000));return server.text.includes('CLOCK_EXIT_READY');});
  const reports=[];
  for(let phase=0;phase<3;phase++){
    const before=sshCount,client=launch('client',phase,clientImages[phase]);
    const timer=setTimeout(()=>client.p.kill('SIGKILL'),10*60*1000);
    let code;try{code=await client.done;}finally{clearTimeout(timer);}
    assert.equal(code,0,client.text.slice(-7000));assert.ok(client.text.includes('CLOCK_VM_OK')&&!client.text.includes('CLOCK_VM_FAILED'),client.text.slice(-14000));
    const rows=[...client.text.matchAll(/CLOCK_VM_REPORT=(\{[^\r\n]+\})/g)];assert.equal(rows.length,1);const r=JSON.parse(rows[0][1]);assert.equal(r.status,'passed');
    const expected=phase===0?3:phase===1?0:1;
    await delay(500);assert.equal(sshCount-before,expected,'SSH forced-command count in independent exit VM');
    r.sshRequests=sshCount-before;r.serialSha256=hash(fs.readFileSync(client.serialPath));reports.push(r);
  }
  assert.equal(new Set(reports.map(r=>r.bootId)).size,3);assert.equal(sshCount,4);
  server.p.kill('SIGTERM');await server.done;
  const report={schema:1,kind:'native-conditional-clock-vm',status:'passed',boots:reports,sshRequests:4,sourceHashes,
    vm:{kernel:release,accelerator:'TCG',isolatedKernels:2,clientBoots:3,connection:'private-unix-stream-only',hostClockChanged:false,externalNetwork:false},
    referenceClock:'exit QEMU default RTC; synchronization flag explicitly set in exit guest only; not an NTP accuracy test',
    serverSerialSha256:hash(fs.readFileSync(server.serialPath))};
  fs.writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log('CLOCK_VM_PASSED='+output);
}finally{cancel();process.off('SIGINT',cancel);process.off('SIGTERM',cancel);fs.rmSync(root,{recursive:true,force:true});}

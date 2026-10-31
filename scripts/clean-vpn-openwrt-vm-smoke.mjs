#!/usr/bin/env node
// Official image, native ARM QEMU cache, disposable snapshot disk, no NIC/share.
import fs from 'node:fs';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {createHash,randomBytes} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {execFileSync,spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import assert from 'node:assert/strict';
const {values:v}=parseArgs({options:Object.fromEntries(['connection','qemu-image','image-gz','kernel','directory','report'].map(k=>[k,{type:'string'}]))});
const expected='f8538784d0288b4133a99ac2a68443e4922ffde6343e80df56a5882364b9d499';
const source='https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/openwrt-25.12.6-x86-64-generic-ext4-combined.img.gz';
const sha=b=>createHash('sha256').update(b).digest('hex');
assert.match(v.connection??'',/^[a-zA-Z0-9_.-]+$/);assert.match(v['qemu-image']??'',/^[a-zA-Z0-9][a-zA-Z0-9_./:@-]*$/);
for(const k of['directory','report'])assert.ok(v[k]&&path.isAbsolute(v[k])&&!fs.existsSync(v[k]),'new_absolute_output_required');
assert.ok(v['image-gz']&&path.isAbsolute(v['image-gz']));
const fd=fs.openSync(v['image-gz'],fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);let compressed;
try{const st=fs.fstatSync(fd);assert.ok(st.isFile()&&st.size<=20*1024*1024);compressed=fs.readFileSync(fd);}finally{fs.closeSync(fd);}
assert.equal(sha(compressed),expected,'official_download_sha256');
const disk=gunzipSync(compressed,{maxOutputLength:256*1024*1024});
assert.ok(v.kernel&&path.isAbsolute(v.kernel));const kernel=fs.readFileSync(v.kernel);assert.ok(kernel.length<=8*1024*1024);assert.equal(sha(kernel),'8f70595f3a6eec3112e007450a1a600153904deffa52ab368712342583cb387c','official_kernel_sha256');
const cli=['--connection',v.connection],run=a=>execFileSync('podman',[...cli,...a],{encoding:'utf8',timeout:30000,maxBuffer:2*1024*1024});
const image=JSON.parse(run(['image','inspect',v['qemu-image']]))[0];assert.equal(image.Architecture,'arm64');
fs.mkdirSync(v.directory,{mode:0o700});const diskPath=path.join(v.directory,'openwrt.img');fs.writeFileSync(diskPath,disk,{mode:0o644});
const tag='cvpn-openwrt-'+randomBytes(6).toString('hex');
const guest=String.raw`set -eux
cat /sys/devices/system/clocksource/clocksource0/available_clocksource
sleep 15
. /etc/openwrt_release
test "$DISTRIB_RELEASE" = 25.12.6
test "$(uname -m)" = x86_64
test "$(cat /proc/1/comm)" = procd
test "$(ls /sys/class/net)" = lo
ubus call system board >/tmp/cvpn-board.json
command -v uci
command -v fw4
command -v dnsmasq
touch /etc/config/clean_vpn_lab
uci set clean_vpn_lab.main=client
uci set clean_vpn_lab.main.enabled=0
uci commit clean_vpn_lab
test "$(uci get clean_vpn_lab.main.enabled)" = 0
cat >/etc/init.d/clean-vpn-lab <<'SERVICE'
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
start_service() {
 procd_open_instance
 procd_set_param command /bin/sleep 3600
 procd_set_param respawn 3600 1 3
 procd_close_instance
}
SERVICE
chmod 755 /etc/init.d/clean-vpn-lab
/etc/init.d/clean-vpn-lab start
sleep 2
pid=$(ubus -t 5 call service list '{"name":"clean-vpn-lab"}' | jsonfilter -e '@["clean-vpn-lab"].instances.instance1.pid')
test -n "$pid"
test "$(cat /proc/$pid/comm)" = sleep
kill -KILL "$pid"
sleep 4
next=$(ubus -t 5 call service list '{"name":"clean-vpn-lab"}' | jsonfilter -e '@["clean-vpn-lab"].instances.instance1.pid')
test -n "$next"
test "$next" != "$pid"
test "$(cat /proc/$next/comm)" = sleep
/etc/init.d/clean-vpn-lab stop
sleep 1
test -z "$(ubus -t 5 call service list '{"name":"clean-vpn-lab"}' | jsonfilter -e '@["clean-vpn-lab"].instances.instance1.pid')"
uci delete clean_vpn_lab.main
uci commit clean_vpn_lab
rm -f /etc/init.d/clean-vpn-lab /etc/config/clean_vpn_lab
printf '\nCVPN_OPENWRT_VERSION=%s\nCVPN_OPENWRT_PROCD_UCI=passed\n' "$DISTRIB_RELEASE"
`;
const guestBytes=Buffer.from(guest);
const report={schema:1,kind:'clean-vpn-openwrt-vm-smoke',status:'running',source,downloadSha256:expected,kernelSha256:sha(kernel),diskSha256:sha(disk),qemuImage:{id:image.Id,architecture:image.Architecture},
 scope:'real OpenWrt procd/UCI boot and supervision fixture; no VPN engine, LuCI, routing or packet acceptance',
 hostNetworkChanged:false,physicalHostsTouched:false,guestNic:false,hostShare:false,persistentGuestDisk:false,globalBinfmtChanged:false,releaseSignatureVerified:false,timing:'QEMU TCG functional boot only; not performance evidence'};
let child,log='',promptBuffer='',activated=false,created=false;const startedAt=Date.now();
// UART/console input buffers are small: wait for each fresh shell prompt.
const chunks=[];for(let i=0;i<guestBytes.length;i+=16)chunks.push([...guestBytes.subarray(i,i+16)].map(n=>'\\0'+n.toString(8).padStart(3,'0')).join(''));
const commands=[': >/tmp/cvpn-smoke.sh',...chunks.map(chunk=>"printf '%b' '"+chunk+"' >>/tmp/cvpn-smoke.sh"),'sh /tmp/cvpn-smoke.sh; cvpn_result=$?; printf "\\nCVPN_OPENWRT_RESULT=%s\\n" "$cvpn_result"; poweroff -f'];
try{
 created=true;
 child=spawn('podman',[...cli,'run','-i','--name',tag,'--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=32','--memory=1536m','--cpus=2','--tmpfs=/tmp:mode=1777,size=128m','-v',diskPath+':/openwrt.img:ro','-v',v.kernel+':/openwrt-kernel:ro',image.Id,
  '-nodefaults','-no-user-config','-nic','none','-display','none','-monitor','none','-no-reboot','-serial','stdio','-accel','tcg,thread=single,tb-size=128','-cpu','max','-m','384','-smp','1','-machine','pc,dump-guest-core=off','-bios','/opt/seabios/bios-256k.bin','-L','/opt/qemu-data','-kernel','/openwrt-kernel','-append','root=/dev/vda2 rootfstype=ext4 rootwait rw console=ttyS0,115200','-drive','file=/openwrt.img,if=virtio,format=raw,snapshot=on'],{stdio:['pipe','pipe','pipe']});
 child.stdin.on('error',()=>{});
 const receive=b=>{
  log+=b.toString();if(log.length>2*1024*1024){child.kill('SIGKILL');return;}
  if(!activated&&log.includes('Please press Enter to activate this console')){activated=true;child.stdin.write('\n');}
  promptBuffer=(promptBuffer+b.toString()).slice(-4096);
  if(commands.length&&/root@(?:OpenWrt|\(none\)):[^\r\n]*#/.test(promptBuffer)){promptBuffer='';child.stdin.write(commands.shift()+'\n');}
 };
 child.stdout.on('data',receive);child.stderr.on('data',receive);
 const timer=setTimeout(()=>{report.deadlineExceeded=true;try{run(['rm','-f',tag]);}catch{}child.kill('SIGKILL');},180000);
 let code;try{[code]=await once(child,'close');}finally{clearTimeout(timer);}
 report.exitCode=code;try{const state=JSON.parse(run(['inspect',tag]))[0].State;report.containerState={OOMKilled:state.OOMKilled,ExitCode:state.ExitCode,Error:String(state.Error??'').slice(0,256)};}catch{}
 assert.equal(code,0,'qemu_exit');assert.match(log,/\r?\nCVPN_OPENWRT_VERSION=25\.12\.6\r?\n/);assert.match(log,/\r?\nCVPN_OPENWRT_PROCD_UCI=passed\r?\n/);assert.match(log,/\r?\nCVPN_OPENWRT_RESULT=0\r?\n/);
 report.status='passed';report.checks=['official-image-hash','x86_64-OpenWrt-procd-PID1','guest-loopback-only','real-ubus-system-board','UCI-write-read-commit','procd-owned-fixture-start','SIGKILL-respawn-new-PID','procd-stop-and-cleanup'];
}catch(e){report.status='failed';report.error=e.code??'guest-smoke-failed';report.failure=String(e.message).slice(0,512);process.exitCode=1;}
finally{
 if(created)try{run(['rm','-f',tag]);}catch{}
 fs.writeFileSync(path.join(v.directory,'console.log'),log,{mode:0o600});report.elapsedMs=Date.now()-startedAt;report.consoleSha256=sha(Buffer.from(log));report.logTail=log.slice(-4096);const exists=spawnSync('podman',[...cli,'container','exists',tag],{timeout:30000});report.cleanup=exists.status===1?'owned-container-removed; disk remains pristine; snapshot discarded':'cleanup-verification-failed';if(exists.status!==1){report.status='failed';process.exitCode=1;}
 fs.writeFileSync(v.report,JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});console.log(JSON.stringify({status:report.status,report:v.report}));
}

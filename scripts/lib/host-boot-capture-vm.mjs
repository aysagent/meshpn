/** Only run within the marked NIC-less test VM. */
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import dgram from 'node:dgram';
import net from 'node:net';
import { captureDir, captureName, captureUnit, gateText, gatePath, consumers } from './host-boot-capture.mjs';
assert.ok(fs.readFileSync('/proc/cmdline','utf8').split(/\s+/).includes('meshpn.boot-capture-lab=1'));
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor','utf8').trim(), 'QEMU');
const run = (f, a) => execFileSync(f, a, { encoding:'utf8', timeout:15000 });
const ip = (...a) => run('ip', a);
const ctl = (...a) => run('systemctl', a).trim();
const put = (p, s) => { fs.mkdirSync(p.slice(0,p.lastIndexOf('/')), {recursive:true}); fs.writeFileSync(p,s); };
const phase = process.env.CAPTURE_PHASE;
const check = (n, ok) => { assert.ok(ok,n); console.log('BOOT_CAPTURE_CHECK '+n); };
if (process.argv[2] === 'prepare') {
  assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname), ['lo']);
  ip('link','set','lo','up'); ip('netns','add','peer');
  ip('link','add','wlan0','type','veth','peer','name','peer0','netns','peer');
  ip('-n','peer','addr','add','198.18.0.2/24','dev','peer0'); ip('-n','peer','link','set','peer0','up');
  ip('-n','peer','-6','addr','add','2001:db8:1::2/64','dev','peer0','nodad');
  put(`${captureDir}/config.json`, JSON.stringify({schema:1,exitIp:'154.62.226.216',installedBootId:'previous-boot'}));
  put(`/etc/systemd/system/${captureName}.service`, captureUnit('/usr/bin/node'));
  for (const u of consumers) put(gatePath(u), gateText);
  put('/etc/systemd/network/10-test.network','[Match]\nName=wlan0\n[Network]\nAddress=198.18.0.1/24\nGateway=198.18.0.2\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n');
  put('/etc/udev/rules.d/99-test.rules','SUBSYSTEM=="net", ACTION=="add", TAG+="systemd", ENV{SYSTEMD_ALIAS}="/sys/subsystem/net/devices/$name"\n');
  if (phase === 'guard') run('bash',['/project/scripts/autostart/killswitch.sh','up','--scope=both','--ipv6=block','--server=154.62.226.216','--ssh-port=22','--tun=tun0']);
  if (phase === 'failure') put(`/etc/systemd/system/${captureName}.service.d/99-failure.conf`, '[Service]\nEnvironment=PATH=/no-capture-binaries\n');
  if (phase === 'early-up') ip('link','set','wlan0','up');
} else if (process.argv[2] === 'wifi') {
  // Model an independent supplicant raising the link before networkd configures it.
  const report = JSON.parse(fs.readFileSync(`${captureDir}/report.json`));
  assert.equal(report.status,'capturing'); assert.ok(report.readyMonotonic);
  put('/run/wifi-started','yes'); ip('link','set','wlan0','up');
} else {
  try {
    if (['failure','early-up'].includes(phase)) {
      await delay(3000);
      check('capture failure blocks networkd',ctl('show','systemd-networkd.service','--property=ActiveState','--value') !== 'active');
      check('capture failure blocks supplicant',!fs.existsSync('/run/wifi-started'));
      check('capture failure blocks networkd socket',ctl('show','systemd-networkd.socket','--property=ActiveState','--value') !== 'active');
      if (phase === 'failure') check('wlan0 remains DOWN',!(Number(fs.readFileSync('/sys/class/net/wlan0/flags','utf8'))&1));
    } else {
      const until = Date.now()+30000;
      while (!ip('-4','addr','show','dev','wlan0').includes('198.18.0.1')) { assert.ok(Date.now()<until,'networkd address timeout'); await delay(200); }
      check('independent WiFi activator ran after capture ready',fs.existsSync('/run/wifi-started'));
      check('networkd actually running',ctl('show','systemd-networkd.service','--property=ActiveState','--value') === 'active');
      ip('-6','addr','add','2001:db8:1::1/64','dev','wlan0','nodad');
      ip('-6','route','add','default','via','2001:db8:1::2','dev','wlan0');
      if(phase==='mid-failure') {
        const tcpdumpPids=fs.readdirSync('/proc').filter(p=>/^\d+$/.test(p)).filter(p=>{
          try{return fs.readFileSync(`/proc/${p}/comm`,'utf8').trim()==='tcpdump';}catch{return false;}
        });
        assert.equal(tcpdumpPids.length,1); process.kill(Number(tcpdumpPids[0]),'SIGINT');
        await delay(2000);
        const interrupted=JSON.parse(fs.readFileSync(`${captureDir}/report.json`));
        check('interrupted capture reports inconclusive',interrupted.status==='inconclusive');
        check('capture failure after READY keeps networkd running',ctl('show','systemd-networkd.service','--property=ActiveState','--value')==='active');
        check('capture failure after READY retains active dependency',ctl('show',`${captureName}.service`,'--property=SubState','--value')==='exited');
        console.log('BOOT_CAPTURE_PASS'); ctl('poweroff','--no-block'); process.exit(0);
      }
      for(let i=0;i<5;i++) {
        const udp=dgram.createSocket('udp4'); await new Promise(r=>udp.send(Buffer.from('test-not-user-data'),53,'1.1.1.1',r)); udp.close();
        const udp6=dgram.createSocket('udp6'); await new Promise(r=>udp6.send(Buffer.from('test-not-user-data'),443,'2606:4700:4700::1111',r)); udp6.close();
        const tcp=net.connect({host:'154.62.226.216',port:443}); tcp.on('error',()=>{}); setTimeout(()=>tcp.destroy(),300);
        await delay(500);
      }
      let report; const end=Date.now()+100000;
      do { await delay(500); report=JSON.parse(fs.readFileSync(`${captureDir}/report.json`)); assert.ok(Date.now()<end,'capture completion timeout'); }
      while(['starting','capturing'].includes(report.status));
      console.log('BOOT_CAPTURE_REPORT '+JSON.stringify(report));
      check('capture completes with loss statistics',report.droppedPackets===0 && report.captureExit.code===0);
      check('first UP observed after readiness',report.firstUpObservedMonotonic>=report.readyMonotonic);
      check('exit transport positively observed',report.counts['exit-tls']>0);
      if(phase==='guard') { check('guard blocks DNS from uplink capture',!report.counts['direct-dns-or-dot']); check('guard blocks public IPv6',!report.counts['unexpected-egress']); check('guarded window clean',report.status==='no-unexpected-egress-observed'); }
      else { check('unguarded control catches direct DNS',report.counts['direct-dns-or-dot']>0); check('unguarded control catches public IPv6',report.samples.some(p=>p.family===6 && p.category==='unexpected-egress')); check('control never reports clean',report.status==='traffic-review-required'); }
      check('normal completion does not stop networkd',ctl('show','systemd-networkd.service','--property=ActiveState','--value')==='active');
      check('capture remains active after bounded completion',ctl('show',`${captureName}.service`,'--property=SubState','--value')==='exited');
      if (phase==='guard') {
        // Exercise publication/removal on a running network. Rescue authentication is
        // tested separately by usb-rescue-lab; here units are explicit test stubs.
        for(const u of consumers) fs.unlinkSync(gatePath(u));
        ctl('daemon-reload'); ctl('stop',`${captureName}.service`);
        fs.unlinkSync(`/etc/systemd/system/${captureName}.service`);
        fs.unlinkSync('/usr/local/lib/clean-vpn-boot-capture.mjs');
        fs.rmSync(captureDir,{recursive:true}); ctl('daemon-reload');
        put('/usr/local/bin/clean-vpn-killswitch.sh',fs.readFileSync('/project/scripts/autostart/killswitch.sh')); fs.chmodSync('/usr/local/bin/clean-vpn-killswitch.sh',0o755);
        for(const u of ['clean-vpn-killswitch.service','clean-vpn-usb-rescue-address.service']) put('/etc/systemd/system/'+u,'[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n');
        put('/etc/systemd/system/clean-vpn-usb-rescue.socket','[Socket]\nListenStream=/run/rescue-test-only.sock\nAccept=yes\n');
        put('/etc/systemd/system/clean-vpn-usb-rescue@.service','[Service]\nExecStart=/bin/true\nStandardInput=socket\n');
        ctl('daemon-reload'); ctl('start','clean-vpn-killswitch.service','clean-vpn-usb-rescue-address.service','clean-vpn-usb-rescue.socket');
        ip('link','add','usb0','address','02:00:00:00:00:02','type','dummy');
        ip('addr','add','192.168.7.1/24','dev','usb0'); ip('link','set','usb0','up');
        const snapshot=()=>JSON.stringify([ip('-j','addr'),ip('-4','route','show','table','all'),run('iptables',['-S']),run('ip6tables',['-S']),ctl('show','systemd-networkd.service','--property=MainPID','--value')]);
        const before=snapshot();
        const install=['/project/scripts/clean-vpn-boot-capture.mjs','--install','--exit-ip=154.62.226.216'];
        run('node',install); check('installer plan publishes nothing',!fs.existsSync(captureDir));
        run('node',[...install,'--apply']); check('arming does not change live network or guard',snapshot()===before);
        check('arming does not start capture in current boot',ctl('show',`${captureName}.service`,'--property=ActiveState','--value')==='inactive');
        assert.throws(()=>run('node',[...install,'--apply'])); check('duplicate install refused',snapshot()===before);
        const removal=['/project/scripts/clean-vpn-boot-capture.mjs','--remove','--apply'];
        fs.appendFileSync(gatePath(consumers[0]),'# foreign modification\n');
        assert.throws(()=>run('node',removal)); check('modified gate removal refused',fs.existsSync(gatePath(consumers.at(-1)))) ;
        put(gatePath(consumers[0]),gateText); run('node',removal);
        check('capture gates removal preserves live network and guard',snapshot()===before);
        check('all capture gates removed',consumers.every(u=>!fs.existsSync(gatePath(u))));
      }
    }
    console.log('BOOT_CAPTURE_PASS');
  } catch(e) { console.error('BOOT_CAPTURE_FAIL',e.stack); }
  finally { ctl('poweroff','--no-block'); }
}

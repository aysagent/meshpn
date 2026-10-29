// Real kernel/journal regression in an explicitly disposable empty netns.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {nativeHostNetwork} from './lib/native-host-network.mjs';
import {openNativeHostStore,nativeHostScope} from './lib/native-host-store.mjs';
import {openHostRoutes} from './lib/vpn-host-routes.mjs';
import {openTunnelDnsJournal} from './lib/dns-tunnel-journal.mjs';
assert.equal(process.env.CVPN_DISPOSABLE_HOST_NET,'1');assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
assert.notEqual(fs.readlinkSync('/proc/self/ns/net'),fs.readlinkSync('/proc/1/ns/net'));
const root=fileURLToPath(new URL('../',import.meta.url));
const cmd=(f,a)=>execFileSync(f,a,{encoding:'utf8',timeout:20000,maxBuffer:1024*1024}).trim();
const ip=(...a)=>cmd('ip',a);
assert.deepEqual(JSON.parse(ip('-j','link')).map(l=>l.ifname),['lo']);
let checks=0;const check=(name,fn)=>{fn();console.log('HOST_NETWORK_CHECK '+name);checks++;};
let c={version:1,exit_ip:'154.62.226.216',engine_unit:'native-daily.service',network_unit:'native-daily-network.service',guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'};
ip('link','set','lo','up');
for(const [dev,address] of [['usb0','192.168.7.1/24'],['wlan0','192.168.1.8/24']]){
  ip('link','add',dev,'type','dummy');ip('addr','add',address,'dev',dev);ip('link','set',dev,'up');
}
ip('route','add','default','via','192.168.1.1','dev','wlan0');
cmd('sysctl',['-w','net.ipv4.ip_forward=1']);
cmd('iptables',['-t','nat','-A','POSTROUTING','-o','wlan0','-m','comment','--comment','foreign-sentinel','-j','MASQUERADE']);
const guard=args=>cmd('bash',[root+'scripts/autostart/killswitch.sh',...args]);
guard(['up','--scope=both','--ipv6=block','--tun=tun0','--server='+c.exit_ip,'--ssh-port=22','--usb-dns=1','--usb-strict=1']);
const before={routes:ip('-N','-j','-4','route','show','table','main'),rp:cmd('sysctl',['-n','net.ipv4.conf.all.rp_filter']),nat:cmd('iptables',['-t','nat','-S']),mangle:cmd('iptables',['-t','mangle','-S']),filter:cmd('iptables',['-S'])};
let engineAlive=false,active=true,crashAt=null,store,host,dns,owner;
const run=(f,a)=>{
  if(f===c.guard_script)return guard(a);
  if(f==='systemctl'){
    if(a[3]==='MainPID')return engineAlive?'123':'0';
    if(a[3]==='BindsTo')return c.network_unit+' '+c.guard_unit;
    if(a[3]==='ActiveState')return a[1]===c.guard_unit?(active?'active':'inactive'):(engineAlive?'active':'inactive');
    throw Error('unexpected fixture systemctl');
  }
  return cmd(f,a);
};
const open=()=>{
  store=openNativeHostStore();host=openHostRoutes({allowTunLinkDown:true});dns=openTunnelDnsJournal();
  const write=store.write;store.write=s=>{write(s);if(crashAt&&crashAt(s))throw Error('simulated_process_boundary');};
  owner=nativeHostNetwork(c,{run,host,dns,store,scope:nativeHostScope,randomId:()=>crypto.randomUUID().replaceAll('-','').slice(0,24),
    createTun:(name,alias,peer)=>cmd('python3',[root+'scripts/clean-vpn-native-tun.py',name,alias,peer])});
};
const close=()=>{dns?.release();host?.release();store?.close();};
const baseline=()=>{
  assert.ok(!JSON.parse(ip('-j','link')).some(l=>l.ifname==='tun0'));
  assert.equal(ip('-N','-j','-4','route','show','table','main'),before.routes);
  assert.equal(cmd('sysctl',['-n','net.ipv4.conf.all.rp_filter']),before.rp);
  assert.equal(cmd('iptables',['-t','nat','-S']),before.nat);assert.equal(cmd('iptables',['-t','mangle','-S']),before.mangle);
  assert.equal(cmd('iptables',['-S']),before.filter);assert.match(guard(['status']),/IPv6: cvks4/);
};
try{
  open();check('preflight leaves routes/firewall untouched',()=>{owner.preflight();baseline();});
  check('prepare creates real persistent TUN, routes, DNS and NAT',()=>{owner.prepare();assert.equal(store.read().stage,'active');owner.tick();assert.equal(JSON.parse(ip('-j','route','get','1.1.1.1'))[0].dev,'tun0');});
  check('default loss waits without tearing down or exhausting restart budget',()=>{
    ip('route','del','default','via','192.168.1.1','dev','wlan0');
    for(let i=0;i<8;i++)assert.equal(owner.tick().state,'waiting-uplink');
    assert.equal(store.read().stage,'active');ip('route','add','default','via','192.168.1.1','dev','wlan0');assert.equal(owner.tick().state,'network-ready');
  });
  check('live engine prevents cleanup',()=>{engineAlive=true;assert.throws(()=>owner.recover(),/still_running/);engineAlive=false;});
  check('replaced alias refuses deletion',()=>{ip('link','set','tun0','alias','foreign');assert.throws(()=>owner.recover(),/owner_changed/);ip('link','set','tun0','alias','cvpn-native-host-'+store.read().id);});
  check('guard failure retains owned network',()=>{active=false;assert.throws(()=>owner.recover(),/guard_inactive/);assert.equal(store.read().stage,'active');active=true;});
  check('cleanup restores baseline and is repeatable',()=>{owner.recover();owner.recover();baseline();});
  close();open();
  check('new owner starts after released journal',()=>{owner.prepare();owner.tick();});
  const previous=c;c={...c,engine_unit:'native-next.service',network_unit:'native-next-network.service'};close();open();
  check('different instance cannot adopt active journal',()=>{assert.throws(()=>owner.recover(),/native_config_owner_mismatch/);assert.equal(store.read().stage,'active');});
  close();c=previous;open();
  close();open();check('process boundary recovery restores only owned state',()=>{owner.recover();baseline();});
  close();c={...previous,engine_unit:'native-next.service',network_unit:'native-next-network.service'};open();
  check('fresh instance follows released journal without adopting old state',()=>{owner.recover();owner.prepare();owner.tick();owner.recover();baseline();});
  close();c=previous;open();
  close();c={...previous,peer_ipv4:'10.99.0.37'};open();
  check('non-default peer binds real TUN DNS routing and USB SNAT to one identity',()=>{
    owner.prepare();owner.tick();
    assert.equal(JSON.parse(ip('-j','-4','addr','show','dev','tun0'))[0].addr_info[0].local,'10.99.0.37');
    assert.match(cmd('iptables',['-t','nat','-S']),/--to-source 10\.99\.0\.37/);
    assert.match(cmd('iptables',['-t','nat','-S']),/--to-destination 10\.99\.0\.37:1053/);
    assert.equal(dns.state.config.listenerAddress,'10.99.0.37');
  });
  close();open();check('non-default peer recovery restores baseline after process boundary',()=>{owner.recover();baseline();});
  close();c=previous;open();
  // Journal intent persisted before each NAT mutation, and TUN helper completion
  // before parent identity commit: neither boundary permits foreign adoption.
  for(const point of ['tun-intent','tun-identity','nat-1','nat-2','nat-3']){
    crashAt=s=>point==='tun-intent'?s.stage==='prepared'&&!s.tun:point==='tun-identity'?s.stage==='prepared'&&!!s.tun&&s.count===0:s.count===Number(point.at(-1));
    check('interrupted '+point,()=>assert.throws(()=>owner.prepare(),/simulated_process_boundary/));
    crashAt=null;close();open();check('recover '+point,()=>{owner.recover();baseline();});
  }
  console.log(JSON.stringify({status:'passed',checks,scope:'real-netns-TUN-DNS-routes-NAT; systemd state injected; no VPN payload or reboot'}));
}finally{close();}

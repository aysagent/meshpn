// Real kernel/journal regression in an explicitly disposable empty netns.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {openNativeComboRedirectJournal} from './lib/native-combo-redirect-journal.mjs';
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
const cubie=process.env.CVPN_CUBIE_PROFILE==='1',usbAddress=cubie?'192.168.8.1':'192.168.7.1',usbSubnet=cubie?'192.168.8.0/24':'192.168.7.0/24',uplink=cubie?(process.env.CVPN_IPHONE_PROFILE==='1'?'iphone0':'enx123456789012'):'wlan0';
let c={...(cubie?{usb_address:usbAddress,uplink:'auto'}:{}),version:1,exit_ip:'154.62.226.216',engine_unit:'native-daily.service',network_unit:'native-daily-network.service',guard_unit:'clean-vpn-killswitch.service',guard_script:'/usr/local/bin/clean-vpn-killswitch.sh'};
const tailnet=process.env.CVPN_TAILSCALE_PROFILE==='1';
const tsPrefs={NetfilterMode:0,CorpDNS:false,RouteAll:false,ExitNodeIP:'',ExitNodeID:'',AdvertiseRoutes:null};
if(tailnet){
 c.tailscale=true;
 ip('link','add','tailscale0','type','dummy');ip('link','set','tailscale0','up');
 ip('address','add','100.64.0.1/32','dev','tailscale0');
 ip('route','add','100.64.0.2/32','dev','tailscale0','table','52');
 for(const [priority,table] of [['5210','main'],['5230','default']])ip('rule','add','priority',priority,'fwmark','0x80000/0xff0000','lookup',table);
 ip('rule','add','priority','5250','fwmark','0x80000/0xff0000','unreachable');
 ip('rule','add','priority','5270','lookup','52');
}
ip('link','set','lo','up');
for(const [dev,address] of [['usb0',usbAddress+'/24'],[uplink,'192.168.1.8/24']]){
  ip('link','add',dev,'type','dummy');ip('addr','add',address,'dev',dev);ip('link','set',dev,'up');
}
ip('route','add','default','via','192.168.1.1','dev',uplink);
cmd('sysctl',['-w','net.ipv4.ip_forward=1']);
cmd('iptables',['-t','nat','-A','POSTROUTING','-o',uplink,'-m','comment','--comment','foreign-sentinel','-j','MASQUERADE']);
// Existing Armbian forwarding is present before guard at boot. A broad foreign
// ACCEPT must remain behind the guard through preparation/recovery.
cmd('iptables',['-N','ARMBIAN_USB_GADGET_FWD']);
cmd('iptables',['-A','ARMBIAN_USB_GADGET_FWD','-i','usb0','-s',usbSubnet,'-j','ACCEPT']);
cmd('iptables',['-I','FORWARD','1','-j','ARMBIAN_USB_GADGET_FWD']);
const guard=args=>cmd('bash',[root+'scripts/autostart/killswitch.sh',...args]);
guard(['up','--scope=both','--ipv6=block','--tun=tun0','--server='+c.exit_ip,'--ssh-port=22','--usb-dns=1','--usb-strict=1','--usb-subnet='+usbSubnet]);
assert.match(cmd('iptables',['-S','FORWARD']).split('\n')[1],/cvks2-hook -j CLEANVPN_KS_FWD/);
const before={routes:ip('-N','-j','-4','route','show','table','main'),rp:cmd('sysctl',['-n','net.ipv4.conf.all.rp_filter']),nat:cmd('iptables',['-t','nat','-S']),mangle:cmd('iptables',['-t','mangle','-S']),filter:cmd('iptables',['-S'])};
let engineAlive=false,active=true,crashAt=null,store,host,dns,redirect,owner,redirectCrash=false;
const run=(f,a)=>{
  if(f==='/usr/bin/tailscale'){assert.deepEqual(a,['debug','prefs']);return JSON.stringify(tsPrefs);}
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
  store=openNativeHostStore();host=openHostRoutes({allowTunLinkDown:true});dns=openTunnelDnsJournal();redirect=openNativeComboRedirectJournal(undefined,{checkpoint:(step)=>{if(redirectCrash&&step==='applied')throw Error('redirect_cut');}});
  const write=store.write;store.write=s=>{write(s);if(crashAt&&crashAt(s))throw Error('simulated_process_boundary');};
  owner=nativeHostNetwork(c,{run,host,dns,redirect,store,scope:nativeHostScope,randomId:()=>crypto.randomUUID().replaceAll('-','').slice(0,24),
    createTun:(name,alias,peer)=>cmd(process.env.CVPN_TEST_TUN_HELPER??root+'native/clean_vpn/build/clean-vpn-tun-helper',[name,alias,peer])});
};
const close=()=>{redirect?.release();dns?.release();host?.release();store?.close();};
const baseline=()=>{
  assert.ok(!JSON.parse(ip('-j','link')).some(l=>l.ifname==='tun0'));
  assert.equal(ip('-N','-j','-4','route','show','table','main'),before.routes);
  assert.equal(cmd('sysctl',['-n','net.ipv4.conf.all.rp_filter']),before.rp);
  assert.equal(cmd('iptables',['-t','nat','-S']),before.nat);assert.equal(cmd('iptables',['-t','mangle','-S']),before.mangle);
  assert.equal(cmd('iptables',['-S']),before.filter);assert.match(guard(['status']),new RegExp('IPv6: '+(cubie?'cvks5':'cvks4')));
};
try{
  open();check('preflight leaves routes/firewall untouched',()=>{owner.preflight();baseline();});
  check('prepare creates real persistent TUN, routes, DNS and NAT',()=>{owner.prepare();assert.equal(store.read().stage,'active');owner.tick();assert.equal(JSON.parse(ip('-j','route','get','1.1.1.1'))[0].dev,'tun0');});
  if(tailnet)check('tailnet routing coexists, marked outer traffic uses VPN, and exit-route drift fails closed',()=>{
    assert.equal(JSON.parse(ip('-j','route','get','100.64.0.2'))[0].dev,'tailscale0');
    assert.equal(JSON.parse(ip('-j','route','get','1.1.1.1','mark','0x80000'))[0].dev,'tun0');
    assert.equal(JSON.parse(ip('-j','route','get',c.exit_ip,'mark','0x80000'))[0].dev,uplink);
    // A pre-VPN bound socket gets a local rejection, not an invalid packet
    // inside the tunnel. Real OUTPUT counters distinguish this from timeout.
    const probe='/run/cvpn-marked-socket';
    execFileSync('cc',['-x','c','-','-o',probe],{input:`
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void){
 int s=socket(AF_INET,SOCK_DGRAM,0),mark=0x80000;
 struct sockaddr_in src={.sin_family=AF_INET},dst={.sin_family=AF_INET,.sin_port=htons(443)};
 if(s<0||setsockopt(s,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)))return 2;
 if(inet_pton(AF_INET,"192.168.1.8",&src.sin_addr)!=1||bind(s,(void*)&src,sizeof(src)))return 3;
 if(inet_pton(AF_INET,"1.1.1.1",&dst.sin_addr)!=1)return 4;
 sendto(s,"x",1,0,(void*)&dst,sizeof(dst));close(s);return 0;
}`,timeout:10000});
    cmd(probe,[]);
    const staleRule=cmd('iptables',['-nvx','-L','OUTPUT']).split('\n').find(l=>l.includes('REJECT')&&l.includes('mark match 0x80000/0xff0000'));
    assert.ok(staleRule&&Number(staleRule.trim().split(/\s+/)[0])>0,'stale Tailscale source rejected in OUTPUT');
    ip('route','add','default','dev','tailscale0','table','52');assert.throws(()=>owner.tick(),/native_tailscale_route/);
    ip('route','del','default','dev','tailscale0','table','52');owner.tick();
    tsPrefs.CorpDNS=true;assert.throws(()=>owner.tick(),/native_tailscale_dns/);tsPrefs.CorpDNS=false;owner.tick();
  });
  check('default loss waits without tearing down or exhausting restart budget',()=>{
    ip('route','del','default','via','192.168.1.1','dev',uplink);
    for(let i=0;i<8;i++)assert.equal(owner.tick().state,'waiting-uplink');
    assert.equal(store.read().stage,'active');ip('route','add','default','via','192.168.1.1','dev',uplink);assert.equal(owner.tick().state,'network-ready');
  });
  check('live engine prevents cleanup',()=>{engineAlive=true;assert.throws(()=>owner.recover(),/still_running/);engineAlive=false;});
  check('replaced alias refuses deletion',()=>{ip('link','set','tun0','alias','foreign');assert.throws(()=>owner.recover(),/owner_changed/);ip('link','set','tun0','alias','cvpn-native-host-'+store.read().id);});
  check('guard failure retains owned network',()=>{active=false;assert.throws(()=>owner.recover(),/guard_inactive/);assert.equal(store.read().stage,'active');active=true;});
  check('cleanup restores baseline and is repeatable',()=>{owner.recover();owner.recover();baseline();});
  if(cubie)check('USB and Wi-Fi defaults select preferred metric and recover on uplink change',()=>{
    ip('link','add','wlan0','type','dummy');ip('addr','add','192.168.2.8/24','dev','wlan0');ip('link','set','wlan0','up');
    ip('route','add','default','via','192.168.2.1','dev','wlan0','metric','600');
    owner.preflight();owner.prepare();assert.equal(owner.tick().state,'network-ready');
    assert.equal(JSON.parse(ip('-j','route','get',c.exit_ip))[0].dev,uplink);
    ip('route','del','default','via','192.168.1.1','dev',uplink);
    assert.throws(()=>owner.tick(),/exit route ownership mismatch/);
    owner.recover();owner.prepare();assert.equal(owner.tick().state,'network-ready');
    assert.equal(JSON.parse(ip('-j','route','get',c.exit_ip))[0].dev,'wlan0');
    ip('route','add','default','via','192.168.1.1','dev',uplink);
    assert.throws(()=>owner.tick(),/exit route ownership mismatch/);
    owner.recover();owner.prepare();assert.equal(owner.tick().state,'network-ready');
    assert.equal(JSON.parse(ip('-j','route','get',c.exit_ip))[0].dev,uplink);
    owner.recover();ip('link','del','wlan0');baseline();
  });
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
  close();c={...previous,combo_redirect:{interface:'usb0',subnet:usbSubnet,endpoint:previous.exit_ip,listen_port:10443,deny_ipv4:[]}};open();
  check('combo overlay redirects USB HTTPS only after native DNS and route preparation',()=>{
    owner.prepare();owner.tick();assert.equal(redirect.state.stage,'active');
    assert.match(cmd('iptables',['-t','nat','-S']),/REDIRECT --to-ports 10443/);
    assert.match(cmd('iptables',['-t','filter','-S']),/--dport 443.*-j DROP/);
  });
  close();open();check('combo process-boundary cleanup removes only journalled interception',()=>{owner.recover();baseline();});
  redirectCrash=true;check('combo interrupted redirect intent remains recoverable',()=>assert.throws(()=>owner.prepare(),/redirect_cut/));
  redirectCrash=false;close();open();check('combo partial redirect rollback restores baseline',()=>{owner.recover();baseline();});
  close();c=previous;open();
  // Journal intent persisted before each NAT mutation, and TUN helper completion
  // before parent identity commit: neither boundary permits foreign adoption.
  for(const point of ['tun-intent','tun-identity','nat-1','nat-2','nat-3']){
    crashAt=s=>point==='tun-intent'?s.stage==='prepared'&&!s.tun:point==='tun-identity'?s.stage==='prepared'&&!!s.tun&&s.count===0:s.count===Number(point.at(-1));
    check('interrupted '+point,()=>assert.throws(()=>owner.prepare(),/simulated_process_boundary/));
    crashAt=null;close();open();check('recover '+point,()=>{owner.recover();baseline();});
  }
  close();c={...previous,incoming_tcp:{source_ipv4:'10.99.0.1',port:9443}};open();
  check('scoped incoming audit and process-boundary recovery preserve guard and foreign rules',()=>{owner.prepare();owner.tick();close();open();owner.recover();baseline();});
  for(const point of [4,5,6,7]){
    crashAt=s=>s.count===point;
    check('interrupted incoming rule '+point,()=>assert.throws(()=>owner.prepare(),/simulated_process_boundary/));
    crashAt=null;close();open();check('recover incoming rule '+point,()=>{owner.recover();baseline();});
  }
  close();c={...c,combo_redirect:{interface:'usb0',subnet:usbSubnet,endpoint:c.exit_ip,listen_port:10443,deny_ipv4:[]}};open();
  check('incoming INPUT precedence composes with combo hooks and cleanup',()=>{owner.prepare();owner.tick();close();open();owner.recover();baseline();});
  console.log(JSON.stringify({status:'passed',checks,scope:'real-netns-TUN-DNS-routes-NAT; systemd state injected; no VPN payload or reboot'}));
}finally{close();}

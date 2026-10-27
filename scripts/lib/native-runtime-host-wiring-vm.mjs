// Physical-host topology model inside the NIC-less guest: USB-like ingress ->
// host policy routing/SNAT -> private bridge -> native client namespace.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { execFileSync } from 'node:child_process';
import { runtimeGatewayUnit } from './native-runtime-units.mjs';
// Own fixture links only: deterministic link-local insertion avoids racing
// bridge/port DAD completion when comparing exact route order after recreation.
const upPrivateLink=(ns,name,mac,linkLocal)=>{
  ns('gateway','ip','link','set',name,'address',mac);
  ns('gateway','sysctl','-w',`net.ipv6.conf.${name}.addr_gen_mode=1`);
  ns('gateway','ip','link','set',name,'up');
  ns('gateway','ip','-6','addr','add',linkLocal+'/64','dev',name,'nodad');
};

export async function prepareHostWiring({ip,ns,namespaces}) {
  for(const name of ['gateway','usb-app','other-app']){ip('netns','add',name);namespaces.push(name);ns(name,'ip','link','set','lo','up');}
  ip('link','add','gw-host','type','veth','peer','name','gw-peer');
  ip('link','set','gw-host','master','br0');ip('link','set','gw-host','up');ip('link','set','gw-peer','netns','gateway');
  ns('gateway','ip','link','set','gw-peer','name','eth0');ns('gateway','ip','addr','add','10.77.0.5/24','dev','eth0');ns('gateway','ip','link','set','eth0','up');
  ns('gateway','ip','route','add','default','via','10.77.0.1');
  ns('gateway','ip','route','add','198.18.0.80/32','via','10.77.0.4');
  for(const server of ['1.1.1.1','8.8.8.8']) {
    ns('origin','ip','addr','add',server+'/32','dev','lo');
    ns('gateway','ip','route','add',server+'/32','via','10.77.0.4');
    for(const proto of ['udp','tcp'])ns('origin','iptables-nft','-t','nat','-A','PREROUTING','-d',server,'-p',proto,'--dport','53','-j','REDIRECT','--to-ports','5353');
  }
  ns('gateway','ip','-6','addr','add','fd77::5/64','dev','eth0','nodad');
  ns('origin','ip','-6','addr','add','fd77::4/64','dev','eth0','nodad');
  for(const [app,dev,subnet,prefix]of [['usb-app','usb0','192.168.7','usb'],['other-app','lan1','192.168.8','other']]){
    ip('link','add',prefix+'-host','type','veth','peer','name',prefix+'-peer');
    ip('link','set',prefix+'-host','netns','gateway');ns('gateway','ip','link','set',prefix+'-host','name',dev);
    ip('link','set',prefix+'-peer','netns',app);ns(app,'ip','link','set',prefix+'-peer','name','eth0');
    ns('gateway','ip','addr','add',subnet+'.1/24','dev',dev);ns('gateway','ip','link','set',dev,'up');
    ns(app,'ip','addr','add',subnet+'.2/24','dev','eth0');ns(app,'ip','link','set','eth0','up');
    ns(app,'ip','route','add','default','via',subnet+'.1');
    ns('origin','ip','route','add',subnet+'.0/24','via','10.77.0.5');
    const v6=app==='usb-app'?'fd07':'fd08';
    ns('gateway','ip','-6','addr','add',v6+'::1/64','dev',dev,'nodad');
    ns(app,'ip','-6','addr','add',v6+'::2/64','dev','eth0','nodad');
    ns(app,'ip','-6','route','add','fd77::/64','via',v6+'::1');
    ns('origin','ip','-6','route','add',v6+'::/64','via','fd77::5');
  }
  ns('gateway','ip','link','add','cvlbr0','type','bridge');ns('gateway','ip','addr','add','192.168.88.1/24','dev','cvlbr0');upPrivateLink(ns,'cvlbr0','02:00:00:88:00:01','fe80::ff:fe88:1');
  ip('link','add','backend-host','type','veth','peer','name','backend-peer');ip('link','set','backend-host','netns','gateway');
  ns('gateway','ip','link','set','backend-host','master','cvlbr0');upPrivateLink(ns,'backend-host','02:00:00:88:00:02','fe80::ff:fe88:2');
  ip('link','set','backend-peer','netns','client');ns('client','ip','link','set','backend-peer','name','eth1');
  ns('client','ip','addr','add','192.168.88.2/24','dev','eth1');ns('client','ip','link','set','eth1','up');
  for(const name of ['gateway','client'])ns(name,'sysctl','-w','net.ipv4.ip_forward=1');
  // Finish all fixture DAD before enabling router anycast. Otherwise a slow
  // LAN DAD can insert fe80:: anycast after the bridge and make the initial
  // route order itself depend on scheduling, even with deterministic bridge IPs.
  const tentative=()=>JSON.parse(ns('gateway','ip','-j','-6','addr','show')).some(l=>l.addr_info.some(a=>a.tentative||(a.flags??[]).includes('tentative')));
  for(let i=0;i<120&&tentative();i++)await delay(50);
  assert.equal(tentative(),false,'fixture_dad_timeout');
  ns('gateway','sysctl','-w','net.ipv6.conf.all.forwarding=1');
  // Preconditions of the reference recipe, not hidden host-wide changes.
  for(const name of ['usb0','cvlbr0'])ns('gateway','sysctl','-w',`net.ipv4.conf.${name}.rp_filter=2`);
  ns('gateway','iptables-nft','-N','FOREIGN_WIRING_SENTINEL');ns('gateway','iptables-nft','-A','FORWARD','-j','FOREIGN_WIRING_SENTINEL');
  fs.writeFileSync('/etc/resolv.conf','nameserver 10.77.0.4\n');
  fs.writeFileSync('/config/gateway.json',JSON.stringify({schema:1,ingress:{interface:'usb0',subnet:'192.168.7.0/24'},
    bridge:{interface:'cvlbr0',subnet:'192.168.88.0/24',host:'192.168.88.1',client:'192.168.88.2'},
    table:19998,priority:10998,bypass:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'],dnsUid:61453}),{mode:0o600});
}

export async function checkHostWiring({ns,child,wait,health,step,client,restartClient,origin}) {
  const helper='/project/scripts/lib/native-runtime-host-wiring-fixture.mjs';
  const snapshot=()=>JSON.stringify(['ip','iptables-nft','ip6tables-nft'].flatMap(bin=>bin==='ip'
    ? [['-j','-4','rule','show'],['-j','-4','route','show','table','all'],['-j','-6','rule','show'],['-j','-6','route','show','table','all']].map(a=>ns('gateway',bin,...a))
    : [['-S'],...(bin==='iptables-nft'?[['-t','nat','-S']]:[])].map(a=>ns('gateway',bin,...a))).concat([
      ns('gateway','sysctl','-n','net.ipv4.ip_forward'),ns('gateway','sysctl','-n','net.ipv6.conf.all.forwarding'),ns('gateway','sysctl','-n','net.ipv4.conf.usb0.rp_filter'),
      ns('gateway','sysctl','-n','net.ipv4.conf.cvlbr0.rp_filter'),fs.readFileSync('/etc/resolv.conf','utf8')]));
  const before=snapshot();
  const journalDirectory='/run/clean-vpn-gateway-'+ns('gateway','readlink','/proc/self/ns/net').match(/\d+/)[0];
  if(fs.existsSync('/state/first-boot.json')){
    fs.mkdirSync(journalDirectory,{mode:0o700});fs.copyFileSync('/state/stale-gateway.json',journalDirectory+'/journal.json');
    assert.throws(()=>ns('gateway','node',helper,'recover'),/gateway_scope_mismatch/);assert.equal(snapshot(),before);
    fs.rmSync(journalDirectory,{recursive:true});step('gateway-reboot-stale-journal-refused-without-network-writes');
  }
  const directDns=String.raw`import {dnsProbe} from '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs';await Promise.all([false,true].map(t=>dnsProbe('1.1.1.1',53,t)));console.log('DIRECT_DNS_OK');`;
  const localDns=String.raw`import {dnsProbe} from '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs';await Promise.all([false,true].map(t=>dnsProbe('127.0.0.1',53,t)));console.log('LOCAL_DNS_OK');`;
  fs.mkdirSync('/run/dnslab',{mode:0o700});fs.chownSync('/run/dnslab',61453,61453);
  const resolver=(servers,tag)=>child('gateway','/usr/sbin/dnsmasq',['--keep-in-foreground','--conf-file=/dev/null','--user=dnslab','--group=dnslab',
    '--interface=usb0','--listen-address=127.0.0.1,192.168.7.1','--bind-interfaces','--no-resolv','--no-hosts','--cache-size=0',
    '--dhcp-range=192.168.7.10,192.168.7.50,255.255.255.0,12h','--dhcp-option=3,192.168.7.1','--dhcp-option=6,192.168.7.1','--dhcp-leasefile=/run/dnslab/leases',
    ...servers.map(s=>'--server='+s),'--pid-file=/run/gateway-dnsmasq.pid','--log-facility=-','--log-queries=extra'],tag);
  let dnsmasq=resolver(['1.1.1.1','8.8.8.8'],'gateway-dnsmasq');
  const stopResolver=async()=>{dnsmasq.p.kill('SIGTERM');await wait(()=>assert.notEqual(dnsmasq.p.exitCode,null));};
  await wait(()=>assert.match(ns('gateway','node','--input-type=module','-e',localDns),/LOCAL_DNS_OK/));
  const dnsPeers=offset=>fs.readFileSync(origin.stdout,'utf8').slice(offset).split('\n').filter(l=>l.startsWith('DNS_QUERY_PEER=')).map(l=>l.split('=')[1]);
  assert.ok(dnsPeers(0).includes('10.77.0.5'));step('dnsmasq-uid-direct-positive-control-cache-disabled');
  const probe = String.raw`const https=require('https'),fs=require('fs');
https.get({host:'198.18.0.80',port:8443,servername:'runtime.test',ca:fs.readFileSync('/config/cert.pem'),timeout:2500},r=>{
let b='';r.on('data',x=>b+=x);r.on('end',()=>{if(b!=='native-runtime-https-ok\n')process.exitCode=1;else console.log(r.headers['x-native-runtime-peer']);});
}).on('error',()=>process.exitCode=1).on('timeout',function(){this.destroy()});`;
  const path=(name,peer)=>assert.equal(ns(name,'node','-e',probe).trim(),peer);
  path('usb-app','192.168.7.2');path('other-app','192.168.8.2');path('gateway','10.77.0.5');step('host-wiring-direct-positive-controls');
  const v6origin=child('origin','node',['-e',"require('net').createServer(s=>s.end('IPV6_DIRECT')).listen(8090,'fd77::4',()=>console.log('V6_READY'))"],'v6-origin');
  await wait(()=>assert.match(fs.readFileSync(v6origin.stdout,'utf8'),/V6_READY/));
  const v6probe="const s=require('net').connect(8090,'fd77::4');s.setTimeout(1200,()=>process.exit(1));s.on('data',b=>process.stdout.write(b));s.on('end',()=>s.destroy());s.on('error',()=>process.exit(1));";
  for(const name of ['usb-app','other-app'])assert.equal(ns(name,'node','-e',v6probe),'IPV6_DIRECT');
  const rescue=child('gateway','node',['-e',"require('net').createServer(s=>s.end('RESCUE')).listen(2222,'192.168.7.1',()=>console.log('RESCUE_READY'))"],'usb-rescue');
  await wait(()=>assert.match(fs.readFileSync(rescue.stdout,'utf8'),/RESCUE_READY/));
  const rescueProbe=()=>assert.equal(ns('usb-app','node','-e',"const s=require('net').connect(2222,'192.168.7.1');s.setTimeout(2000,()=>process.exit(1));s.on('data',b=>process.stdout.write(b));s.on('end',()=>s.destroy());s.on('error',()=>process.exit(1));"),'RESCUE');
  const ready=owner=>wait(()=>assert.match(fs.readFileSync(owner.stdout,'utf8'),/HOST_WIRING_READY/,fs.readFileSync(owner.stderr,'utf8')));
  let owner=child('gateway','node',[helper,'apply'],'host-wiring');await ready(owner);
  // Existing direct upstream sockets are now blocked; the fixture owns its
  // dnsmasq lifecycle and switches it explicitly. No host config is rewritten.
  assert.throws(()=>ns('gateway','node','--input-type=module','-e',localDns));
  await stopResolver();dnsmasq=resolver(['192.168.88.2@192.168.88.1'],'gateway-dnsmasq-native');
  await wait(()=>assert.match(ns('gateway','node','--input-type=module','-e',localDns),/LOCAL_DNS_OK/));
  step('dnsmasq-old-upstream-blocked-explicit-owned-switch');
  assert.match(ns('usb-app','node','/project/scripts/lib/native-runtime-dhcp-probe.mjs'),/DHCP_ROUTER_AND_SINGLE_DNS_OPTION_OK/);
  step('dnsmasq-usb-dhcp-offer-ack-router-and-single-dns-option');
  path('usb-app','10.77.0.2');path('other-app','192.168.8.2');path('gateway','10.77.0.5');rescueProbe();step('host-iif-policy-selected-exit-other-and-host-direct');
  assert.throws(()=>ns('usb-app','node','-e',v6probe));assert.equal(ns('other-app','node','-e',v6probe),'IPV6_DIRECT');step('host-selected-ipv6-blocked-other-interface-preserved');
  const dns=String.raw`import {dnsProbe} from '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs';await Promise.all([false,true].map(t=>dnsProbe('192.168.7.1',53,t)));console.log('DNS_OK');`;
  assert.match(ns('usb-app','node','--input-type=module','-e',dns),/DNS_OK/);step('host-ingress-dns-udp-tcp-through-client');
  let offset=fs.statSync(origin.stdout).size;
  assert.match(ns('gateway','node','--input-type=module','-e',localDns),/LOCAL_DNS_OK/);
  const viaExit=dnsPeers(offset);assert.ok(viaExit.length>=2&&viaExit.every(p=>p==='10.77.0.2'),JSON.stringify(viaExit));
  assert.match(ns('gateway','node','--input-type=module','-e',directDns),/DIRECT_DNS_OK/);step('dnsmasq-local-udp-tcp-via-exit-other-host-dns-unchanged');
  assert.throws(()=>ns('gateway','node',helper,'recover'),/live_owner_refused/);step('host-wiring-live-owner-recovery-refused');
  owner.p.kill('SIGKILL');await wait(()=>assert.ok(owner.p.signalCode));path('usb-app','10.77.0.2');step('host-wiring-controller-sigkill-retains-route');
  if(fs.existsSync('/state')&&!fs.existsSync('/state/first-boot.json'))fs.copyFileSync(journalDirectory+'/journal.json','/state/stale-gateway.json');
  client.p.kill('SIGKILL');await wait(()=>assert.ok(client.p.signalCode));
  assert.throws(()=>ns('usb-app','node','-e',probe));assert.throws(()=>ns('usb-app','node','--input-type=module','-e',dns));
  offset=fs.statSync(origin.stdout).size;assert.throws(()=>ns('gateway','node','--input-type=module','-e',localDns));
  await delay(500);assert.deepEqual(dnsPeers(offset),[]);step('dnsmasq-tunnel-loss-no-direct-upstream-fallback');
  path('other-app','192.168.8.2');path('gateway','10.77.0.5');rescueProbe();step('host-wiring-tunnel-failure-no-selected-fallback-rescue-retained');
  assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);assert.equal(snapshot(),before);
  path('usb-app','192.168.7.2');step('host-wiring-independent-rollback-exact-baseline');
  await stopResolver();dnsmasq=resolver(['1.1.1.1','8.8.8.8'],'gateway-dnsmasq-restored');
  await wait(()=>assert.match(ns('gateway','node','--input-type=module','-e',localDns),/LOCAL_DNS_OK/));step('dnsmasq-fixture-owner-restores-original-upstreams');
  assert.equal(ns('usb-app','node','-e',v6probe),'IPV6_DIRECT');
  // Kill after durable intent but before route mutation: recovery must handle
  // a journal cursor ahead of the actual kernel state without deleting foreign rules.
  client=restartClient();await wait(()=>health('client'));
  owner=child('gateway','env',['CVPN_WIRING_KILL_AT=9','node',helper,'apply'],'host-wiring-partial');
  await wait(()=>assert.equal(owner.p.signalCode,'SIGKILL'));
  assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);assert.equal(snapshot(),before);step('host-wiring-intent-before-mutation-recovery');
  for(const [fault,label]of [['CVPN_WIRING_KILL_BEFORE_RENAME','journal-temp-orphan'],['CVPN_WIRING_KILL_AFTER_MUTATION','mutation-before-verification']]){
    owner=child('gateway','env',[fault+'=9','node',helper,'apply'],'host-wiring-'+label);
    await wait(()=>assert.equal(owner.p.signalCode,'SIGKILL'));
    assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);assert.equal(snapshot(),before);step('host-wiring-'+label+'-recovery');
  }
  owner=child('gateway','node',[helper,'apply'],'host-wiring-foreign');await ready(owner);
  assert.match(ns('gateway','node','/project/scripts/clean-vpn-native-gateway.mjs','status'),/live-owner/);
  owner.p.kill('SIGKILL');await wait(()=>assert.ok(owner.p.signalCode));
  const oldJournal=fs.readFileSync(journalDirectory+'/journal.json');
  ns('gateway','iptables-nft','-A','CVPN_GW','-j','RETURN');const drift=snapshot();
  assert.throws(()=>ns('gateway','node',helper,'recover'),/gateway_foreign_firewall_drift/);assert.equal(snapshot(),drift);
  ns('gateway','iptables-nft','-D','CVPN_GW','-j','RETURN');
  const recovering=child('gateway','env',['CVPN_WIRING_RECOVER_KILL_BEFORE_RENAME=5','node',helper,'recover'],'host-wiring-recovery-crash');
  await wait(()=>assert.equal(recovering.p.signalCode,'SIGKILL'));
  assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);assert.equal(snapshot(),before);
  step('gateway-foreign-drift-refused-and-interrupted-recovery-resumed');
  fs.writeFileSync(journalDirectory+'/journal.json',oldJournal,{mode:0o600});
  ns('gateway','ip','-4','route','add','unreachable','default','metric','32767','table','19998');const unowned=snapshot();
  assert.throws(()=>ns('gateway','node',helper,'recover'),/gateway_routes_without_ownership_tag/);assert.equal(snapshot(),unowned);
  ns('gateway','ip','-4','route','del','unreachable','default','metric','32767','table','19998');fs.unlinkSync(journalDirectory+'/journal.json');
  assert.equal(snapshot(),before);step('gateway-matching-routes-without-random-ownership-tag-refused');
  // Exercise the same controller with different names, not just the old
  // hardcoded usb0/cvlbr0 recipe. wg0 here is a veth model, not WireGuard crypto.
  const original=fs.readFileSync('/config/gateway.json'),alternate=JSON.parse(original);
  ns('gateway','ip','link','set','usb0','name','wg0');ns('gateway','ip','link','set','cvlbr0','name','vpnbr0');
  alternate.ingress.interface='wg0';alternate.bridge.interface='vpnbr0';alternate.table=19997;alternate.priority=10997;
  fs.writeFileSync('/config/gateway.json',JSON.stringify(alternate));
  owner=child('gateway','node',[helper,'apply'],'host-wiring-configurable');await ready(owner);path('usb-app','10.77.0.2');rescueProbe();
  owner.p.kill('SIGTERM');await wait(()=>assert.equal(owner.p.exitCode,0));
  ns('gateway','ip','link','set','wg0','name','usb0');ns('gateway','ip','link','set','vpnbr0','name','cvlbr0');fs.writeFileSync('/config/gateway.json',original);
  assert.equal(snapshot(),before);step('gateway-configurable-interface-table-and-normal-stop');
  owner=child('gateway','node',['/project/scripts/clean-vpn-native-gateway.mjs','apply','--config=/config/gateway.json','--seconds=10'],'gateway-expiry');
  await wait(()=>assert.match(fs.readFileSync(owner.stdout,'utf8'),/NATIVE_GATEWAY=ready/));path('usb-app','10.77.0.2');
  await wait(()=>assert.equal(owner.p.exitCode,0));assert.equal(snapshot(),before);step('gateway-bounded-expiry-restores-baseline');
  owner=child('gateway','node',[helper,'apply'],'host-wiring-link-loss');await ready(owner);
  // The host's main default remains usable; the selected ingress must still
  // fail closed when the private bridge disappears and its route is removed.
  ns('gateway','ip','link','del','cvlbr0');assert.throws(()=>ns('usb-app','node','-e',probe));path('other-app','192.168.8.2');rescueProbe();
  owner.p.kill('SIGKILL');await wait(()=>assert.ok(owner.p.signalCode));assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);
  assert.equal(ns('gateway','ip','-j','-4','rule','show'),JSON.parse(before)[0]);step('host-bridge-loss-unreachable-default-no-fallback');
  // Recreate only the fixture-owned bridge so the existing namespace remains
  // usable for the subsequent standalone clock/restart checks.
  // Rebuild its fixture-owned port in the original order as well: otherwise
  // equal-prefix kernel IPv6 link routes retain a different insertion order.
  // Keep the strict baseline comparison rather than sorting differences away.
  ns('gateway','ip','link','set','backend-host','down');
  ns('gateway','ip','link','add','cvlbr0','type','bridge');ns('gateway','ip','addr','add','192.168.88.1/24','dev','cvlbr0');upPrivateLink(ns,'cvlbr0','02:00:00:88:00:01','fe80::ff:fe88:1');
  ns('gateway','ip','link','set','backend-host','master','cvlbr0');upPrivateLink(ns,'backend-host','02:00:00:88:00:02','fe80::ff:fe88:2');
  ns('gateway','sysctl','-w','net.ipv4.conf.cvlbr0.rp_filter=2');await wait(()=>assert.equal(snapshot(),before));
  // The runtime guest can optionally boot systemd PID1. Test the *rendered*
  // unit and independent ExecStopPost, not an in-process finally surrogate.
  if(fs.readFileSync('/proc/1/comm','utf8').trim()==='systemd'){
    const ctl=(...a)=>execFileSync('systemctl',a,{encoding:'utf8',timeout:45000}).trim();
    const unit='cvpn-gateway-lab.service',log='/run/gateway-systemd.log';
    fs.writeFileSync('/etc/systemd/system/'+unit,runtimeGatewayUnit({namespace:'gateway',parent:fs.readlinkSync('/proc/self/ns/net'),
      scripts:'/project/scripts',node:'/usr/local/bin/node',config:'/config/gateway.json',seconds:60})
      .replace('[Unit]\n','[Unit]\nDefaultDependencies=no\n')+`StandardOutput=append:${log}\nStandardError=append:${log}\n`);
    ctl('daemon-reload');
    const start=async()=>{fs.writeFileSync(log,'');ctl('start',unit);await wait(()=>assert.match(fs.readFileSync(log,'utf8'),/NATIVE_GATEWAY=ready/));path('usb-app','10.77.0.2');};
    await start();ctl('stop',unit);assert.equal(snapshot(),before);step('gateway-systemd-normal-stop-exact-rollback');
    await start();ctl('kill','--kill-whom=main','--signal=SIGKILL',unit);
    await wait(()=>{assert.equal(ctl('show',unit,'-p','ActiveState','--value'),'failed');assert.equal(snapshot(),before);});
    assert.match(fs.readFileSync(log,'utf8'),/NATIVE_GATEWAY=restored/);step('gateway-systemd-independent-exec-stop-post-after-sigkill');
    ctl('reset-failed',unit);await start();ctl('stop',unit);assert.equal(snapshot(),before);step('gateway-systemd-restart-after-crash-recovery');
    fs.unlinkSync('/etc/systemd/system/'+unit);ctl('daemon-reload');
  }
  await stopResolver();
  await delay(100);return client;
}

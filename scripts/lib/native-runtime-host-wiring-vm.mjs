// Physical-host topology model inside the NIC-less guest: USB-like ingress ->
// host policy routing/SNAT -> private bridge -> native client namespace.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

export function prepareHostWiring({ip,ns,namespaces}) {
  for(const name of ['gateway','usb-app','other-app']){ip('netns','add',name);namespaces.push(name);ns(name,'ip','link','set','lo','up');}
  ip('link','add','gw-host','type','veth','peer','name','gw-peer');
  ip('link','set','gw-host','master','br0');ip('link','set','gw-host','up');ip('link','set','gw-peer','netns','gateway');
  ns('gateway','ip','link','set','gw-peer','name','eth0');ns('gateway','ip','addr','add','10.77.0.5/24','dev','eth0');ns('gateway','ip','link','set','eth0','up');
  ns('gateway','ip','route','add','default','via','10.77.0.1');
  ns('gateway','ip','route','add','198.18.0.80/32','via','10.77.0.4');
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
  ns('gateway','ip','link','add','cvlbr0','type','bridge');ns('gateway','ip','link','set','cvlbr0','address','02:00:00:88:00:01');ns('gateway','ip','addr','add','192.168.88.1/24','dev','cvlbr0');ns('gateway','ip','link','set','cvlbr0','up');
  ip('link','add','backend-host','type','veth','peer','name','backend-peer');ip('link','set','backend-host','netns','gateway');
  ns('gateway','ip','link','set','backend-host','master','cvlbr0');ns('gateway','ip','link','set','backend-host','up');
  ip('link','set','backend-peer','netns','client');ns('client','ip','link','set','backend-peer','name','eth1');
  ns('client','ip','addr','add','192.168.88.2/24','dev','eth1');ns('client','ip','link','set','eth1','up');
  for(const name of ['gateway','client'])ns(name,'sysctl','-w','net.ipv4.ip_forward=1');
  ns('gateway','sysctl','-w','net.ipv6.conf.all.forwarding=1');
  // Preconditions of the reference recipe, not hidden host-wide changes.
  for(const name of ['usb0','cvlbr0'])ns('gateway','sysctl','-w',`net.ipv4.conf.${name}.rp_filter=2`);
  ns('gateway','iptables-nft','-N','FOREIGN_WIRING_SENTINEL');ns('gateway','iptables-nft','-A','FORWARD','-j','FOREIGN_WIRING_SENTINEL');
  fs.writeFileSync('/etc/resolv.conf','nameserver 10.77.0.4\n');
}

export async function checkHostWiring({ns,child,wait,health,step,client,restartClient}) {
  const helper='/project/scripts/lib/native-runtime-host-wiring-fixture.mjs';
  const snapshot=()=>JSON.stringify(['ip','iptables-nft','ip6tables-nft'].flatMap(bin=>bin==='ip'
    ? [['-j','-4','rule','show'],['-j','-4','route','show','table','all'],['-j','-6','rule','show'],['-j','-6','route','show','table','all']].map(a=>ns('gateway',bin,...a))
    : [['-S'],...(bin==='iptables-nft'?[['-t','nat','-S']]:[])].map(a=>ns('gateway',bin,...a))).concat([
      ns('gateway','sysctl','-n','net.ipv4.ip_forward'),ns('gateway','sysctl','-n','net.ipv6.conf.all.forwarding'),ns('gateway','sysctl','-n','net.ipv4.conf.usb0.rp_filter'),
      ns('gateway','sysctl','-n','net.ipv4.conf.cvlbr0.rp_filter'),fs.readFileSync('/etc/resolv.conf','utf8')]));
  const before=snapshot();
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
  path('usb-app','10.77.0.2');path('other-app','192.168.8.2');path('gateway','10.77.0.5');rescueProbe();step('host-iif-policy-selected-exit-other-and-host-direct');
  assert.throws(()=>ns('usb-app','node','-e',v6probe));assert.equal(ns('other-app','node','-e',v6probe),'IPV6_DIRECT');step('host-selected-ipv6-blocked-other-interface-preserved');
  const dns=String.raw`import {dnsProbe} from '/opt/clean-vpn/clean-vpn-native-runtime-health.mjs';await Promise.all([false,true].map(t=>dnsProbe('192.168.7.1',53,t)));console.log('DNS_OK');`;
  assert.match(ns('usb-app','node','--input-type=module','-e',dns),/DNS_OK/);step('host-ingress-dns-udp-tcp-through-client');
  assert.throws(()=>ns('gateway','node',helper,'recover'),/live_owner_refused/);step('host-wiring-live-owner-recovery-refused');
  owner.p.kill('SIGKILL');await wait(()=>assert.ok(owner.p.signalCode));path('usb-app','10.77.0.2');step('host-wiring-controller-sigkill-retains-route');
  client.p.kill('SIGKILL');await wait(()=>assert.ok(client.p.signalCode));
  assert.throws(()=>ns('usb-app','node','-e',probe));assert.throws(()=>ns('usb-app','node','--input-type=module','-e',dns));
  path('other-app','192.168.8.2');path('gateway','10.77.0.5');rescueProbe();step('host-wiring-tunnel-failure-no-selected-fallback-rescue-retained');
  assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);assert.equal(snapshot(),before);
  path('usb-app','192.168.7.2');step('host-wiring-independent-rollback-exact-baseline');
  assert.equal(ns('usb-app','node','-e',v6probe),'IPV6_DIRECT');
  // Kill after durable intent but before route mutation: recovery must handle
  // a journal cursor ahead of the actual kernel state without deleting foreign rules.
  owner=child('gateway','env',['CVPN_WIRING_KILL_AT=9','node',helper,'apply'],'host-wiring-partial');
  await wait(()=>assert.equal(owner.p.signalCode,'SIGKILL'));
  assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);assert.equal(snapshot(),before);step('host-wiring-intent-before-mutation-recovery');
  client=restartClient();await wait(()=>health('client'));
  owner=child('gateway','node',[helper,'apply'],'host-wiring-link-loss');await ready(owner);
  // The host's main default remains usable; the selected ingress must still
  // fail closed when the private bridge disappears and its route is removed.
  ns('gateway','ip','link','del','cvlbr0');assert.throws(()=>ns('usb-app','node','-e',probe));path('other-app','192.168.8.2');rescueProbe();
  owner.p.kill('SIGKILL');await wait(()=>assert.ok(owner.p.signalCode));assert.match(ns('gateway','node',helper,'recover'),/HOST_WIRING_RESTORED/);
  assert.equal(ns('gateway','ip','-j','-4','rule','show'),JSON.parse(before)[0]);step('host-bridge-loss-unreachable-default-no-fallback');
  // Recreate only the fixture-owned bridge so the existing namespace remains
  // usable for the subsequent standalone clock/restart checks.
  ns('gateway','ip','link','add','cvlbr0','type','bridge');ns('gateway','ip','link','set','cvlbr0','address','02:00:00:88:00:01');ns('gateway','ip','addr','add','192.168.88.1/24','dev','cvlbr0');ns('gateway','ip','link','set','cvlbr0','up');
  ns('gateway','ip','link','set','backend-host','master','cvlbr0');ns('gateway','ip','link','set','backend-host','up');
  ns('gateway','sysctl','-w','net.ipv4.conf.cvlbr0.rp_filter=2');await wait(()=>assert.equal(snapshot(),before));
  await delay(100);return client;
}

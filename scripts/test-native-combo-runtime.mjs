import test from 'node:test';
import assert from 'node:assert/strict';
import { runtimePlan, runtimePacketConfig, runtimeAnnouncements, restoreTable } from './lib/native-runtime-plan.mjs';
import { publishedExitPort } from './lib/native-port.mjs';

const config = role => ({ version:1, transport:'combo-tls', role,
  boring:{version:1,role,tun:'cvpn0',address:'198.18.0.2',port:3443,dns:true,sni:'relay.example',secret_path:'/config/packet.psk'},
  transparent:{version:1,transport:'transparent-tls',role,public_name:'relay.example',secret_path:'/config/relay.psk',
    destination_policy:{mode:'public-https',deny_ipv4:['11.0.0.0/8']},
    listen:{ipv4:role==='client'?'0.0.0.0':'198.18.0.2',port:role==='client'?10443:3443},
    ...(role==='client'?{exit:{ipv4:'198.18.0.2',port:3443}}:{replay_directory:'/replay/state'})}});
const options = {lan:{interface:'eth1',subnet:'192.168.88.0/24'}};
test('ARP announcement uses only assigned IPv4 on approved namespace interfaces',()=>{
  const plan=runtimePlan(config('client'),options);
  const links=[{ifname:'eth0',addr_info:[{family:'inet',local:'10.77.0.3'}]},
    {ifname:'eth1',addr_info:[{family:'inet',local:'192.168.88.2'}]},
    {ifname:'cvpn0',addr_info:[{family:'inet',local:'10.99.0.2'}]},
    {ifname:'foreign',addr_info:[{family:'inet',local:'192.168.1.1'}]}];
  const args=runtimeAnnouncements(plan,links);
  assert.deepEqual(args.map(a=>a.slice(-2)),[['eth0','10.77.0.3'],['eth1','192.168.88.2']]);
  assert.ok(args.every(a=>a.includes('-U')&&a.includes('2')));
  assert.throws(()=>runtimeAnnouncements(plan,links.slice(1)),/interface_missing/);
  links[0].addr_info[0].local='10.0.0.1;bad';assert.throws(()=>runtimeAnnouncements(plan,links));
});
test('combo runtime keeps LAN DNS before relay exclusions and blocks HTTPS fallback to TUN',()=>{
  const plan=runtimePlan(config('client'),options);
  const nat=restoreTable(plan.tables.find(t=>t.name==='nat'));
  assert.ok(nat.indexOf('--dport 53 -j DNAT')<nat.indexOf('-d 10.0.0.0/8 -i eth1 -j RETURN'));
  assert.ok(nat.includes('--dport 443 -j REDIRECT --to-ports 10443'));
  const forward=plan.tables.find(t=>t.family===4&&t.name==='filter').entries.find(e=>e.hook==='FORWARD').rules;
  assert.ok(forward[0].includes('--dport 443 -j DROP'));
  assert.ok(forward[1].includes('-o cvpn0 -j ACCEPT'));
  assert.equal(plan.port,3443);assert.equal(plan.relayPort,10443);
  assert.equal(publishedExitPort(runtimePacketConfig(config('exit')),4443),'4443:3443/tcp');
});
test('combo exit limits locally generated traffic to listener replies and permitted public HTTPS',()=>{
  const plan=runtimePlan(config('exit'));
  const output=plan.tables.find(t=>t.family===4&&t.name==='filter').entries.find(e=>e.hook==='OUTPUT').rules;
  assert.ok(output[1].includes('--sport 3443')&&output[1].includes('--ctdir REPLY'));
  const deny=output.findIndex(r=>r.includes('11.0.0.0/8 -o eth0 -j DROP'));
  assert.ok(deny>1&&deny<output.findIndex(r=>r.includes('--dport 443 -j ACCEPT')));
  assert.ok(!output.some(r=>r.includes('ESTABLISHED,RELATED')));
  assert.equal(output.at(-1),'-j DROP');
});
test('combo runtime refuses ambiguous endpoints, scope, listener, key and LAN contracts',()=>{
  assert.throws(()=>runtimePlan(config('client')),/explicit_lan/);
  for(const change of [c=>c.boring.port++,c=>c.transparent.role='exit',c=>c.transparent.exit.ipv4='198.18.0.3',
    c=>c.transparent.listen.port=1053,c=>c.transparent.listen.ipv4='127.0.0.1',
    c=>c.boring.secret_path=c.transparent.secret_path,c=>c.boring.sni='other.example',
    c=>c.transparent.destination_policy.deny_ipv4=['1.2.3.4/24'],
    c=>c.transparent.destination_policy.mode='all',c=>c.unknown=true]){
    const c=config('client');change(c);assert.throws(()=>runtimePlan(c,options));
  }
  const exit=config('exit');exit.transparent.listen.port++;assert.throws(()=>runtimePlan(exit));
});

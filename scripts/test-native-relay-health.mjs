import test from 'node:test';
import assert from 'node:assert/strict';
import {validateRelayHealth} from './lib/native-relay-health.mjs';
import {runtimePlan,restoreTable} from './lib/native-runtime-plan.mjs';
const relay={version:1,transport:'transparent-tls',role:'client',public_name:'relay.example',secret_path:'/config/relay.psk',
  listen:{ipv4:'0.0.0.0',port:10443},exit:{ipv4:'10.77.0.2',port:3443},destination_policy:{mode:'public-https',deny_ipv4:['12.0.0.0/8']}};
const health={version:1,ipv4:'11.22.33.44',server_name:'origin.test',path:'/health',ca:null,sha256:'0'.repeat(64)};
const config={version:1,transport:'combo-tls',role:'client',transparent:relay,
  boring:{version:1,role:'client',tun:'cvpn0',dns:true,address:'10.77.0.2',port:3443,sni:'relay.example',secret_path:'/config/packet.psk'}};
test('health target is explicit public IPv4 and cannot bypass destination policy or inject configuration',()=>{
  validateRelayHealth(health,relay);
  for(const patch of [{ipv4:'127.0.0.1'},{ipv4:'10.77.0.2'},{ipv4:'12.1.2.3'},{ipv4:'example.com'},
    {server_name:'evil\r\nX:1'},{path:'/\r\n'},{sha256:'bad'},{ca:'/etc/passwd'},{unknown:1}])assert.throws(()=>validateRelayHealth({...health,...patch},relay));
});
test('local health redirect is narrowly scoped and missing redirect cannot fall back to packet or direct output',()=>{
  const p=runtimePlan(config,{lan:{interface:'eth1',subnet:'192.168.88.0/24'},relayHealth:health});
  const output=p.tables.find(t=>t.family===4&&t.name==='filter').entries.find(e=>e.hook==='OUTPUT').rules;
  assert.equal(output[0],'-s 10.99.0.2/32 -d 127.0.0.1/32 -p tcp --dport 10443 -m conntrack --ctstate DNAT -j ACCEPT');
  assert.equal(output[1],'-s 10.99.0.2/32 -d 11.22.33.44/32 -p tcp --dport 443 -j DROP');
  assert.ok(output.findIndex(r=>r.includes('-o cvpn0'))>1);
  const nat=restoreTable(p.tables.find(t=>t.name==='nat'));
  assert.ok(nat.includes('-s 10.99.0.2/32 -d 11.22.33.44/32 -p tcp --dport 443 -j REDIRECT --to-ports 10443'));
  assert.throws(()=>runtimePlan(config.boring,{relayHealth:health}),/combo_only/);
});

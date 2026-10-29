import test from 'node:test';
import assert from 'node:assert/strict';
import {exitAdminPlan} from '../lib/exit-install.mjs';
const registry={configPath:'/opt/vpn/config.json',management:{engine:'/opt/vpn/engine',unit:'native-exit.service'}};
test('exit admin plan binds only loopback and does not alter VPN or USB units',()=>{
 const p=exitAdminPlan({name:'test'},registry);assert.equal(p.web.address,'127.0.0.1');assert.equal(p.web.loopbackProxy,true);assert.equal(p.broker.publishMdns,false);assert.equal(p.broker.clientsDirectory,'/var/lib/clean-vpn/clients');assert.equal(p.networkSettingsChanged,false);assert.deepEqual(Object.keys(p.units).sort(),['meshpn-exit-test-broker.service','meshpn-exit-test-web.service']);
 for(const text of Object.values(p.units)){assert.ok(!text.includes('ExecStartPre=')&&!text.includes('iptables')&&!text.includes('avahi'));assert.match(text,/ProtectSystem=strict/);}
 assert.match(p.units[p.webUnit],/User=cvweb-test/);assert.match(p.units[p.webUnit],/CapabilityBoundingSet=\n/);assert.ok(!p.units[p.webUnit].includes('/opt/vpn'));assert.ok(!p.units[p.brokerUnit].includes('CAP_SYS_ADMIN'));
});
test('reject unit/path injection, privileged or colliding service ports',()=>{
 for(const opts of [{name:'../bad'},{directory:'/tmp/a b'},{directory:'/'},{port:80},{port:2222},{port:18843},{capturePort:NaN}])assert.throws(()=>exitAdminPlan(opts,registry));
 assert.throws(()=>exitAdminPlan({}, {...registry,management:{...registry.management,unit:'x.service\nExecStart=evil'}}));
 assert.throws(()=>exitAdminPlan({}, {...registry,configPath:'/config.json'}));
});
test('combo broker can initialize distinct relay replay journals in external owned directory',()=>{
 const p=exitAdminPlan({},registry,{transport:'combo-tls',transparent:{replay_directory:'/var/lib/vpn/replay'}});
 assert.match(p.units[p.brokerUnit],/ReadWritePaths=.* \/var\/lib\/vpn\/replay\n/);
 for(const replay_directory of ['/','/tmp/bad path','/tmp/../var'])assert.throws(()=>exitAdminPlan({},registry,{transport:'combo-tls',transparent:{replay_directory}}));
});

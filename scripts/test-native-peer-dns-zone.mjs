#!/usr/bin/env node
import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { peerDnsZoneOperation, peerDnsZoneConfig, validatePeerDnsZoneRecord } from './lib/native-peer-dns-zone.mjs';
import { peerDnsZoneUnit } from './clean-vpn-native-peer-dns-zone.mjs';
const linuxRoot = process.platform === 'linux' && process.getuid() === 0;
function fixture() {
 const directory=fs.mkdtempSync('/tmp/cvpn-zone-unit-'); fs.chmodSync(directory,0o700);
 const state={context:{boot:'01234567-1234-1234-1234-012345678901',net:'net:[123]',owner:':1.2'},link:null,dns:{DNSEx:[],Domains:[],DefaultRoute:true},sets:0,collision:false,addressCollision:false};
 const backend={context:async()=>({...state.context}),link:async()=>structuredClone(state.link),dns:async()=>structuredClone(state.dns),
 assertForeignDomains:async()=>assert.ok(!state.collision,'foreign'),assertAddressAvailable:async()=>assert.ok(!state.addressCollision,'address'),
 create:async r=>{state.link={index:8,name:r.name,mac:r.mac,kind:'dummy',mtu:1500,master:null,alias:'',addresses:[],up:false};},
 stamp:async r=>{state.link.alias='clean-vpn-mpn:'+r.id;},address:async r=>{state.link.addresses=['inet:'+r.config.address+'/32'];},up:async()=>{state.link.up=true;},
 set:async(_o,_i,k,v)=>{state.dns[k]=v;state.sets++;},remove:async()=>{state.link=null;}};
 return {state,directory,op:args=>peerDnsZoneOperation({directory,backend,...args}),cleanup:()=>fs.rmSync(directory,{recursive:true,force:true})};
}
test('zone config and generated unit are bounded and own only one state directory',()=>{assert.throws(()=>peerDnsZoneConfig({address:'127.0.0.1'}));assert.throws(()=>peerDnsZoneConfig({port:53}));assert.throws(()=>validatePeerDnsZoneRecord({})); const unit=peerDnsZoneUnit({directory:'/var/lib/cvpn-zone',node:'/usr/bin/node',script:'/opt/zone.mjs'});assert.match(unit,/ReadWritePaths=\/var\/lib\/cvpn-zone\n/);assert.doesNotMatch(unit,/ExecStopPost|resolv.conf/);});
for(const point of ['intent','created','stamped','addressed','up','set-DefaultRoute','set-DNSEx','set-Domains','active']) test('recovers after '+point,{skip:!linuxRoot},async()=>{const f=fixture();try{await assert.rejects(f.op({checkpoint:p=>{if(p===point)throw Error('crash');}}),/crash/);assert.equal((await f.op({})).status,'active');assert.equal((await f.op({operation:'status'})).status,'active');assert.equal((await f.op({operation:'remove'})).status,'removed');assert.equal(f.state.link,null);}finally{f.cleanup();}});
test('repeat apply is read-only and backend restart reset is repaired',{skip:!linuxRoot},async()=>{const f=fixture();try{await f.op({});const s=fs.statSync(f.directory+'/zone.json').mtimeMs,sets=f.state.sets;await f.op({});assert.equal(fs.statSync(f.directory+'/zone.json').mtimeMs,s);assert.equal(f.state.sets,sets);f.state.context.owner=':1.3';f.state.dns={DNSEx:[],Domains:[],DefaultRoute:true};await f.op({});assert.ok(f.state.sets>sets);}finally{f.cleanup();}});
test('foreign DNS changes, alias changes, reused ifindex and partial removal refuse',{skip:!linuxRoot},async()=>{for(const change of [f=>f.state.link.alias='foreign',f=>f.state.link.index=9,f=>f.state.dns.Domains=[],f=>f.state.dns.DNSEx=[[2,[1,1,1,1],53,'']]]){const f=fixture();try{await f.op({});change(f);await assert.rejects(f.op({}));await assert.rejects(f.op({operation:'remove'}));assert.ok(f.state.link);}finally{f.cleanup();}}});
test('foreign domains and address conflicts fail before intent or creation',{skip:!linuxRoot},async()=>{for(const flag of ['collision','addressCollision']){const f=fixture();try{f.state[flag]=true;await assert.rejects(f.op({}));assert.equal(f.state.link,null);assert.equal(fs.existsSync(f.directory+'/zone.json'),false);}finally{f.cleanup();}}});
test('namespace changes and corrupted journal never remove link',{skip:!linuxRoot},async()=>{const f=fixture();try{await f.op({});f.state.context.net='net:[456]';await assert.rejects(f.op({operation:'remove'}));fs.writeFileSync(f.directory+'/zone.json','{');await assert.rejects(f.op({operation:'remove'}));assert.ok(f.state.link);}finally{f.cleanup();}});
test('stale boot status preserves journal and remove cleans only absent old link',{skip:!linuxRoot},async()=>{const f=fixture();try{await f.op({});f.state.context.boot='11234567-1234-1234-1234-012345678901';await assert.rejects(f.op({operation:'remove'}));f.state.link=null;assert.equal((await f.op({operation:'status'})).status,'stale');assert.ok(fs.existsSync(f.directory+'/zone.json'));assert.equal((await f.op({operation:'remove'})).status,'removed');}finally{f.cleanup();}});

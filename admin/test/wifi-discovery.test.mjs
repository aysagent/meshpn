import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {Wifi} from '../lib/wifi.mjs';
import {wifiScanNetworks} from '../lib/wifi-scan.mjs';

test('saved names stay selectable when hidden or absent, without guessing anonymous BSSID identities',()=>{
 const saved=[{id:'one',ssid:'iPhone (Андрей)',priority:10,security:'wpa2',psk:'NEVER-EXPOSE'},
  {id:'two',ssid:'Visible',priority:0,security:'open'},
  {id:'three',ssid:'Absent',priority:0,security:'wpa2'}];
 const scan='bssid / frequency / signal level / flags / ssid\n'+
  '00:11:22:33:44:55\t2437\t-42\t[WPA2-PSK-CCMP][ESS]\t\n'+
  '00:11:22:33:44:56\t2437\t-44\t[ESS]\tVisible\n';
 const rows=wifiScanNetworks(scan,saved);
 assert.equal(rows.length,3);
 const hidden=rows.find(x=>x.savedId==='one');
 assert.deepEqual(hidden,{ssid:'iPhone (Андрей)',security:'wpa2',savedId:'one',source:'saved',observed:false,signal:null,frequency:null,bssid:null});
 assert.equal(rows.find(x=>x.savedId==='two').observed,true);
 assert.equal(rows.find(x=>x.savedId==='three').observed,false);
 assert(!JSON.stringify(rows).includes('NEVER-EXPOSE'));
 assert(!JSON.stringify(rows).includes('00:11:22:33:44:55'));
 assert.deepEqual(wifiScanNetworks('header\n',[]),[]);
});

test('restart upgrades existing profiles to directed scans; daemon loss restores them without enabling disabled or foreign networks',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-wifi-discovery-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=path.join(dir,'wifi.json'),calls=[],networks=new Map();let next=1;
 const run=async(_file,args,options={})=>{
  const cmd=args.slice(2);calls.push({cmd,input:options.input});
  if(cmd[0]==='list_networks')return{out:'network id / ssid / bssid / flags\n0\tforeign\tany\t[CURRENT]\n'+[...networks.keys()].map(n=>n+'\tsaved\tany\t\n').join('')};
  if(cmd[0]==='get_network')return{out:cmd[2]==='id_str'?networks.get(cmd[1])?.tag??'"foreign"':'0'};
  if(cmd[0]==='add_network'){const n=String(next++);networks.set(n,{});return{out:n};}
  if(!cmd.length){
   const tag=options.input.match(/set_network (\d+) id_str "([^"]+)"/);
   networks.get(tag[1]).tag='"'+tag[2]+'"';return{out:'OK\n'};
  }
  return{out:'OK\n'};
 };
 const first=new Wifi({file,interface:'wlan0',run});
 first.save({ssid:'Visible then hidden',security:'wpa2',password:'test-password',priority:0,enabled:true,hidden:false});
 first.save({ssid:'Higher priority',security:'open',priority:10,enabled:true,hidden:false});
 first.save({ssid:'Disabled',security:'open',priority:-10,enabled:false,hidden:false});
 await first.sync();
 assert(calls.filter(x=>x.input).every(x=>x.input.includes('scan_ssid 1\n')));
 assert(calls.find(x=>x.input).input.includes(Buffer.from('Higher priority').toString('hex')));
 const restarted=new Wifi({file,interface:'wlan0',run});calls.length=0;
 await restarted.restore(); // Existing owned profiles must be migrated on broker upgrade.
 assert.equal(calls.filter(x=>x.input).length,3);
 assert(!calls.some(x=>x.cmd[0]==='enable_network'&&x.cmd[1]==='0'));
 assert(calls.some(x=>x.cmd[0]==='disable_network'));
 calls.length=0;await restarted.restore();
 assert(!calls.some(x=>x.input||x.cmd[0]==='enable_network')); // No periodic reconnect loop.
 networks.clear();calls.length=0;await restarted.restore();
 assert.equal(calls.filter(x=>x.input).length,3);
 assert(!calls.some(x=>x.cmd.includes('remove_network')));
});

test('system catalog is read-only and summaries separate a connection from last observed SSIDs',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-wifi-system-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const calls=[];let ownedId;
 const run=async(_file,args)=>{
  const cmd=args.slice(2);calls.push(cmd);
  if(cmd[0]==='list_networks')return{out:'network id / ssid / bssid / flags\n0\tHome router\tany\t\n1\tGuests\tany\t[DISABLED]\n7\tPhone\tany\t[CURRENT]\n'};
  if(cmd[0]==='get_network'){assert.equal(cmd[2],'id_str');return{out:cmd[1]==='7'?'"mpn-admin-'+ownedId+'"':'"foreign"'};}
  if(cmd[0]==='status')return{out:'wpa_state=COMPLETED\nssid=Phone\nid=7\nip_address=192.0.2.8\n'};
  if(cmd[0]==='scan_results')return{out:'bssid / frequency / signal level / flags / ssid\n00:11:22:33:44:55\t2412\t-43\t[ESS]\tHome router\n'};
  throw Error('unexpected command');
 };
 const wifi=new Wifi({file:dir+'/profiles.json',interface:'wlan0',run});
 wifi.save({ssid:'Phone',security:'wpa2',password:'do-not-export',priority:5,enabled:true,hidden:false});ownedId=wifi.list()[0].id;
 const catalog=await wifi.catalog();assert.equal(catalog.length,3);
 assert.equal(catalog[0].source,'admin');assert.equal(catalog[0].readOnly,false);
 assert.deepEqual(catalog.find(p=>p.ssid==='Home router'),{id:'system-0',networkId:'0',ssid:'Home router',priority:null,enabled:true,source:'system',readOnly:true});
 assert.equal(catalog.find(p=>p.ssid==='Guests').enabled,false);
 assert(!JSON.stringify(catalog).includes('do-not-export'));assert(!JSON.stringify(catalog).includes('psk'));
 const summary=await wifi.summary();assert.equal(summary.profileId,ownedId);assert.equal(summary.ssid,'Phone');
 assert.deepEqual(summary.observedSsids,['Home router']);
 assert(calls.every(c=>['list_networks','get_network','status','scan_results'].includes(c[0])));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pbkdf2Sync} from 'node:crypto';
import {Wifi} from '../lib/wifi.mjs';
import {decodeWifiSsid,validWifiSsid} from '../lib/wifi-ssid.mjs';

const name='iPhone (Андрей) (2)';
const escaped=String.raw`iPhone (\xd0\x90\xd0\xbd\xd0\xb4\xd1\x80\xd0\xb5\xd0\xb9) (2)`;
test('decode supplicant UTF-8 bytes once, preserving quotes, backslashes and spaces',()=>{
 assert.equal(decodeWifiSsid(escaped),name);
 assert.equal(Buffer.byteLength(name),25);
 assert.equal(decodeWifiSsid('a \\"quoted\\" \\\\x41 '),'a "quoted" \\x41 ');
 assert.equal(decodeWifiSsid(' trailing '),' trailing ');
 assert.equal(decodeWifiSsid('\\xef\\xbb\\xbfnetwork'),'\ufeffnetwork');
 assert.equal(decodeWifiSsid('a'.repeat(32)),'a'.repeat(32));
});
test('unsupported SSIDs are never silently changed to replacement bytes',()=>{
 for(const value of ['', 'a'.repeat(33),'\\xff','\\xc0\\xaf','\\xd0','a\\x00b','a\\nb','a\\tb','a\\rb','a\\eb','\\x7f','\\x1','\\xzz','\\q','a\\'])assert.equal(decodeWifiSsid(value),null,value);
 assert.equal(validWifiSsid('я'.repeat(16)),true);
 assert.equal(validWifiSsid('я'.repeat(17)),false);
 assert.equal(validWifiSsid('\ud800'),false);
});
test('scan -> save -> persisted profile -> WPA PSK and hex SSID use original UTF-8 bytes',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-wifi-ssid-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const calls=[];
 const run=async(file,args,options={})=>{
  calls.push({file,args,options});
  switch(args[2]){
   case 'scan':return{out:'OK\n'};
   case 'scan_results':return{out:'bssid / frequency / signal level / flags / ssid\n'+
    '00:11:22:33:44:55\t2412\t-45\t[WPA2-PSK-CCMP][ESS]\t'+escaped+'\n'+
    '00:11:22:33:44:56\t2412\t-50\t[ESS]\t\\xff\n'+
    '00:11:22:33:44:57\t2412\t-51\t[ESS]\t trailing \n'};
   case 'status':return{out:'wpa_state=COMPLETED\nssid='+escaped+'\nid=7\n'};
   case 'list_networks':return{out:'network id / ssid / bssid / flags\n'};
   case 'add_network':return{out:'7\n'};
   default:return{out:'OK\n'};
  }
 };
 const wifi=new Wifi({file:dir+'/profiles.json',interface:'wlan0',run});
 const scan=await wifi.scan();assert.deepEqual(scan.map(x=>x.ssid),[name,' trailing ']);
 assert.equal((await wifi.status()).ssid,name);
 wifi.save({ssid:scan[0].ssid,password:'test-password',security:'wpa2',priority:0,enabled:false,hidden:false});
 const reloaded=new Wifi({file:dir+'/profiles.json',interface:'wlan0',run});
 assert.equal(reloaded.list()[0].ssid,name);
 await reloaded.sync();
 const input=calls.find(x=>x.options.input)?.options.input;
 assert(input.includes('set_network 7 ssid '+Buffer.from(name).toString('hex')+'\n'));
 const psk=pbkdf2Sync('test-password',Buffer.from(name),4096,32,'sha1').toString('hex');
 assert(input.includes('set_network 7 psk '+psk+'\n'));
 assert(!JSON.stringify(calls.map(x=>x.args)).includes(psk));
 assert(!JSON.stringify(reloaded.list()).includes(psk));
 wifi.save({ssid:'literal\\x41',security:'open',priority:0,enabled:false,hidden:false});
 assert.equal(wifi.list()[1].ssid,'literal\\x41');
 assert.throws(()=>wifi.save({ssid:escaped,security:'open',priority:0,enabled:false,hidden:false}),/wifi_ssid/);
});

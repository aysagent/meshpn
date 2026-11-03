#!/usr/bin/env node
// Offline export of one runtime client; no service or network changes.
import fs from 'node:fs';
import path from 'node:path';
import {parseArgs} from 'node:util';
import {readClientPrivate} from './lib/native-client-manager.mjs';
const {values:o}=parseArgs({options:Object.fromEntries(['directory','client','output','clock-host-key'].map(k=>[k,{type:'string'}]))});
if(!path.isAbsolute(o.directory??'')||!path.isAbsolute(o.output??'')||!/^client-[1-9][0-9]*$/.test(o.client??''))throw Error('export_arguments');
const dir=o.directory+'/'+o.client,config=JSON.parse(readClientPrivate(dir+'/engine.json')),p=config.transport==='combo-tls'?config.boring:config;
if(config.role!=='client'||p.role!=='client')throw Error('client_config_required');
const files={};p.tun='tun0';
for(const [obj,key,file]of [[p,'ca','ca.pem'],[p,'secret_path','psk'],[p,'tls_profile_path','profile.json'],...(config.transport==='combo-tls'?[[config.transparent,'secret_path','relay.psk']]:[])]){
 if(!['/config/'+file,dir+'/'+file].includes(obj[key]))throw Error('unexpected_client_path');
 files[file]=readClientPrivate(dir+'/'+file).toString('base64');obj[key]='@bundle/'+file;
}
let clock;
if(o['clock-host-key']){
 const pub=fs.readFileSync(o['clock-host-key'],'utf8').trim().split(/\s+/);if(pub[0]!=='ssh-ed25519'||pub.length<2)throw Error('ed25519_host_key_required');
 clock={host:p.address,port:22,user:'cvpn-clock',identity:readClientPrivate(dir+'/clock-identity').toString('base64'),known_hosts:Buffer.from('clean-vpn-clock '+pub.slice(0,2).join(' ')+'\n').toString('base64')};
}
const enrollment={version:1,kind:'clean-vpn-client-enrollment',name:o.client,hostname:o.client+'.mpn',ipv4:p.peer_ipv4,config,files};
fs.writeFileSync(o.output,JSON.stringify({version:1,kind:'clean-vpn-install-bundle',enrollment,...(clock?{clock}:{})})+'\n',{mode:0o600,flag:'wx'});
console.log(JSON.stringify({status:'exported',client:o.client,output:o.output,clock:!!clock,secretsPrinted:false}));

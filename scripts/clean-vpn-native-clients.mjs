#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
import {NativeClientManager,importClientBundle,readClientPrivate,writeClientPrivate} from './lib/native-client-manager.mjs';
import {nativeClientService} from './lib/native-client-service.mjs';
import {prepareNativeClientManifest} from './lib/native-client-bundles.mjs';
export {planNativeClients,prepareNativeClients} from './lib/native-client-bundles.mjs';
export async function main(args){
 if(args.some(a=>a.startsWith('--manifest=')))return prepareNativeClientManifest(args);
 if(args.length===0||args.includes('--help'))return{usage:'node scripts/clean-vpn-native-clients.mjs init|list|add NAME|rename NAME NEW_NAME|revoke NAME|rotate NAME|export NAME|recover|import --directory=/PRIVATE/STATE --engine=/ABS/ENGINE [--unit=exit.service | --offline] [--config=/EXIT/config.json --endpoint=IP --server-name=DNS --ca=/CA.pem --profile=/PROFILE.json] [--output=/NEW/client.bundle [--address-discovery] | --bundle=/client.bundle]',notes:'init imports existing keys without rotation. add allocates a stable IP. Mutations require --unit (hot reload) or explicit --offline. export never prints keys; import writes a new private directory and does not activate networking. Existing clients use names client-2, client-3, etc; rename them as desired.'};
 const [action,...rest]=args,options={},position=[];for(const a of rest){if(!a.startsWith('--')){position.push(a);continue;}if(['--offline','--address-discovery'].includes(a)){assert.ok(!Object.hasOwn(options,a.slice(2)),'client_option');options[a.slice(2)]=true;continue;}const m=a.match(/^--([a-z-]+)=(.+)$/);assert.ok(m&&!Object.hasOwn(options,m[1]),'client_option');options[m[1]]=m[2];}
 for(const key of ['offline','address-discovery'])assert.ok(options[key]===undefined||options[key]===true,'client_boolean_option');
 const allowed=['directory','engine','unit','offline','config','endpoint','server-name','ca','profile','output','bundle','relay-map','address-discovery'];assert.ok(!options['address-discovery']||action==='export','client_address_discovery_export_only');assert.ok(Object.keys(options).every(k=>allowed.includes(k)),'client_option');
 assert.ok(['init','list','add','rename','revoke','rotate','export','recover','import'].includes(action),'client_action');
 const expected=['add','revoke','rotate','export'].includes(action)?1:action==='rename'?2:0;assert.equal(position.length,expected,'client_arguments');options.directory??='/var/lib/clean-vpn/clients';assert.ok(path.isAbsolute(options.directory),'client_directory');assert.ok(!(options.offline&&options.unit),'client_apply_mode');
 if(!['init','import'].includes(action)){
  const saved=JSON.parse(readClientPrivate(options.directory+'/registry.json')).management;
  options.engine??=saved?.engine;if(!options.offline)options.unit??=saved?.unit;
 }
 if(['add','rename','revoke','rotate','recover'].includes(action))assert.ok(options.unit||options.offline,'client_choose_unit_or_offline');
 const service=nativeClientService({engine:options.engine,unit:options.unit,directory:options.directory});if(action==='init')await service.preflight();
 const manager=new NativeClientManager({directory:options.directory,...service});
 if(action==='init')return manager.init({configPath:options.config,endpoint:options.endpoint,serverName:options['server-name'],caPath:options.ca,profilePath:options.profile,relayMap:options['relay-map']?JSON.parse(readClientPrivate(options['relay-map'])):undefined,management:{engine:options.engine,...(options.unit?{unit:options.unit}:{})}});
 if(action==='export'){assert.ok(options.output&&path.isAbsolute(options.output),'client_output');const bundle=await manager.export(position[0],{addressDiscovery:options['address-discovery']===true});writeClientPrivate(options.output,Buffer.from(JSON.stringify(bundle,null,2)+'\n'));return{exported:true,name:position[0],output:options.output,containsCredentials:true};}
 if(action==='import'){const b=JSON.parse(readClientPrivate(options.bundle,262144));return importClientBundle(b,options.directory,service);}
 return manager[action](...position);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main(process.argv.slice(2)).then(v=>console.log(JSON.stringify(v,null,2))).catch(e=>{console.error('NATIVE_CLIENTS=failed: '+(/^[a-z0-9_]+$/.test(e.message)?e.message:e.code??'operation_failed'));process.exitCode=1;});

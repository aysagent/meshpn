#!/usr/bin/env node
// Offline stdout renderer: never writes /etc, enables or starts services.
import { parseArgs } from 'node:util';
import assert from 'node:assert/strict';
import { runtimeEngineUnit, runtimeGatewayUnit } from './lib/native-runtime-units.mjs';
try {
  const {values:v}=parseArgs({options:{help:{type:'boolean'},...Object.fromEntries(['kind','namespace','parent-netns','scripts','node','config','engine','instance','lan-subnet','seconds'].map(k=>[k,{type:'string'}]))}});
  if(v.help)console.log('Usage: node scripts/clean-vpn-native-runtime-unit.mjs --kind=engine|gateway --namespace=NAME --parent-netns=net:[NUMBER] --scripts=/TARGET/repo/scripts --node=/usr/bin/node --config=/TARGET/engine-or-gateway.json [--engine=/TARGET/clean-vpn-engine --instance=NAME --lan-subnet=192.168.88.0/24] [--seconds=300]\nRenders a unit to stdout. Pre-existing dedicated Linux netns required. No installation/enable/start. Gateway is a bounded trial: stop/expiry/controller-crash explicitly restores its baseline; engine failure alone keeps gateway guards.');
  else {
    const flags=process.argv.slice(2).filter(a=>a.startsWith('--')).map(a=>a.split('=')[0]);assert.equal(flags.length,new Set(flags).size);
    assert.ok(['engine','gateway'].includes(v.kind));
    const o={namespace:v.namespace,parent:v['parent-netns'],scripts:v.scripts,node:v.node,config:v.config};
    if(v.kind==='engine'){
      assert.equal(v.seconds,undefined);process.stdout.write(runtimeEngineUnit({...o,engine:v.engine,instance:v.instance,lanSubnet:v['lan-subnet']}));
    }else{
      for(const k of ['engine','instance','lan-subnet'])assert.equal(v[k],undefined);
      process.stdout.write(runtimeGatewayUnit({...o,seconds:Number(v.seconds??300)}));
    }
  }
}catch(e){console.error('NATIVE_UNIT_RENDER=failed: '+e.message);process.exitCode=1;}

#!/usr/bin/env node
// Offline stdout only: no /etc writes, enable, start, time or network changes.
import {parseArgs} from 'node:util';
import assert from 'node:assert/strict';
import {nativeServiceUnit} from './lib/native-service-unit.mjs';
import {nativeClockRecoveryUnit} from './lib/native-clock-unit.mjs';
try{
  const {values:v}=parseArgs({options:Object.fromEntries(['kind','binary','config','network-unit','guard-unit','recovery-unit','consumer-unit','script','state-directory','namespace'].map(k=>[k,{type:'string'}]))});
  const flags=process.argv.slice(2).filter(x=>x.startsWith('--')).map(x=>x.split('=')[0]);assert.equal(flags.length,new Set(flags).size,'duplicate_option');
  if(v.kind==='consumer'){
    for(const key of ['consumer-unit','script','state-directory','namespace'])assert.equal(v[key],undefined,'unexpected_option');
    assert.ok(v['recovery-unit'],'recovery_unit_required');
    process.stdout.write(nativeServiceUnit({binary:v.binary,config:v.config,networkUnit:v['network-unit'],guardUnit:v['guard-unit'],role:'client',clockRecoveryUnit:v['recovery-unit']}));
  }else{
    assert.equal(v.kind,'recovery','kind_consumer_or_recovery_required');
    for(const key of ['binary','network-unit','guard-unit','recovery-unit'])assert.equal(v[key],undefined,'unexpected_option');
    process.stdout.write(nativeClockRecoveryUnit({consumerUnit:v['consumer-unit'],script:v.script,config:v.config,stateDirectory:v['state-directory'],namespace:v.namespace}));
  }
}catch(e){console.error('NATIVE_CLOCK_UNIT=refused: '+e.message);process.exitCode=1;}

import test from 'node:test';
import assert from 'node:assert/strict';
import {projectEngineDiagnostics,publicEngineDiagnostics,createJournalDiagnostics} from '../lib/engine-diagnostics.mjs';
import {diagnosticExport} from '../lib/diagnostics.mjs';
import {validNativeDiagnostics} from '../../scripts/lib/native-engine-diagnostics.mjs';
const event=()=>({version:1,event:'diagnostics',diagnostics:{schema:1,scope:'process-lifetime-sampled',
 packet:{ready_events:2,session_ends:1,last_end:{code:'h2_ping_timeout',monotonic_ms:500}},
 relay:{accepted:4,completed:2,failed:1,pending:1,active:2,broken:false,failures_by_phase:{authorization:1},last_failure:{code:'relay_token_auth',phase:'authorization',monotonic_ms:505}},
 dns:{queries:9,answers:8,servfail:1,upstream_timeouts:1}}});
test('native projection preserves separate packet, relay phase and DNS counters',()=>{
 const result=projectEngineDiagnostics(event());assert.equal(result.packet.lastEnd.code,'h2_ping_timeout');
 assert.equal(result.relay.lastFailure.phase,'authorization');assert.equal(result.relay.failuresByPhase.authorization,1);assert.equal(result.dns.upstream_timeouts,1);
 assert.equal(result.relay.active,2);assert.equal(result.relay.broken,false);
 for(const v of [null,{}, {...event(),version:2},{...event(),event:'state'}])assert.equal(projectEngineDiagnostics(v),null);
});
test('unknown reason, arbitrary metadata and unsafe counters cannot enter UI or exported diagnostic',()=>{
 const secret='SECRET-NO-EXPORT',e=event();e.diagnostics.secret=secret;e.diagnostics.packet.last_end.code=secret;
 e.diagnostics.relay.last_failure.code='relay_secret_no_export';e.diagnostics.relay.failures_by_phase.secret=secret;e.diagnostics.relay.accepted=-1;e.diagnostics.relay.active=Number.MAX_SAFE_INTEGER+1;e.diagnostics.dns.name=secret;
 const projected=projectEngineDiagnostics(e);assert.equal(projected.packet.lastEnd.code,'packet_failure');assert.equal(projected.relay.lastFailure.code,'relay_internal');
 assert.equal(projected.relay.accepted,undefined);assert.equal(projected.relay.active,undefined);assert(!JSON.stringify(projected).includes(secret));
 const published={...projected,status:'sampled',ageMs:100,secret,relay:{...projected.relay,secret,lastFailure:{code:secret,phase:'authorization',monotonicMs:50}}};
 const exported=diagnosticExport({engineDiagnostics:published});assert(!JSON.stringify(exported).includes(secret));assert.equal(exported.engineDiagnostics.relay.lastFailure.code,'relay_internal');
 assert.deepEqual(publicEngineDiagnostics(),{status:'unavailable'});
});
test('journal samples bind to current invocation and PID; cache expires and never survives restart',async()=>{
 let now=300000,calls=0;const invocation='a'.repeat(32),state={MainPID:'123',InvocationID:invocation};
 const entry=(overrides={})=>JSON.stringify({_PID:'123',_SYSTEMD_INVOCATION_ID:invocation,__REALTIME_TIMESTAMP:String((now-100)*1000),MESSAGE:JSON.stringify(event()),...overrides});
 let out=entry()+'\n'+entry({_PID:'999',MESSAGE:'private stale record'});
 const read=createJournalDiagnostics(async(file,args)=>{calls++;assert.equal(file,'/usr/bin/journalctl');assert(args.includes('_SYSTEMD_INVOCATION_ID='+state.InvocationID));return{out};},{now:()=>now});
 assert.equal((await read('native-test.service',state)).status,'sampled');assert.equal(calls,1);
 await read('native-test.service',state);assert.equal(calls,1);now+=5001;
 out=entry({__REALTIME_TIMESTAMP:'1000'});assert.equal((await read('native-test.service',state)).status,'stale');
 state.InvocationID='b'.repeat(32);assert.equal((await read('native-test.service',state)).status,'unavailable');assert.equal(calls,3);state.MainPID='456';assert.equal((await read('native-test.service',state)).status,'unavailable');assert.equal(calls,4);
 assert.deepEqual(await read('native-test.service',{MainPID:'0'}),{status:'stopped'});
 assert.equal((await read('bad;unit',state)).status,'stopped');
});
test('control validator rejects extra fields, unknown codes and malformed nested counters',()=>{
 const e={version:1,event:'diagnostics',state:'ready',generation:0,tx_packets:1,rx_packets:1,dropped_packets:0,
  diagnostics:{schema:1,scope:'process-lifetime-sampled',packet:{ready_events:1,session_ends:1,last_end:{code:'h2_ping_timeout',monotonic_ms:100}}}};
 assert.equal(validNativeDiagnostics(e),true);
 for(const mutate of [x=>x.payload='PRIVATE',x=>x.diagnostics.extra='PRIVATE',x=>x.diagnostics.packet.last_end.code='private_secret',x=>x.diagnostics.packet.ready_events=-1,x=>x.diagnostics.packet=null,x=>x.diagnostics.relay=null,x=>x.diagnostics.packet.last_end.secret='PRIVATE']){
  const x=structuredClone(e);mutate(x);assert.equal(validNativeDiagnostics(x),false);
 }
});

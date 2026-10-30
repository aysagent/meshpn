import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {ContainerEngine} from './clean-vpn-container-broker.mjs';
test('container diagnostics use projected current child stdout and reset on restart',async()=>{
 let pid=100,child;
 const engine=new ContainerEngine({config:'/config/test.json',engine:'/native',runtime:'/runtime',health:'/health'},{run:async()=>({out:''}),start:()=>{
  child=new EventEmitter();child.pid=pid++;child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{queueMicrotask(()=>child.emit('close',0));return true;};
  queueMicrotask(()=>child.stdout.write(JSON.stringify({event:'state',state:'ready'})+'\n'));return child;
 }});
 try{
  await engine.start();assert.equal(engine.engineDiagnostics,null);
  const raw=JSON.stringify({version:1,event:'diagnostics',diagnostics:{schema:1,scope:'process-lifetime-sampled',secret:'HIDDEN',dns:{queries:3,upstream_timeouts:1,password:'HIDDEN'}}});
  child.stdout.write(raw.slice(0,30));assert.equal(engine.engineDiagnostics,null);child.stdout.write(raw.slice(30)+'\n');
  assert.equal(engine.engineDiagnostics.dns.upstream_timeouts,1);assert(!JSON.stringify(engine.engineDiagnostics).includes('HIDDEN'));assert(engine.diagnosticsAt>0);
  const first=child.pid;await engine.restart();assert.notEqual(child.pid,first);assert.equal(engine.engineDiagnostics,null);assert.equal(engine.diagnosticsAt,0);
 }finally{await engine.close();}
});

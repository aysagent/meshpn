import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

function fixture(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-build-mode-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  fs.mkdirSync(path.join(dir,'scripts'));fs.mkdirSync(path.join(dir,'bin'));
  fs.copyFileSync(new URL('./build-clean-vpn-native.sh',import.meta.url),path.join(dir,'scripts/build.sh'));
  // Argument/failure tests do not exercise OS locking. Keep them runnable on
  // macOS; the actual Linux operation lock is tested by the trial suite.
  fs.writeFileSync(path.join(dir,'bin/flock'),'#!/bin/sh\nexit 0\n',{mode:0o755});
  // Log argv verbatim, allow dependency configure, then stop before compilation.
  fs.writeFileSync(path.join(dir,'bin/cmake'),`#!/bin/sh
printf '%s\\n' "$@" >> "$CVPN_BUILD_TEST_CALLS"
if [ "$1" = '-S' ] && [ "$2" = 'native/boring_tls' ]; then exit 0; fi
exit 23
`,{mode:0o755});
  const calls=path.join(dir,'calls');
  const run=args=>spawnSync('bash',[path.join(dir,'scripts/build.sh'),...args],{encoding:'utf8',timeout:5000,
    env:{...process.env,PATH:path.join(dir,'bin')+':'+process.env.PATH,CVPN_BUILD_TEST_CALLS:calls}});
  return {dir,calls,run};
}
test('low-memory flag reaches CMake; default explicitly clears it on the same checkout',t=>{
  const f=fixture(t);
  for(const [args,value] of [[['--low-memory'],'ON'],[[],'OFF']]) {
    if(fs.existsSync(f.calls))fs.unlinkSync(f.calls);
    const r=f.run(args);assert.equal(r.status,1);assert.match(r.stderr,/NATIVE_BUILD=failed/);
    const argv=fs.readFileSync(f.calls,'utf8').trim().split('\n');
    assert.ok(argv.includes('-DCVPN_LOW_MEMORY_BUILD='+value));
    assert.ok(argv.includes('-DCMAKE_BUILD_TYPE=RelWithDebInfo'));assert.ok(argv.includes('-DCVPN_SANITIZE=OFF'));
    assert.ok(!argv.includes('--build')); // Failure does not fall through.
    assert.ok(!fs.existsSync(path.join(f.dir,'native/boring_tls/build')));
    assert.match(fs.readFileSync(path.join(f.dir,'native/clean_vpn/build/radxa-build.log'),'utf8'),new RegExp('low_memory='+value));
  }
});
test('help and invalid arguments refuse before creating build directory or calling tools',t=>{
  const f=fixture(t);
  for(const args of [['--help'],['--fast'],['--low-memory','--help'],['--jobs=0'],['--jobs=9'],
    ['--jobs=2','--jobs=3'],['--jobs=02'],['--low-memory','--low-memory']]) {
    const r=f.run(args);assert.equal(r.status,args[0]==='--help'?0:2);
    assert.ok(!fs.existsSync(f.calls));assert.ok(!fs.existsSync(path.join(f.dir,'native')));
  }
});
test('explicit jobs reaches build invocation without skipping failed compilation',t=>{
  const f=fixture(t);
  fs.writeFileSync(path.join(f.dir,'bin/cmake'),`#!/bin/sh
printf '%s\\n' "$@" >> "$CVPN_BUILD_TEST_CALLS"
if [ "$1" = '-S' ]; then exit 0; fi
exit 23
`,{mode:0o755});
  for(const args of [[],['--jobs=2'],['--low-memory','--jobs=2']]) {
    if(fs.existsSync(f.calls))fs.unlinkSync(f.calls);
    const r=f.run(args);assert.equal(r.status,1);assert.match(r.stderr,/NATIVE_BUILD=failed/);
    const argv=fs.readFileSync(f.calls,'utf8').trim().split('\n');
    assert.equal(argv.at(-2),'--parallel');assert.equal(argv.at(-1),args.length?'2':'1');
    assert.ok(argv.includes('-DCVPN_LOW_MEMORY_BUILD='+(args.includes('--low-memory')?'ON':'OFF')));
  }
});

import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
test('mDNS bounded wire parser and IPv4-only negative answer',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-mdns-test-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const bin=path.join(dir,'mdns-test');
 execFileSync('cc',['-std=c11','-Wall','-Wextra','-Werror',fileURLToPath(new URL('./mdns-negative.c',import.meta.url)),'-o',bin]);
 execFileSync(bin);
});

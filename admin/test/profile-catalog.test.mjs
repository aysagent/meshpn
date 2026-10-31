import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {profileCatalog,profileImportReceipt} from '../lib/profile-catalog.mjs';
test('catalog separates configured file, native import receipt and missing runtime/browser evidence',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-profiles-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=dir+'/saved.json',profile=JSON.parse(fs.readFileSync('fixtures/native-tls-profiles/chromium-156-bounded-http.json'));
 fs.writeFileSync(file,JSON.stringify(profile));
 let [p]=profileCatalog(dir,{configuredPath:file});assert.equal(p.configured,true);assert.equal(p.validation.status,'unknown');assert.equal(p.runtimeVerified,false);assert.equal(p.browserEquivalent,false);assert.equal(p.provenance.status,'unverified');assert.equal(p.layers.http,'bounded-request-fields');assert.match(p.fileSha256,/^[a-f0-9]{64}$/);
 fs.writeFileSync(file+'.receipt',JSON.stringify(profileImportReceipt(file,0)));
 [p]=profileCatalog(dir);assert.equal(p.configured,false);assert.equal(p.validation.status,'accepted-at-import');assert.equal(p.validation.checkedAt,'1970-01-01T00:00:00.000Z');
 profile.http.user_agent='Changed/1';fs.writeFileSync(file,JSON.stringify(profile));[p]=profileCatalog(dir);assert.equal(p.validation.status,'unknown','edited profile must invalidate old receipt');
});
test('catalog skips unsafe files and malformed documents, bounds receipts, and has stable ordering',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mpn-profiles-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const p=fs.readFileSync('fixtures/native-tls-profiles/cold-h2.json');fs.writeFileSync(dir+'/z.json',p);fs.writeFileSync(dir+'/a.json',p);
 fs.symlinkSync(dir+'/a.json',dir+'/link.json');fs.mkdirSync(dir+'/directory.json');fs.writeFileSync(dir+'/oversized.json',' '.repeat(16385));fs.writeFileSync(dir+'/bad.json','{}');
 fs.symlinkSync(dir+'/a.json',dir+'/a.json.receipt');
 let rows=profileCatalog(dir);assert.deepEqual(rows.map(p=>p.id),['a.json','z.json']);assert.ok(rows.every(p=>p.validation.status==='unknown'));
 assert.throws(()=>profileImportReceipt(dir+'/link.json'));
 fs.writeFileSync(dir+'/z.json.receipt',' '.repeat(2049));rows=profileCatalog(dir);assert.equal(rows[1].validation.status,'unknown');assert.equal(rows[0].layers.http,'native-defaults');
});

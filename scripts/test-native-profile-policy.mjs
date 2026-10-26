import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {assessNativeProfilePolicy as assess} from './lib/native-profile-policy.mjs';
const read=file=>JSON.parse(fs.readFileSync(file));
const browserPath='fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47-h2.json';
const nativePath='fixtures/native-browser-captures/native-cold-alps-h2.json';
const capsPath='fixtures/clean-vpn-native-profile-policy-capabilities.json';
const browser=read(browserPath),native=read(nativePath),caps=read(capsPath);
function changed(source,edit) {
  const b=structuredClone(source.bundle??source);delete b.contentSha256;edit(b);
  b.contentSha256=createHash('sha256').update(JSON.stringify(b)).digest('hex');return b;
}
const has=(r,reason)=>r.checks.some(c=>c.reason===reason);

test('measured Chromium is blocked by explicit TLS and H2 policy without altering evidence',()=>{
  const before=JSON.stringify([browser,caps,native]),r=assess(browser,caps,native);
  assert.equal(r.status,'blocked');assert.equal(JSON.stringify([browser,caps,native]),before);
  assert.deepEqual(r.checks.filter(c=>c.reason==='cipher-security-policy').map(c=>c.observed).sort((a,b)=>a-b),[47,53,156,157,49171,49172]);
  for(const id of [2308,2309,2310,35,51764])assert.ok(r.checks.some(c=>c.status==='blocked'&&c.observed===id));
  for(const [field,observed] of [['setting:4',6291456],['setting:6',262144],['setting:3',null],['connection_window',15728640]])
    assert.ok(r.checks.some(c=>c.field===field&&c.observed===observed&&c.status==='blocked'&&c.samples.length===20));
  assert.equal(r.checks.filter(c=>c.status==='deviation').length,4);
  assert.deepEqual(r.claims,{nativeValidated:false,browserEquivalent:false,profileActivated:false,executableProfile:null});
  assert.equal(r.inputs.browserContentSha256,browser.bundle.contentSha256);
  assert.deepEqual(r,read('fixtures/clean-vpn-native-profile-policy-report.json'));
});

test('native reference falls within envelope but is never automatically approved as browser-compatible',()=>{
  const r=assess(native,caps,native);assert.equal(r.status,'needs-native-validation');
  assert.equal(r.claims.nativeValidated,false);assert.equal(r.claims.browserEquivalent,false);
  assert.equal(r.claims.executableProfile,null);
  assert.ok(r.requiredNext.includes('native-prewire-check-for-combinations-and-groups'));
});

test('missing browser or native prefixes, and insufficient sampling, remain incomplete',()=>{
  for(const edit of [b=>{delete b.samples[0].http2;},b=>{b.samples=b.samples.slice(0,1);},
    b=>{for(const s of b.samples)delete s.http2;}]) {
    const b=changed(native,edit);
    assert.equal(assess(b,caps,native).status,'incomplete');
    assert.equal(assess(native,caps,b).status,'incomplete');
  }
});

test('settings unknown IDs, duplicates, extra frames and stream credit are rejected as exact replay candidates',()=>{
  for(const [edit,reason] of [
    [h=>h.settingsFrames[0].push([99,0]),'setting-not-supported'],
    [h=>h.settingsFrames[0].push([2,0]),'duplicate-setting'],
    [h=>h.settingsFrames.push([]),'single-settings-frame-required'],
    [h=>h.windowUpdates.push({streamId:1,increment:1}),'stream-window-prefix-not-reproducible'],
    [h=>{h.settingsFrames[0]=h.settingsFrames[0].filter(([id])=>id!==3);},'required-setting-absent-on-wire']
  ]) {
    const b=changed(native,b=>{for(const s of b.samples)edit(s.http2);}),r=assess(b,caps,native);
    assert.equal(r.status,'blocked');assert.ok(has(r,reason),reason);
  }
});

test('boundary values come from capabilities; changed wire values are never silently clamped',()=>{
  for(const rule of caps.profile_policy.http2.settings)for(const value of new Set([rule.min,rule.max,rule.max+1])) {
    const b=changed(native,b=>{for(const s of b.samples) {
      s.http2.settingsFrames[0]=s.http2.settingsFrames[0].filter(([id])=>id!==rule.id);
      s.http2.settingsFrames[0].push([rule.id,value]);
    }}),r=assess(b,caps,native);
    const c=r.checks.find(c=>c.field===`setting:${rule.id}`);
    assert.equal(c.observed,value);assert.equal(c.status,value<=rule.max?'within-envelope':'blocked');
  }
});

test('cold variants must not be merged into a fictitious stable profile',()=>{
  for(const edit of [s=>s.measurement.actual.cipher_suites.reverse(),s=>{s.http2.settingsFrames[0][0][1]++;}]) {
    const b=changed(native,b=>edit(b.samples[0])),r=assess(b,caps,native);
    assert.equal(r.status,'blocked');assert.ok(has(r,'multiple-cold-variants'));
  }
});

test('compression and ALPS missing evidence, unsupported algorithms and inconsistent extensions remain explicit',()=>{
  for(const [edit,status,reason] of [
    [a=>{delete a.certificate_compression;},'incomplete','missing-algorithms'],
    [a=>{delete a.application_settings;},'incomplete','missing-protocol-evidence'],
    [a=>{a.certificate_compression=[1];},'blocked','compression-policy'],
    [a=>{a.application_settings=['http/1.1'];},'blocked','alps-protocol-policy'],
    [a=>{a.extension_types=a.extension_types.filter(id=>id!==27);},'blocked','extension-evidence-inconsistent']
  ]) {
    const b=changed(native,b=>{for(const s of b.samples)edit(s.measurement.actual);}),r=assess(b,caps,native);
    assert.equal(r.status,status);assert.ok(has(r,reason));
  }
});

test('unverified checksums, unsupported policy schemas and malformed envelopes fail closed',()=>{
  const b=structuredClone(native);b.bundle.samples[0].http2.settingsFrames[0][0][1]++;
  assert.throws(()=>assess(b,caps,native),/capture_checksum/);
  assert.throws(()=>assess(native,caps,b),/capture_checksum/);
  const missing=structuredClone(native);delete missing.bundle.contentSha256;assert.throws(()=>assess(missing,caps,native));
  for(const edit of [p=>{p.schema=2;},p=>{p.id='unknown';},p=>{p.activation.automatic=true;},
    p=>{p.http2.settings[0].id=2;},p=>{p.http2.settings[0].min=-1;},
    p=>{p.http2.connection_window.max=2**32;},p=>{p.tls.extension_types.push(p.tls.extension_types[0]);}]) {
    const c=structuredClone(caps);edit(c.profile_policy);assert.throws(()=>assess(native,c,native));
  }
});

test('cold evidence cannot claim session reuse or a different negotiated protocol',()=>{
  for(const edit of [s=>{s.negotiated.sessionReused=true;},s=>{s.negotiated.alpn='http/1.1';}]) {
    const b=changed(native,b=>edit(b.samples[0]));
    assert.throws(()=>assess(b,caps,native));assert.throws(()=>assess(native,caps,b));
  }
});

test('CLI is read-only, returns a blocked report and rejects symlink or oversized inputs',t=>{
  const command='scripts/clean-vpn-native-profile-policy.mjs';
  const run=(b=browserPath,c=capsPath)=>spawnSync(process.execPath,[command,b,c,nativePath],{encoding:'utf8'});
  const r=run();assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).status,'blocked');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvpn-policy-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const link=path.join(dir,'link.json');fs.symlinkSync(path.resolve(browserPath),link);assert.notEqual(run(link).status,0);
  const big=path.join(dir,'big.json');fs.writeFileSync(big,' '.repeat(65537));assert.notEqual(run(browserPath,big).status,0);
  assert.deepEqual(fs.readdirSync(dir).sort(),['big.json','link.json']);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {compareHttp2Captures,compareHttpRequestFields} from './lib/http2-capture-compare.mjs';
const read=n=>JSON.parse(fs.readFileSync('fixtures/native-browser-captures/'+n));
const browser=read('chromium-linux-arm64-156.0.8078.47-h2.json'),native=read('native-bounded-http-20261031.json');
test('selected real request fields match while every full-prefix difference remains visible',()=>{
 const before=JSON.stringify([browser,native]),r=compareHttpRequestFields(browser,native);
 assert.equal(r.status,'selected-fields-match');assert.equal(r.browserEquivalent,false);assert.equal(r.profileActivated,false);
 assert.equal(r.fields.length,3);assert.ok(r.fields.every(f=>f.status==='stable-match'));
 assert.deepEqual(r.fullPrefix,compareHttp2Captures(browser,native));assert.equal(r.fullPrefix.status,'different');
 assert.ok(r.fullPrefix.fields.some(f=>f.field==='headersPriority'&&f.status==='different'));
 assert.ok(r.fullPrefix.fields.some(f=>f.field==='settingsFrames'&&f.status==='different'));
 assert.equal(JSON.stringify([browser,native]),before);
});
test('historical native prefix cannot claim an unobserved UA and different pseudo order as a match',()=>{
 const r=compareHttpRequestFields(browser,read('native-cold-alps-h2.json'));
 assert.equal(r.status,'incomplete');assert.equal(r.fields.find(f=>f.field==='userAgent').status,'unmeasured');
 assert.equal(r.fields.find(f=>f.field==='pseudoHeaderOrder').status,'different');
 assert.equal(r.fields.find(f=>f.field==='settingsIdOrder').status,'different');
});
test('narrow comparison also rejects checksum tampering',()=>{
 const b=structuredClone(browser);b.bundle.samples[0].http2.headers.publicValues.push(['user-agent','fake']);
 assert.throws(()=>compareHttpRequestFields(b,native),/capture_checksum/);
});

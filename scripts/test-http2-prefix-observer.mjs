import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Http2PrefixObserver,headerEvidence } from './lib/http2-prefix-observer.mjs';
import { compareHttp2Captures } from './lib/http2-capture-compare.mjs';
const magic=Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
const frame=(type,flags,stream,body=Buffer.alloc(0))=>{
  const h=Buffer.alloc(9);h.writeUIntBE(body.length,0,3);h[3]=type;h[4]=flags;h.writeUInt32BE(stream,5);return Buffer.concat([h,body]);
};
const settings=Buffer.from('000100010000000200000000000400600000000600040000','hex');
const prefix=()=>Buffer.concat([magic,frame(4,0,0,settings),frame(8,0,0,Buffer.from('00ef0001','hex')),
  frame(1,32,1,Buffer.from([0x80,0,0,0,255,0x82])),frame(9,4,1,Buffer.from([0x87,0x84]))]);
const headers=[':method','GET',':scheme','https',':authority','private.local',':path','/secret-token','user-agent','Measured/1','cookie','PRIVATE_COOKIE','authorization','Bearer PRIVATE_AUTH','x-PRIVATE_NAME','PRIVATE_VALUE'];
function observe(bytes=prefix(),step=1) {const o=new Http2PrefixObserver();for(let i=0;i<bytes.length;i+=step)o.feed(bytes.subarray(i,i+step));return o.snapshot(headers,1);}
test('fragmented H2 prefix preserves exact SETTINGS order, window, priority and continuation shape',()=>{
  const h=observe();assert.equal(h.status,'complete');
  assert.deepEqual(h.settingsFrames,[[[1,65536],[2,0],[4,6291456],[6,262144]]]);
  assert.deepEqual(h.windowUpdates,[{streamId:0,increment:15663105}]);
  assert.deepEqual(h.firstHeaders,{streamId:1,blockBytes:3,paddingBytes:0,priority:{dependency:0,exclusive:true,weight:256}});
  for(const step of [2,3,8,9,17,65536])assert.deepEqual(observe(prefix(),step),h);
  assert.deepEqual(h.headers.names,[':method',':scheme',':authority',':path','user-agent','cookie','authorization','<other>']);
  assert.doesNotMatch(JSON.stringify(h),/PRIVATE|private.local|secret-token/);
  assert.deepEqual(observe(Buffer.concat([prefix(),Buffer.alloc(1048576,0xff)]),2000000),h);
});
test('invalid and over-limit prefixes are unavailable, never partial successes',()=>{
  for(let n=0;n<prefix().length;n++)assert.equal(observe(prefix().subarray(0,n)).status,'unavailable');
  const badMagic=prefix();badMagic[0]^=1;
  const badSize=frame(1,4,1);badSize.writeUIntBE(16385,0,3);
  for(const b of [badMagic,Buffer.concat([magic,frame(4,1,0)]),
    Buffer.concat([magic,frame(4,0,1,settings)]),Buffer.concat([magic,frame(4,0,0,Buffer.alloc(5))]),
    Buffer.concat([magic,frame(4,0,0),frame(8,0,0,Buffer.alloc(4))]),
    Buffer.concat([magic,frame(4,0,0),badSize]),
    Buffer.concat([magic,frame(4,0,0),frame(1,0,1),frame(9,4,3)]),
    Buffer.concat([magic,frame(4,0,0),frame(1,8|4,1,Buffer.from([9]))]),
    Buffer.concat([magic,...Array.from({length:33},()=>frame(4,0,0))]),
    Buffer.concat([magic,frame(4,0,0),...Array.from({length:5},()=>frame(99,0,0,Buffer.alloc(16384)))])])
    assert.equal(observe(b,65536).status,'unavailable');
  const o=new Http2PrefixObserver();o.feed(prefix());assert.equal(o.snapshot(headers,3).reason,'accepted-request-is-not-first');
  assert.throws(()=>headerEvidence(Array(66).fill('a')));assert.throws(()=>headerEvidence(['user-agent','x'.repeat(513)]));
});
test('comparison distinguishes measured differences, variability and missing historical evidence',()=>{
  const wrap=http2=>({schema:1,kind:'clean-vpn-browser-capture-bundle',samples:[{http2}]});
  const h=observe(),same=compareHttp2Captures(wrap(h),wrap(h));
  assert.equal(same.status,'matched-prefix');assert.equal(same.browserEquivalent,false);
  const native=structuredClone(h);native.settingsFrames=[[[3,1],[4,1048576],[6,8192],[2,0]]];native.headers.publicValues[0][1]='POST';
  const diff=compareHttp2Captures(wrap(h),wrap(native));assert.equal(diff.status,'different');
  assert.equal(diff.fields.find(f=>f.field==='settingsFrames').status,'different');
  const old=wrap(undefined);assert.equal(compareHttp2Captures(old,wrap(h)).status,'incomplete');
  const unsafe=structuredClone(h);unsafe.headers.publicValues.push(['authorization','Bearer private']);
  assert.throws(()=>compareHttp2Captures(wrap(unsafe),wrap(h)));
  const variable=wrap(h);variable.samples.push({http2:native});
  assert.equal(compareHttp2Captures(variable,wrap(h)).status,'variable');
});

test('measured Chromium and native bundles retain checksums and real H2 differences',()=>{
  const browser=JSON.parse(fs.readFileSync('fixtures/native-browser-captures/chromium-linux-arm64-156.0.8078.47-h2.json'));
  const native=JSON.parse(fs.readFileSync('fixtures/native-browser-captures/native-cold-alps-h2.json'));
  const result=compareHttp2Captures(browser,native);
  assert.equal(result.status,'different');assert.deepEqual(result.sampleCounts,{browser:20,native:6,browserComplete:20,nativeComplete:6});
  assert.deepEqual(result.inputIntegrity,{browser:true,native:true});
  assert.ok(browser.bundle.samples.every(s=>s.http2.settingsFrames[0].some(([id,n])=>id===4&&n===6291456)));
  assert.ok(native.bundle.samples.every(s=>s.http2.headers.names.includes('authorization')));
  assert.ok(native.bundle.samples.every(s=>!s.http2.headers.publicValues.some(([name])=>name==='authorization')));
  assert.doesNotMatch(JSON.stringify(native.bundle),/Bearer /);
  const damaged=structuredClone(browser);damaged.bundle.samples[0].http2.settingsFrames[0][0][1]++;
  assert.throws(()=>compareHttp2Captures(damaged,native),/capture_checksum/);
});

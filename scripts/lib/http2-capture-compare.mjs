import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { headerEvidence, publicHeaderValues } from './http2-prefix-observer.mjs';
const integer=(v,max)=>Number.isInteger(v)&&v>=0&&v<=max;
function evidence(sample) {
  const h=sample?.http2;
  if(!h || h.status==='unavailable')return null;
  assert.equal(h.schema,1);assert.equal(h.kind,'clean-vpn-http2-prefix');assert.equal(h.status,'complete');
  assert.equal(h.scope,'client-preface-through-first-END_HEADERS');
  assert.ok(Array.isArray(h.settingsFrames)&&h.settingsFrames.length<=32);
  for(const frame of h.settingsFrames) {
    assert.ok(Array.isArray(frame)&&frame.length<=32);
    for(const p of frame)assert.ok(Array.isArray(p)&&p.length===2&&integer(p[0],65535)&&integer(p[1],0xffffffff));
  }
  assert.ok(Array.isArray(h.windowUpdates)&&h.windowUpdates.length<=32);
  for(const w of h.windowUpdates)assert.ok(integer(w.streamId,0x7fffffff)&&integer(w.increment,0x7fffffff)&&w.increment>0);
  assert.ok(Array.isArray(h.headers.names)&&h.headers.names.length<=32);
  for(const name of h.headers.names) {
    assert.equal(typeof name,'string');assert.ok(name==='<other>' || headerEvidence([name,'']).names[0]===name);
  }
  assert.ok(Array.isArray(h.headers.publicValues)&&h.headers.publicValues.length<=32);
  for(const p of h.headers.publicValues)assert.ok(Array.isArray(p)&&p.length===2&&publicHeaderValues.has(p[0]));
  assert.deepEqual(headerEvidence(h.headers.publicValues.flat()).publicValues,h.headers.publicValues);
  assert.ok(integer(h.firstHeaders.blockBytes,65536));
  const p=h.firstHeaders.priority;
  if(p!==null)assert.ok(p&&integer(p.dependency,0x7fffffff)&&typeof p.exclusive==='boolean'&&integer(p.weight,256)&&p.weight>=1);
  return h;
}
export function compareHttp2Captures(browserDocument,nativeDocument) {
  const samples=document=>{
    const bundle=document.bundle??document;
    const {contentSha256,...content}=bundle;
    if(contentSha256!==undefined)assert.equal(contentSha256,createHash('sha256').update(JSON.stringify(content)).digest('hex'),'capture_checksum');
    assert.equal(bundle.kind,'clean-vpn-browser-capture-bundle');assert.equal(bundle.schema,1);
    assert.ok(Array.isArray(bundle.samples)&&bundle.samples.length>0&&bundle.samples.length<=32);
    return bundle.samples.map(evidence);
  };
  const browser=samples(browserDocument), native=samples(nativeDocument);
  const select={settingsFrames:h=>h.settingsFrames,windowUpdates:h=>h.windowUpdates,
    headerOrder:h=>h.headers.names,publicHeaderValues:h=>h.headers.publicValues,
    headersPriority:h=>h.firstHeaders.priority,hpackBlockBytes:h=>h.firstHeaders.blockBytes};
  const variants=(items,read)=>[...new Set(items.filter(Boolean).map(h=>JSON.stringify(read(h))))].sort().map(s=>JSON.parse(s));
  const fields=Object.entries(select).map(([field,read])=>{
    const b=variants(browser,read),n=variants(native,read);
    const overlap=b.some(x=>n.some(y=>JSON.stringify(x)===JSON.stringify(y)));
    return {field,browser:b,native:n,status:!b.length||!n.length?'unmeasured':
      b.length===1&&n.length===1&&overlap?'stable-match':overlap?'variable-overlap':'different'};
  });
  const incomplete=browser.some(h=>!h)||native.some(h=>!h);
  return {schema:1,kind:'clean-vpn-http2-capture-comparison',
    status:incomplete?'incomplete':fields.some(f=>f.status==='different')?'different':
      fields.every(f=>f.status==='stable-match')?'matched-prefix':'variable',
    sampleCounts:{browser:browser.length,native:native.length,browserComplete:browser.filter(Boolean).length,nativeComplete:native.filter(Boolean).length},
    fields,inputIntegrity:{browser:!!(browserDocument.bundle??browserDocument).contentSha256,native:!!(nativeDocument.bundle??nativeDocument).contentSha256},
    profileActivated:false,browserEquivalent:false,
    limitations:['controlled-endpoint-first-request-only','ALPS-not-negotiated-at-this-endpoint',
      'HPACK-size-not-encoder-strategy','GET-navigation-vs-native-POST-are-different-application-contracts',
      'header-values-redacted-except-explicit-public-allowlist','no-resumption-or-later-stream-or-timing-claim']};
}

// Selected fields may match while the full browser/native request still differs.
// Preserve the complete comparison alongside the narrow positive evidence.
export function compareHttpRequestFields(browserDocument,nativeDocument){
  const fullPrefix=compareHttp2Captures(browserDocument,nativeDocument);
  const samples=d=>(d.bundle??d).samples.map(evidence);
  const browser=samples(browserDocument),native=samples(nativeDocument);
  const reads={
    pseudoHeaderOrder:h=>{const v=h.headers.names.filter(n=>n.startsWith(':'));return v.length===4&&new Set(v).size===4?v:null;},
    userAgent:h=>{const v=h.headers.publicValues.filter(([n])=>n==='user-agent').map(([,v])=>v);return v.length===1?v[0]:null;},
    settingsIdOrder:h=>h.settingsFrames.map(f=>f.map(([id])=>id)),
  };
  const variants=(items,read)=>[...new Set(items.filter(Boolean).map(read).filter(v=>v!==null).map(v=>JSON.stringify(v)))].sort().map(v=>JSON.parse(v));
  const fields=Object.entries(reads).map(([field,read])=>{
    const b=variants(browser,read),n=variants(native,read),overlap=b.some(x=>n.some(y=>JSON.stringify(x)===JSON.stringify(y)));
    return{field,browser:b,native:n,status:!b.length||!n.length?'unmeasured':b.length===1&&n.length===1&&overlap?'stable-match':overlap?'variable-overlap':'different'};
  });
  const incomplete=browser.some(h=>!h)||native.some(h=>!h)||fields.some(f=>f.status==='unmeasured');
  return{schema:1,kind:'clean-vpn-http-request-field-comparison',
    status:incomplete?'incomplete':fields.every(f=>f.status==='stable-match')?'selected-fields-match':fields.some(f=>f.status==='different')?'different':'variable',
    fields,fullPrefix,browserEquivalent:false,profileActivated:false,
    scope:'controlled-first-request-selected-fields-not-full-browser-or-policy-approval',
    limitations:['settings-IDs-match-does-not-match-values-or-windows','UA-and-pseudo-order-match-does-not-establish-method-body-other-headers-or-priority',
      'passive-encrypted-pcap-cannot-prove-these-HTTP-fields','capture-integrity-not-publisher-authentication']};
}

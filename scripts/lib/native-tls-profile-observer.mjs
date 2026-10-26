// Independent wire observer: never consumes engine logs or its effective report.
// Only structural fields and JA fingerprints leave this module; no random/key bytes.
import assert from 'node:assert/strict';
import { parseFirstTlsClientHelloFromTcpBuf, ja3ComponentsFromClientHelloBody,
  signatureAlgorithmsFromClientHelloBody, TLS_GREASE_VALUES } from './tls-clienthello-ja3.mjs';
import { ja4FromClientHelloBody } from './tls-clienthello-ja4.mjs';

export function observeTlsProfile(wire, profile) {
  const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
  assert.ok(exact(profile,['schema','kind','id','scenario','tls']));
  assert.equal(profile.schema,1);assert.equal(profile.kind,'clean-vpn-native-tls-profile');assert.equal(profile.scenario,'cold');
  assert.match(profile.id,/^[A-Za-z0-9_.-]{1,64}$/);
  const t=profile.tls;
  assert.ok(exact(t,['min_version','max_version','cipher_suites','supported_groups','key_share_groups','signature_algorithms',
    'alpn','grease','permute_extensions','ech_grease','ocsp','sct','extension_types','optional_extension_types']));
  assert.ok([771,772].includes(t.min_version));assert.equal(t.max_version,772);
  for(const key of ['cipher_suites','supported_groups','key_share_groups','signature_algorithms','extension_types','optional_extension_types']) {
    const a=t[key];assert.ok(Array.isArray(a)&&a.length<=32&&new Set(a).size===a.length);
    assert.ok(a.every(n=>Number.isInteger(n)&&n>=0&&n<=65535&&!TLS_GREASE_VALUES.has(n)));
    if(!['key_share_groups','optional_extension_types'].includes(key))assert.ok(a.length>0);
  }
  assert.ok(t.optional_extension_types.length===0||JSON.stringify(t.optional_extension_types)==='[21]');
  assert.ok(!t.optional_extension_types.some(n=>t.extension_types.includes(n)));
  assert.ok(['["h2"]','["h2","http/1.1"]'].includes(JSON.stringify(t.alpn)));
  for(const key of ['grease','permute_extensions','ech_grease','ocsp','sct'])assert.equal(typeof t[key],'boolean');
  for(const [key,id] of [['ech_grease',65037],['ocsp',5],['sct',18]])assert.equal(t[key],t.extension_types.includes(id));
  const measurement=measureTlsClientHello(wire), actual=measurement.actual;
  const expected = {
    cipher_suites:t.cipher_suites,supported_groups:t.supported_groups,key_share_groups:t.key_share_groups,
    signature_algorithms:t.signature_algorithms,alpn:t.alpn,
    supported_versions:t.min_version===771?[772,771]:[772],extension_types:t.extension_types,grease:t.grease,
  };
  const differences=[];
  for(const key of Object.keys(expected)) {
    let a=actual[key],e=expected[key];
    if(key==='extension_types') {
      if(a.includes(21)&&a.at(-1)!==21)differences.push({field:'padding_order',expected:'last',actual:a.indexOf(21)});
      a=a.filter(n=>!(t.optional_extension_types??[]).includes(n));
    }
    if(key==='extension_types'&&t.permute_extensions){a=[...a].sort((x,y)=>x-y);e=[...e].sort((x,y)=>x-y);}
    if(JSON.stringify(a)!==JSON.stringify(e))differences.push({field:key,expected:e,actual:a});
  }
  return {schema:1,kind:'clean-vpn-native-tls-observation',status:differences.length?'mismatch':'matched',
    profileId:profile.id,...measurement,differences,
    scope:'first-cold-ClientHello-fields-only-not-browser-or-HTTP2-equivalence'};
}

export function measureTlsClientHello(wire) {
  assert.ok(wire.length <= 65536, 'hello_limit');
  const hello = parseFirstTlsClientHelloFromTcpBuf(wire);
  assert.equal(hello.ok, true, 'complete_clienthello_required');
  const body = hello.clientHelloBody, ja3 = ja3ComponentsFromClientHelloBody(body);
  const sig = signatureAlgorithmsFromClientHelloBody(body);
  let o = 35 + body[34], n = body.readUInt16BE(o); o += 2;
  const ciphers = []; for (let end=o+n;o<end;o+=2)ciphers.push(body.readUInt16BE(o));
  o += 1 + body[o]; const end = o + 2 + body.readUInt16BE(o); o += 2;
  const extensions=[], shares=[];
  for (;o<end;) {
    const type=body.readUInt16BE(o), size=body.readUInt16BE(o+2);o+=4;
    assert.ok(o+size<=end);extensions.push(type);
    if(type===51) {
      assert.equal(body.readUInt16BE(o),size-2);
      for(let p=o+2;p<o+size;) {
        const group=body.readUInt16BE(p), length=body.readUInt16BE(p+2);p+=4;
        assert.ok(p+length<=o+size);
        shares.push({group,length});p+=length;
      }
    }
    o+=size;
  }
  assert.equal(o,end);
  const clean = a => a.filter(n=>!TLS_GREASE_VALUES.has(n));
  const actual = {
    cipher_suites:ja3.ciphers, supported_groups:ja3.curves,
    key_share_groups:shares.filter(x=>!TLS_GREASE_VALUES.has(x.group)).map(x=>x.group),
    signature_algorithms:sig.signature_algorithms, alpn:hello.alpn,
    supported_versions:clean(hello.supportedVersions), extension_types:clean(extensions),
    grease:ciphers.some(n=>TLS_GREASE_VALUES.has(n)),
  };
  return {actual,keyShares:shares,sessionIdBytes:body[34],
    ja3:ja3.ja3Digest,ja3String:ja3.ja3String,ja3Sorted:ja3.ja3SortedDigest,
    ja4:ja4FromClientHelloBody(body)};
}

// A single capture does not establish ordering/padding/ECH policy. The caller
// must choose them explicitly and still run native --check-config afterwards.
export function compileTlsProfileCandidate(wire, {id,extensionOrder,padding,echMode}) {
  assert.match(id,/^[A-Za-z0-9_.-]{1,64}$/);
  assert.ok(['fixed','permuted'].includes(extensionOrder));
  assert.ok(['exact','optional'].includes(padding));
  assert.ok(['disabled','grease'].includes(echMode));
  const measurement=measureTlsClientHello(wire), a=measurement.actual, unsupported=[];
  const allowedExtensions=new Set([0,5,10,11,13,16,18,21,23,43,45,51,65281,65037]);
  for(const type of a.extension_types)if(!allowedExtensions.has(type))unsupported.push(`extension:${type}`);
  const allowedCiphers=new Set([4865,4866,4867,49195,49196,49199,49200,52392,52393]);
  for(const cipher of a.cipher_suites)if(!allowedCiphers.has(cipher))unsupported.push(`cipher:${cipher}`);
  // Mirror the current native contract's explicit signature policy. Availability
  // in a newer browser or BoringSSL alone does not enable it in our engine.
  const allowedSignatures=new Set([0x0401,0x0501,0x0601,0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0807]);
  for(const signature of a.signature_algorithms)if(!allowedSignatures.has(signature))unsupported.push(`signature:${signature}`);
  if(!['[772]','[772,771]'].includes(JSON.stringify(a.supported_versions)))unsupported.push('versions');
  if(!['["h2"]','["h2","http/1.1"]'].includes(JSON.stringify(a.alpn)))unsupported.push('alpn');
  if(!a.extension_types.includes(0))unsupported.push('missing-sni');
  if(a.extension_types.includes(65037)!==(echMode==='grease'))unsupported.push('declared-ech-mode');
  const p={schema:1,kind:'clean-vpn-native-tls-profile',id,scenario:'cold',tls:{
    min_version:a.supported_versions.includes(771)?771:772,max_version:772,
    cipher_suites:a.cipher_suites,supported_groups:a.supported_groups,key_share_groups:a.key_share_groups,
    signature_algorithms:a.signature_algorithms,alpn:a.alpn,grease:a.grease,
    permute_extensions:extensionOrder==='permuted',ech_grease:echMode==='grease',
    ocsp:a.extension_types.includes(5),sct:a.extension_types.includes(18),
    extension_types:a.extension_types.filter(n=>padding!=='optional'||n!==21),optional_extension_types:padding==='optional'?[21]:[]}};
  return {schema:1,kind:'clean-vpn-native-tls-profile-candidate',status:unsupported.length?'unsupported':'candidate',
    profile:unsupported.length?null:p,unsupported,measurement,
    policySource:'explicit-caller-declaration-not-inferred-from-one-capture',
    next:'native --check-config with target SNI/CA before activation; this is not an applied profile'};
}

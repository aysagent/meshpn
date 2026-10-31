/** Read-only assessment of measured evidence against an engine's own envelope. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {compareHttp2Captures} from './http2-capture-compare.mjs';
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const integer=(v,max=0xffffffff)=>Number.isInteger(v)&&v>=0&&v<=max;
function ids(values,empty=false) {
  assert.ok(Array.isArray(values)&&values.length<=32&&(empty||values.length>0));
  assert.ok(values.every(v=>integer(v,65535))&&new Set(values).size===values.length);return values;
}
function bundle(document) {
  const b=document.bundle??document,{contentSha256,...content}=b;
  assert.match(contentSha256??'',/^[0-9a-f]{64}$/);
  assert.equal(contentSha256,hash(content),'capture_checksum');
  assert.equal(b.schema,1);assert.equal(b.kind,'clean-vpn-browser-capture-bundle');
  assert.ok(Array.isArray(b.samples)&&b.samples.length>0&&b.samples.length<=32);
  assert.equal(b.metadata.context.scenario,'cold');assert.equal(b.metadata.context.http,'h2');return b;
}
function policyFrom(capabilities) {
  assert.equal(capabilities.version,1);assert.equal(capabilities.engine,'clean-vpn-native-m1');
  const p=capabilities.profile_policy;
  assert.equal(p?.schema,1,'policy_schema');assert.ok(['bounded-cold-v1','bounded-cold-http-v1'].includes(p.id),'policy_id');
  assert.equal(p.scope,'policy-envelope-not-native-validation');
  for(const key of ['tls13_cipher_suites','tls12_cipher_suites','signature_algorithms','extension_types','certificate_compression'])ids(p.tls[key]);
  assert.equal(p.tls.alps_codepoint,17613);
  assert.equal(p.tls.group_combinations,'require-native-prewire-check');
  assert.equal(p.http2.settings_frames,1);assert.equal(p.http2.duplicate_settings,false);
  assert.ok(Array.isArray(p.http2.settings)&&p.http2.settings.length===6);
  assert.deepEqual([...p.http2.settings.map(r=>r.id)].sort((a,b)=>a-b),[1,2,3,4,5,6]);
  for(const r of p.http2.settings)assert.ok(integer(r.min)&&integer(r.max)&&r.min<=r.max&&typeof r.required==='boolean');
  const w=p.http2.connection_window;assert.ok(integer(w.min,0x7fffffff)&&integer(w.max,0x7fffffff)&&w.min<=w.max);
  assert.equal(p.application.fixed_native_carrier,true);assert.equal(p.application.exporter_psk_required,true);
  assert.equal(p.application.browser_navigation_emulation,false);
  assert.equal(p.activation.automatic,false);assert.equal(p.activation.native_check_config_required,true);
  assert.equal(p.activation.independent_wire_check_required,true);return p;
}
export function assessNativeProfilePolicy(browserDocument,capabilities,nativeDocument) {
  const browser=bundle(browserDocument),native=bundle(nativeDocument),p=policyFrom(capabilities);
  // Independent evidence decoder validates H2 shapes and reports actual carrier
  // differences. Historical TLS-only bundles remain explicitly incomplete.
  const comparison=compareHttp2Captures(browser,native),records=new Map();
  const add=(layer,field,status,reason,observed,expected,sample)=>{
    const entry={layer,field,status,reason,observed,expected};const key=JSON.stringify(entry);
    if(!records.has(key))records.set(key,{...entry,samples:[]});
    if(sample!==undefined)records.get(key).samples.push(sample);
  };
  if(browser.samples.length<3)add('evidence','samples','incomplete','minimum-three-cold-samples',browser.samples.length,3);
  if(native.samples.length<3)add('evidence','nativeSamples','incomplete','minimum-three-cold-samples',native.samples.length,3);
  if(comparison.sampleCounts.nativeComplete!==native.samples.length)
    add('evidence','nativePrefix','incomplete','missing-native-first-request-evidence',comparison.sampleCounts.nativeComplete,native.samples.length);
  for(const sample of native.samples) {
    assert.equal(sample.negotiated.alpn,'h2');assert.equal(sample.negotiated.tlsVersion,'TLSv1.3');assert.equal(sample.negotiated.sessionReused,false);
  }
  const tlsFields=['cipher_suites','signature_algorithms','extension_types','supported_groups','key_share_groups','supported_versions','alpn','grease'];
  const variants=Object.fromEntries(tlsFields.map(k=>[k,new Set()]));
  const h2Variants=new Set();
  const ranges=new Map(p.http2.settings.map(r=>[r.id,r]));
  const tlsRules={cipher_suites:[...p.tls.tls13_cipher_suites,...p.tls.tls12_cipher_suites],
    signature_algorithms:p.tls.signature_algorithms,extension_types:p.tls.extension_types};
  for(const [index,sample] of browser.samples.entries()) {
    const n=index+1,a=sample.measurement.actual;
    assert.equal(sample.negotiated.alpn,'h2');assert.equal(sample.negotiated.tlsVersion,'TLSv1.3');assert.equal(sample.negotiated.sessionReused,false);
    for(const field of tlsFields) {
      let value=a[field];
      if(field==='grease')assert.equal(typeof value,'boolean');
      else if(field==='alpn')assert.ok(Array.isArray(value)&&value.length<=2&&value.every(x=>typeof x==='string'&&x.length<=32));
      else ids(value,field==='key_share_groups');
      if(field==='extension_types') {
        value=value.filter(id=>browser.metadata.context.padding!=='optional'||id!==21);
        if(browser.metadata.context.extensionOrder==='permuted')value=[...value].sort((x,y)=>x-y);
      }
      variants[field].add(JSON.stringify(value));
    }
    for(const [field,allowed] of Object.entries(tlsRules))for(const id of a[field])
      add('tls',field,allowed.includes(id)?'within-envelope':'blocked',allowed.includes(id)?'id-enabled':
        field==='cipher_suites'?'cipher-security-policy':field==='extension_types'&&id===51764?
          'trust-anchor-selection-and-retry-not-implemented':'feature-not-enabled',id,allowed,n);
    for(const [field,ok] of [['supported_versions',['[772]','[772,771]'].includes(JSON.stringify(a.supported_versions))],
      ['alpn',['["h2"]','["h2","http/1.1"]'].includes(JSON.stringify(a.alpn))]])
      add('tls',field,ok?'within-envelope':'blocked',ok?'supported-shape':'unsupported-shape',a[field],null,n);
    if(a.extension_types.includes(27)) {
      if(!a.certificate_compression)add('tls','certificate_compression','incomplete','missing-algorithms',null,p.tls.certificate_compression,n);
      else {ids(a.certificate_compression);const ok=JSON.stringify(a.certificate_compression)===JSON.stringify(p.tls.certificate_compression);
        add('tls','certificate_compression',ok?'within-envelope':'blocked','compression-policy',a.certificate_compression,p.tls.certificate_compression,n);}
    }
    if(a.extension_types.includes(17613)) {
      const value=a.application_settings;
      if(!value)add('tls','application_settings','incomplete','missing-protocol-evidence',null,['h2'],n);
      else {assert.ok(Array.isArray(value)&&value.length<=2&&value.every(x=>typeof x==='string'&&x.length<=32));
        add('tls','application_settings',JSON.stringify(value)==='["h2"]'?'within-envelope':'blocked','alps-protocol-policy',value,['h2'],n);}
    }
    for(const [field,extension] of [['certificate_compression',27],['application_settings',17613]])
      if(!a.extension_types.includes(extension)&&a[field]?.length)
        add('tls',field,'blocked','extension-evidence-inconsistent',a[field],[],n);
    const h=sample.http2;
    if(h?.status!=='complete') {add('http2','prefix','incomplete','missing-first-request-evidence',null,null,n);continue;}
    h2Variants.add(JSON.stringify([h.settingsFrames,h.windowUpdates]));
    if(h.settingsFrames.length!==p.http2.settings_frames)
      add('http2','settingsFrames','blocked','single-settings-frame-required',h.settingsFrames.length,1,n);
    const seen=new Set();
    for(const [id,value] of h.settingsFrames.flat()) {
      if(seen.has(id))add('http2',`setting:${id}`,'blocked','duplicate-setting',id,null,n);seen.add(id);
      const rule=ranges.get(id);
      const ok=rule&&value>=rule.min&&value<=rule.max;
      add('http2',`setting:${id}`,ok?'within-envelope':'blocked',!rule?'setting-not-supported':ok?'value-in-range':'resource-or-protocol-bound',
        value,rule?{min:rule.min,max:rule.max}:null,n);
    }
    for(const rule of ranges.values())if(rule.required&&!seen.has(rule.id))
      add('http2',`setting:${rule.id}`,'blocked','required-setting-absent-on-wire',null,{min:rule.min,max:rule.max},n);
    const window=65535+h.windowUpdates.filter(w=>w.streamId===0).reduce((sum,w)=>sum+w.increment,0);
    const ok=window>=p.http2.connection_window.min&&window<=p.http2.connection_window.max;
    add('http2','connection_window',ok?'within-envelope':'blocked',ok?'value-in-range':'resource-bound',window,p.http2.connection_window,n);
    if(h.windowUpdates.some(w=>w.streamId!==0))add('http2','windowUpdates','blocked','stream-window-prefix-not-reproducible',null,null,n);
  }
  for(const [field,values] of Object.entries(variants))if(values.size>1)
    add('tls',field,'blocked','multiple-cold-variants',values.size,1);
  if(h2Variants.size>1)add('http2','prefix','blocked','multiple-cold-variants',h2Variants.size,1);
  for(const field of comparison.fields.filter(f=>['headerOrder','publicHeaderValues','headersPriority','hpackBlockBytes'].includes(f.field)))
    if(field.status!=='stable-match')add('application',field.field,field.status==='unmeasured'?'incomplete':'deviation',
      field.field==='hpackBlockBytes'?'size-not-encoder-strategy':'fixed-native-carrier-differs',field.browser,field.native);
  const checks=[...records.values()],blocked=checks.some(c=>c.status==='blocked'),incomplete=checks.some(c=>c.status==='incomplete');
  return {schema:1,kind:'clean-vpn-native-profile-policy-assessment',policyId:p.id,
    inputs:{browserContentSha256:browser.contentSha256,nativeContentSha256:native.contentSha256,capabilitiesSha256:hash(capabilities)},
    status:blocked?'blocked':incomplete?'incomplete':'needs-native-validation',checks,
    claims:{nativeValidated:false,browserEquivalent:false,profileActivated:false,executableProfile:null},
    unchanged:{memoryCaps:true,cipherSecurityPolicy:true,exporterPskAuthentication:true,httpCarrier:true},
    requiredNext:['native-prewire-check-for-combinations-and-groups','independent-TLS-H2-wire-comparison',
      'explicit-application-contract-for-any-header-changes'],
    limitations:['capabilities-file-is-an-input-not-attested-engine-identity','capture-checksum-is-not-publisher-authentication',
      'within-envelope-does-not-prove-native-acceptance','wire-credit-is-not-an-allocation-budget',
      'ALPS-peer-behavior-and-resumption-not-proven-by-cold-prefix','native-reference-may-be-a-different-binary-build']};
}

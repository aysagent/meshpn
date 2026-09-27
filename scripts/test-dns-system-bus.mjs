import assert from 'node:assert/strict';
import test from 'node:test';
import { createDnsSystemBus, validateResolvedCall } from './lib/dns-system-bus.mjs';
import { resolvedMethod } from './lib/dns-resolved-backend.mjs';
const values = { DNSEx: [[2,[127,0,0,1],2053,'']], Domains: [['.',true]], DefaultRoute: true };
test('fixed bus endpoint, unique owner, validated property readback and void setters', async () => {
  const calls=[];
  const bus=createDnsSystemBus(async (tool,args) => {
    calls.push(args); assert.equal(tool,'busctl');
    assert.deepEqual(args.slice(0,5), ['--address=unix:path=/run/dbus/system_bus_socket','--timeout=5s','--auto-start=no','--allow-interactive-authorization=no','--json=short']);
    let data;
    if(args.includes('GetId')) data=['a'.repeat(32)];
    else if(args.includes('GetNameOwner')) data=[':1.23'];
    else if(args.includes('GetLink')) data=['/org/freedesktop/resolve1/link/_32'];
    else if(args[5]==='get-property') data=values[args.at(-1)];
    else return {stdout:''};
    return {stdout:JSON.stringify({data})};
  });
  assert.equal(await bus.id(),'a'.repeat(32)); assert.equal(await bus.owner(),':1.23');
  for(const [property,value] of Object.entries(values)) {
    assert.deepEqual(await bus.property(':1.23',2,property),value);
    await bus.set(':1.23',resolvedMethod(property,value,2));
  }
  const before=calls.length;
  for(const owner of ['org.freedesktop.resolve1','',':x.y']) await assert.rejects(bus.property(owner,2,'DNSEx'));
  await assert.rejects(bus.property(':1.23',1,'DNSEx'));
  await assert.rejects(bus.property(':1.23',2,'DNS'));
  await assert.rejects(bus.set(':1.23',['RevertLink','i','2']));
  assert.equal(calls.length,before);
});
test('only canonical bounded resolved setters pass validation', () => {
  for(const [p,v] of Object.entries(values)) {
    const args=resolvedMethod(p,v,2); assert.deepEqual(validateResolvedCall(args),args);
    assert.throws(()=>validateResolvedCall([...args,'extra']));
    assert.throws(()=>validateResolvedCall([args[0],args[1],'02',...args.slice(3)]));
  }
  for(const args of [[], ['SetLinkDNSEx','ia(iayqs)','2','999'], ['SetLinkDomains','ia(sb)','2','1','x','yes'],
    ['SetLinkDNSEx','ia(iayqs)','2','1','2','4','999','0','0','1','53','']]) assert.throws(()=>validateResolvedCall(args));
});
test('invalid D-Bus replies fail without authorizing a setter', async () => {
  for(const stdout of ['', '{}','null','{"data":[]}','{"data":["wrong"]}', 'x'.repeat(262145)]) {
    const bus=createDnsSystemBus(async()=>({stdout})); await assert.rejects(bus.id()); await assert.rejects(bus.owner());
  }
});
test('read-only manager inspection uses fixed properties and unique peers', async () => {
  const calls = [], values = { DNSEx: [[2, 2, [10,129,0,2], 0, '']], FallbackDNSEx: [], Domains: [[2, 'auto.internal', false]], ResolvConfMode: ['stub'] };
  const bus = createDnsSystemBus(async (_tool, args) => {
    calls.push(args); let data;
    if (args.includes('GetNameOwner')) data = [args.at(-1) === 'org.freedesktop.network1' ? ':1.24' : ':1.23'];
    else if (args.includes('GetConnectionUnixProcessID')) data = [42];
    else if (args.includes('GetConnectionUnixUser')) data = [101];
    else data = values[args.at(-1)];
    return { stdout: JSON.stringify({ data }) };
  });
  assert.equal(await bus.owner('org.freedesktop.network1'), ':1.24');
  assert.equal(await bus.ownerPid(':1.23'), 42); assert.equal(await bus.ownerUid(':1.23'), 101);
  assert.deepEqual(await bus.managerSnapshot(':1.23'), { ...values, ResolvConfMode: 'stub' });
  assert.ok(calls.slice(-4).every((args) => args[5] === 'get-property' && args[6] === ':1.23'));
  const before = calls.length;
  await assert.rejects(bus.owner('org.freedesktop.systemd1'));
  for (const method of ['ownerPid', 'ownerUid', 'managerSnapshot']) await assert.rejects(bus[method]('org.freedesktop.resolve1'));
  assert.equal(calls.length, before);
});
test('read-only manager refuses malformed scalar and oversized list replies', async () => {
  for (const data of [null, [], ['42'], [-1], [4294967295], [42, 43]]) {
    const bus = createDnsSystemBus(async () => ({ stdout: JSON.stringify({ data }) }));
    await assert.rejects(bus.ownerPid(':1.2')); await assert.rejects(bus.ownerUid(':1.2'));
  }
  for (const data of [null, 'bad', Array(65).fill(0)]) {
    const bus = createDnsSystemBus(async (_tool, args) => ({ stdout: JSON.stringify({ data: args.at(-1) === 'ResolvConfMode' ? ['stub'] : data }) }));
    await assert.rejects(bus.managerSnapshot(':1.2'));
  }
});

import assert from 'node:assert/strict';
import {parseCIDR,mergeRanges,encodeRanges} from '../scripts/compile-ip-ranges.mjs';
assert.deepEqual(parseCIDR('255.255.255.255/32'),[0xffffffff,0xffffffff]);
assert.deepEqual(parseCIDR('123.4.5.6/0'),[0,0xffffffff]);
assert.deepEqual(parseCIDR('192.168.7.42/24'),[0xc0a80700,0xc0a807ff]);
for(const bad of ['256.0.0.1','1.2.3.4/33','1.2.3.4/-1','1.2.3.4/','1.2.3.4/1/2','1.2.3'])
  assert.throws(()=>parseCIDR(bad));
const merged=mergeRanges([[20,30],[0,10],[11,19],[100,200],[150,250]]);
assert.deepEqual(merged,[[0,30],[100,250]]);
const binary=encodeRanges(merged);
assert.equal(binary.length,32);assert.equal(binary.readUInt32LE(12),2);
assert.equal(binary.readUInt32LE(28),250);
console.log('IP range compiler tests passed');

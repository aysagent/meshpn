/** Matching regressions use synthetic tshark rows, NOT claims of network captures. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { HRR_RANDOM, parseBrowserPcap, assertBrowserPcap } from './lib/browser-lab-pcap.mjs';

const ports = { client: 14001, exit: 14002, origin: 14003 };
function fixture({ hrr = false, offered = false, resumed = false } = {}) {
  const random = 'aa'.repeat(32), ja3 = 'ab'.repeat(16), ja4 = 't13d1516h2_test_test';
  const captures = [], rows = [];
  let frame = 0;
  for (const [i, [stage, port]] of Object.entries(ports).entries()) {
    const peerPort = 30001 + i, stream = i;
    const sni = stage === 'exit' ? 'opaque.relay.test' : 'localhost';
    const client = (flight) => {
      rows.push([++frame, stream, peerPort, port, '1', random, sni, ja3, ja4, offered ? '0,43,41' : '0,43']);
      captures.push({ stage, peerPort, id: random, flight, sni, ja3, ja4 });
    };
    const server = (retry) => rows.push([++frame, stream, port, peerPort, '2', retry ? HRR_RANDOM : 'bb'.repeat(32),
      '', '', '', !retry && resumed ? '43,51,41' : '43,51']);
    client(1);
    if (hrr) { server(true); client(2); }
    server(false);
  }
  const expectations = new Map([[random, { hrr, offered, resumed }]]);
  return { rows, captures, expectations };
}
const parse = (rows) => parseBrowserPcap(`${rows.map((row) => row.join('\t')).join('\n')}\n`, ports);
const verify = (f) => assertBrowserPcap(parse(f.rows), f.captures, f.expectations);

for (const options of [{}, { hrr: true }, { offered: true, resumed: true }, { offered: true },
  { hrr: true, offered: true, resumed: true }]) {
  test(`independent pcap matcher accepts complete three-stage trace ${JSON.stringify(options)}`, () => {
    const f = fixture(options);
    assert.equal(verify(f), options.hrr ? 6 : 3);
  });
}

for (const [name, mutate] of [
  ['missing CH2', (f) => { f.rows.splice(2, 1); }],
  ['missing HRR', (f) => { f.rows.splice(1, 1); }],
  ['missing final ServerHello', (f) => { f.rows.pop(); }],
  ['CH2 mistaken for CH1', (f) => { f.captures[1].flight = 1; }],
  ['wrong CH2 JA3', (f) => { f.rows[2][7] = 'ef'.repeat(16); }],
  ['wrong CH2 JA4', (f) => { f.rows[2][8] = 'wrong'; }],
  ['plaintext SNI on relay leg', (f) => { f.rows[6][6] = 'localhost'; }],
  ['changed CH2 random', (f) => { f.rows[2][5] = 'cc'.repeat(32); }],
  ['wrong peer port', (f) => { f.captures[0].peerPort++; }],
  ['unmatched extra passive capture', (f) => { f.captures.push({ ...f.captures[0] }); }],
  ['unmatched pcap hello', (f) => { f.captures.splice(1, 1); }],
  ['lost whole stage', (f) => { f.rows.splice(8, 4); f.captures.splice(4, 2); }],
]) test(`pcap matcher rejects ${name}`, () => {
  const f = fixture({ hrr: true }); mutate(f); assert.throws(() => verify(f));
});

test('PSK offer alone is not proof of resumption', () => {
  const f = fixture({ offered: true, resumed: true });
  f.rows[1][9] = '43,51';
  assert.throws(() => verify(f), /PSK selection/);
});
test('ticket fallback must still have offered the rejected PSK', () => {
  const f = fixture({ offered: true }); f.rows[0][9] = '0,43';
  assert.throws(() => verify(f), /PSK offer/);
});
test('resumed HRR must keep the PSK offer in CH2 as well', () => {
  const f = fixture({ hrr: true, offered: true, resumed: true }); f.rows[2][9] = '0,43';
  assert.throws(() => verify(f), /PSK offer/);
});
test('equal random on two TCP streams is ambiguous, not a successful match', () => {
  const f = fixture();
  const extra = f.rows.slice(0, 2).map((row, i) => [7 + i, 99, ...row.slice(2)]);
  f.rows.push(...extra);
  assert.throws(() => verify(f), /exactly one stream/);
});
test('interleaved independent streams remain matched by identity, not arrival order', () => {
  const f = fixture({ hrr: true });
  f.rows.sort((a, b) => (a[0] - 1) % 4 - (b[0] - 1) % 4);
  f.rows.forEach((row, i) => { row[0] = i + 1; });
  assert.equal(verify(f), 6);
});
test('reused peer port on different streams is distinguished by random', () => {
  const f = fixture(), other = fixture({ offered: true, resumed: true });
  for (const row of other.rows) { row[0] += 6; row[1] += 3; if (row[4] === '1') row[5] = 'dd'.repeat(32); }
  for (const capture of other.captures) capture.id = 'dd'.repeat(32);
  f.rows.push(...other.rows); f.captures.push(...other.captures);
  f.expectations.set('dd'.repeat(32), { hrr: false, offered: true, resumed: true });
  assert.equal(verify(f), 6);
});
for (const [name, mutate] of [
  ['truncated fields', (rows) => rows[0].pop()],
  ['duplicate frame', (rows) => { rows[1][0] = rows[0][0]; }],
  ['multiple hellos in one field row', (rows) => { rows[0][4] = '1,1'; }],
  ['wrong direction', (rows) => { rows[0][4] = '2'; }],
  ['invalid extension number', (rows) => { rows[0][9] = '0,invalid'; }],
  ['invalid hello random', (rows) => { rows[0][5] = 'not-a-random'; }],
]) test(`tshark parser fails closed for ${name}`, () => {
  const { rows } = fixture(); mutate(rows); assert.throws(() => parse(rows));
});
test('empty tshark result is not a pass', () => assert.throws(() => parseBrowserPcap('', ports)));

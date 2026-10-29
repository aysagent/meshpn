import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { once } from 'node:events';
import { createBroker } from '../broker.mjs';
import { createAdmin } from '../server.mjs';
import { publicClientList } from '../lib/clients.mjs';
import { adminControls } from '../public/capabilities.js';

const temporary = t => { const p = fs.mkdtempSync(path.join(os.tmpdir(), 'mpn-clients-admin-')); t.after(() => fs.rmSync(p, { recursive: true, force: true })); return p; };
const publicList = () => ({ version: 1, revision: 2, clients: [{ name: 'laptop', ipv4: '10.99.0.3', revoked: false, secret_path: '/do-not-display', secret: 'test-key', connectionState: 'unknown' }] });
async function broker(t, role = 'exit', enabled = true) {
  const state = temporary(t), config = state + '/engine.json', calls = [], operations = [];
  fs.writeFileSync(config, JSON.stringify({ version: 1, role, address: '192.0.2.1', port: 443 }), { mode: 0o600 });
  fs.mkdirSync(state + '/profiles');
  const fake = Object.fromEntries(['list', 'add', 'rename', 'rotate', 'revoke'].map(action => [action, async (...args) => { operations.push([action, ...args]); return publicList(); }]));
  fake.export = async name => { operations.push(['export', name]); return { kind: 'clean-vpn-client-enrollment', name, files: { 'packet.psk': 'test-secret-export' } }; };
  const c = { version: 1, usbAddress: '127.0.0.1', usbInterface: 'lo', wifiInterface: 'wlan0', vpnUnit: 'native-exit.service', guardUnit: 'guard.service', guardScript: '/guard', state, engine: '/engine', profiles: state + '/profiles', vpnConfig: config, socket: state + '/broker.sock', publishMdns: false,
    ...(enabled ? { clientsDirectory: state + '/clients' } : {}) };
  const b = await createBroker(c, { clientsFactory: () => fake, run: async (...args) => { calls.push(args); return { out: 'ActiveState=active\nSubState=running\nMainPID=123\n' }; } });
  t.after(() => b.close()); return { b, calls, operations };
}
test('public client projection drops secret paths and unexpected credential fields', () => {
  const result = publicClientList(publicList()); assert.equal(result.clients[0].hostname, 'laptop.mpn');
  assert.doesNotMatch(JSON.stringify(result), /test-key|secret|do-not-display/);
});
test('exit role advertises clients and rejects Wi-Fi guard hostname and client-profile operations', async t => {
  const { b, calls } = await broker(t);
  const settings = await b.dispatch('/settings'); assert.equal(settings.vpn.role, 'exit'); assert.deepEqual(settings.wifi, []);
  const status = await b.dispatch('/status'); assert.equal(status.capabilities.clients, true); assert.equal(status.capabilities.wifi, false); assert.equal(status.capabilities.guardToggle, false);
  calls.length = 0;
  for (const route of ['/guard', '/wifi/scan', '/wifi/save', '/hostname', '/profile/import', '/vpn/settings', '/probe', '/observer/start']) await assert.rejects(b.dispatch(route, {}), /client_only_operation/);
  assert.equal(calls.length, 0);
});
test('broker client mutations accept names only; revoke and rotation require confirmation', async t => {
  const { b, operations } = await broker(t);
  await assert.rejects(b.dispatch('/clients/add', { name: 'laptop', directory: '/etc' }), /unknown_fields/);
  await assert.rejects(b.dispatch('/clients/revoke', { name: 'laptop' }), /client_action_confirmation_required/);
  await assert.rejects(b.dispatch('/clients/rotate', { name: 'laptop', confirm: false }), /client_action_confirmation_required/);
  const added = await b.dispatch('/clients/add', { name: 'phone' }); assert.equal(added.status, 'running'); await new Promise(resolve => setImmediate(resolve));
  const renamed = await b.dispatch('/clients/rename', { name: 'phone', newName: 'tablet' }); assert.equal(renamed.kind, 'client-rename'); await new Promise(resolve => setImmediate(resolve));
  await b.dispatch('/clients/revoke', { name: 'tablet', confirm: true }); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(operations, [['add', 'phone'], ['rename', 'phone', 'tablet'], ['revoke', 'tablet']]);
  const result = await b.dispatch('/status'); assert.doesNotMatch(JSON.stringify(result.jobs), /test-key|secret|do-not-display/);
});
test('export credentials do not enter operation history and unconfigured clients API refuses', async t => {
  const { b } = await broker(t); const exported = await b.dispatch('/clients/export', { name: 'laptop' }); assert.equal(exported.files['packet.psk'], 'test-secret-export');
  assert.doesNotMatch(JSON.stringify(await b.dispatch('/status')), /test-secret-export/);
  const disabled = await broker(t, 'exit', false); await assert.rejects(disabled.b.dispatch('/clients'), /clients_not_configured/);
});
test('client role cannot enable exit client registry', async t => {
  await assert.rejects(broker(t, 'client', true), /clients_exit_only/);
});
test('capability projection hides unsupported container controls and separates roles', () => {
  const caps = { containerManaged: true, role: 'exit', wifi: false, guardToggle: false, hostnameChange: false, observer: false, profileImport: false, vpnSettings: false, clients: true };
  assert.deepEqual(adminControls(caps), { wifi: false, guardToggle: false, hostnameChange: false, observer: false, profileImport: false, vpnSettings: false, clients: true, probes: [] });
  const client = adminControls({ ...caps, role: 'client', vpnSettings: true, profileImport: true, clients: false }); assert.equal(client.clients, false); assert.equal(client.vpnSettings, true); assert.deepEqual(client.probes, ['dns']);
});
test('HTTP enrollment download requires changed password, POST and CSRF and is an attachment', async t => {
  const state = temporary(t), calls = [];
  const app = await createAdmin({ state, address: '127.0.0.1', subnet: '127.0.0.0/8', port: 80, lab: true }, { rpc: async (route, p) => {
    calls.push([route, p]); return route === '/clients/export' ? { kind: 'clean-vpn-client-enrollment', name: p.name, files: { key: 'only-in-download' } } : { hostname: 'mpn', ...publicList() };
  } });
  app.server.listen(0, '127.0.0.1'); await once(app.server, 'listening'); t.after(() => app.close());
  const request = (route, { method = 'GET', data, cookie, csrf } = {}) => new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: app.server.address().port, path: route, method, headers: { host: 'mpn.local', origin: 'http://mpn.local', ...(data ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}), ...(csrf ? { 'x-csrf-token': csrf } : {}) } }, res => {
      let text = ''; res.on('data', b => text += b); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(text) }));
    }); req.on('error', reject); req.end(data ? JSON.stringify(data) : undefined);
  });
  let login = await request('/api/login', { method: 'POST', data: { password: 'admin' } }); let cookie = login.headers['set-cookie'][0].split(';')[0], csrf = login.body.csrf;
  assert.equal((await request('/api/clients/export', { method: 'POST', cookie, csrf, data: { name: 'laptop' } })).status, 403);
  await request('/api/password', { method: 'POST', cookie, csrf, data: { oldPassword: 'admin', newPassword: 'test changed password' } });
  login = await request('/api/login', { method: 'POST', data: { password: 'test changed password' } }); cookie = login.headers['set-cookie'][0].split(';')[0]; csrf = login.body.csrf;
  assert.equal((await request('/api/clients', { cookie })).status, 200);
  assert.equal((await request('/api/clients/export', { cookie })).status, 405);
  assert.equal((await request('/api/clients/export', { method: 'POST', cookie, data: { name: 'laptop' } })).status, 403);
  assert.equal((await request('/api/clients/export', { method: 'POST', cookie, csrf, data: { name: '../file' } })).status, 400);
  const result = await request('/api/clients/export', { method: 'POST', cookie, csrf, data: { name: 'laptop' } });
  assert.equal(result.status, 200); assert.equal(result.headers['content-disposition'], 'attachment; filename=laptop.meshpn.json'); assert.equal(result.headers['cache-control'], 'no-store'); assert.equal(result.body.files.key, 'only-in-download');
  assert.equal(calls.filter(([route]) => route === '/clients/export').length, 1);
});

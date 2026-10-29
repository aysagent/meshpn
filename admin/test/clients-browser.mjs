// Real Chromium + frontend; broker fixture has no system/network privileges.
// No external browser requests, persistent browser profile or host DNS changes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { once } from 'node:events';
import assert from 'node:assert/strict';
import puppeteer from 'puppeteer';
import { createAdmin } from '../server.mjs';

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mpn-clients-browser-'));
const reservation = net.createServer(); reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening'); const port = reservation.address().port;
await new Promise(resolve => reservation.close(resolve));
const clients = [], actions = [], capabilities = { role: 'exit', clients: true, containerManaged: true, nativeManaged: true, networkOwner: true, wifi: false, guardToggle: false, hostnameChange: false, observer: false, profileImport: false, vpnSettings: false };
const publicList = () => ({ version: 1, revision: actions.length, zone: 'mpn', clients: structuredClone(clients) });
const app = await createAdmin({ address: '127.0.0.1', subnet: '127.0.0.0/8', port, state: directory, lab: true }, { rpc: async (route, p) => {
  if (route === '/settings') return { hostname: 'mpn', adminUrl: '/', vpn: { role: 'exit', nativeManaged: true }, dns: { mode: 'exit', upstreams: 'fixture' }, profiles: [], wifi: [], capabilities };
  if (route === '/status') return { metrics: { time: Date.now(), timezone: 'UTC', temperatures: [], memory: {}, uptimeSeconds: 1, cpu: [], network: [] }, vpn: { ActiveState: 'active' }, network: { ActiveState: 'active' }, guard: { active: true }, wifi: {}, jobs: [], capabilities };
  if (route === '/clients') return publicList();
  if (route === '/clients/add') { clients.push({ name: p.name, hostname: p.name + '.mpn', ipv4: '10.99.0.3', revoked: false, connectionState: 'unknown' }); actions.push('add'); return { status: 'passed', kind: 'client-add' }; }
  if (route === '/clients/revoke') { assert.equal(p.confirm, true); clients.find(c => c.name === p.name).revoked = true; actions.push('revoke'); return { status: 'passed', kind: 'client-revoke' }; }
  throw Error('unexpected_route');
} });
await app.auth.change('admin', 'browser fixture password'); app.server.listen(port, '127.0.0.1'); await once(app.server, 'listening');
let browser;
try {
  browser = await puppeteer.launch({ headless: true, protocolTimeout: 10000, args: ['--disable-background-networking', '--no-proxy-server'] });
  const page = await browser.newPage(), errors = []; page.setDefaultTimeout(10000); page.on('pageerror', e => {errors.push(e.message);console.error('PAGE_ERROR',e.message);});
  await page.setRequestInterception(true); page.on('request', req => req.url().startsWith(`http://127.0.0.1:${port}/`) ? req.continue() : req.abort());
  await page.goto(`http://127.0.0.1:${port}/`); await page.type('#login-password', 'browser fixture password'); await page.$eval('#login-form', form => form.requestSubmit());
  try{await page.waitForFunction(() => !document.querySelector('#dashboard').hidden && !document.querySelector('#clients').hidden,{polling:100});}catch(error){console.error(await page.evaluate(()=>({message:document.querySelector('#message').textContent,dashboard:document.querySelector('#dashboard').hidden,clients:document.querySelector('#clients').hidden,cap:document.querySelector('#clients').dataset.cap}))); throw error;}
  for (const selector of ['#wifi', '#observer', '#vpn-form', '#guard-save', '#hostname-form', '#profile-import']) assert.equal(await page.$eval(selector, el => !!el.getClientRects().length), false, selector);
  await page.type('#client-name', 'laptop'); await page.$eval('#client-add-form', form => form.requestSubmit()); await page.waitForFunction(() => document.querySelector('#message').textContent.includes('client-add'),{polling:100});
  await page.$eval('#clients-refresh', button => button.click()); await page.waitForFunction(() => document.querySelector('#clients-list').textContent.includes('laptop.mpn'),{polling:100});
  assert.equal(await page.$eval('#clients-list', el => el.textContent.includes('10.99.0.3')), true);
  page.once('dialog', dialog => dialog.accept()); await page.evaluate(() => [...document.querySelectorAll('#clients-list button')].find(b => b.textContent === 'Отозвать').click());
  await page.waitForFunction(() => document.querySelector('#message').textContent.includes('client-revoke'),{polling:100}); await page.$eval('#clients-refresh', button => button.click());
  await page.waitForFunction(() => document.querySelector('#clients-list').textContent.includes('Отозван'),{polling:100});
  assert.deepEqual(errors, []); assert.deepEqual(actions, ['add', 'revoke']);
  console.log(JSON.stringify({ status: 'passed', browser: await browser.version(), scope: 'real frontend DOM; fixture broker; loopback only', checks: ['exit role', 'unsupported controls hidden', 'client add', 'list render', 'confirmed revoke'], hostNetworkChanged: false }));
} finally { if (browser) await browser.close(); await app.close(); fs.rmSync(directory, { recursive: true, force: true }); }

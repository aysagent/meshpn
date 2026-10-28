import fs from 'node:fs';
import assert from 'node:assert/strict';
assert.equal(fs.readFileSync('/run/systemd/container', 'utf8').trim(), 'podman');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab', 'utf8'), 'isolated-admin-lab-v1\n');
const file = '/shared/socket/broker.sock';
try {assert(fs.lstatSync(file).isSocket()); fs.unlinkSync(file);} catch(e) {if(e.code!=='ENOENT')throw e;}

// Image-only fixture setup, before PID1 execs systemd. No host mounts accepted.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {addNativeSystemdImage} from '../../scripts/lib/native-systemd-vm-image.mjs';
import {addNativeAdminImage} from '../../scripts/lib/native-admin-vm-image.mjs';
assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
assert.equal(process.env.container, 'podman');
assert.equal(fs.readFileSync('/etc/meshpn-admin-disposable-lab', 'utf8'), 'isolated-admin-lab-v1\n');
assert.deepEqual(fs.readdirSync('/sys/class/net'), ['lo']);
const put = (file, bytes, mode = 0o644) => {fs.mkdirSync(file.slice(0, file.lastIndexOf('/')), {recursive: true}); fs.writeFileSync(file, bytes, {mode}); fs.chmodSync(file, mode);};
execFileSync('/usr/bin/openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-keyout','/native/key.pem','-out','/native/cert.pem','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'], {stdio: 'pipe'});
fs.chmodSync('/native/key.pem', 0o600);
addNativeSystemdImage(put); addNativeAdminImage(put);
for (const name of ['c2','c3','exit']) {
  // systemd 255's PSI bind mount conflicts with the delegated container
  // cgroup view. The full host unit hardening is tested in QEMU separately.
  put('/etc/systemd/system/native-'+name+'.service.d/container.conf', '[Service]\nMemoryPressureWatch=no\nProtectControlGroups=no\n');
}
let script = fs.readFileSync('/native/systemd-lab.sh', 'utf8');
script = script.replace('test "$(cat /sys/class/dmi/id/sys_vendor)" = QEMU', 'test "$(cat /etc/meshpn-admin-disposable-lab)" = isolated-admin-lab-v1')
  .replace('grep -qw meshpn.native-systemd=1 /proc/cmdline', 'test "$(cat /run/systemd/container)" = podman');
// ip netns exec also mounts a new sysfs, disallowed in this container. The
// fixture needs only the network namespace; retain the restricted mount view.
script = script.replace('ip() { /usr/bin/ip "$@"; }', 'ip() { if [ "$1" = netns ] && [ "$2" = exec ]; then ns="$3"; shift 3; /usr/bin/nsenter --net="/run/netns/$ns" -- "$@"; elif [ "$1" = -n ]; then ns="$2"; shift 2; /usr/bin/nsenter --net="/run/netns/$ns" -- /usr/bin/ip "$@"; else /usr/bin/ip "$@"; fi; }');
put('/native/systemd-lab.sh', script, 0o755);
put('/native/admin-guard.sh', fs.readFileSync('/native/admin-guard.sh','utf8').replaceAll('/usr/bin/ip netns exec nc2 ', '/usr/bin/nsenter --net=/run/netns/nc2 -- '), 0o755);
// The test driver is started explicitly after the isolated frontend container.
put('/etc/systemd/system/default.target', '[Unit]\nWants=dbus.service\nAfter=dbus.service\n');
put('/etc/systemd/system/native-lab-driver.service', '[Unit]\nAfter=dbus.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/node /project/scripts/lib/native-admin-vm.mjs --container-fixture\nTimeoutStartSec=5min\n');
// Both containers share only this named-volume directory, not host /run or bus.
let broker = fs.readFileSync('/etc/systemd/system/meshpn-admin-broker.service', 'utf8');
broker = broker.replace('RuntimeDirectory=meshpn-admin\nRuntimeDirectoryMode=0750\n', '')
  .replace('ExecStart=', 'ExecStartPre=/usr/bin/node /project/admin/test/systemd-socket-clean.mjs\nExecStart=');
put('/etc/systemd/system/meshpn-admin-broker.service', broker);
fs.mkdirSync('/shared/socket', {recursive: true, mode: 0o750}); fs.chownSync('/shared/socket', 0, 65534);
fs.mkdirSync('/shared/web', {recursive: true, mode: 0o700}); fs.chownSync('/shared/web', 65534, 65534);

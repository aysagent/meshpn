import test from 'node:test';
import assert from 'node:assert/strict';
import {usbAdminSocketUnit,upgradeUsbAdminSocket} from '../lib/socket-unit.mjs';
const old=`# meshpn-admin-owned-v1
[Unit]
Description=MeshPN administration bound to USB device
After=clean-vpn-usb-rescue-address.service
Wants=clean-vpn-usb-rescue-address.service
[Socket]
ListenStream=192.168.7.1:80
ListenStream=192.168.7.1:8443
BindToDevice=usb0
FreeBind=yes
Service=meshpn-admin-web.service
[Install]
WantedBy=sockets.target
`;
test('upgrade removes early socket ordering while preserving USB isolation and shutdown ordering',()=>{
 const unit=upgradeUsbAdminSocket(old);
 assert.match(unit,/DefaultDependencies=no/);
 assert.match(unit,/Conflicts=shutdown.target\nBefore=shutdown.target/);
 assert.match(unit,/After=clean-vpn-usb-rescue-address.service/);
 assert.match(unit,/BindToDevice=usb0/);
 assert.match(unit,/WantedBy=multi-user.target sys-subsystem-net-devices-usb0.device/);
 assert.doesNotMatch(unit,/sockets.target/);
 assert.equal(unit,'# meshpn-admin-owned-v1\n'+usbAdminSocketUnit());
 assert.equal(upgradeUsbAdminSocket(unit),unit);
});
test('update refuses administrator modifications rather than overwriting them',()=>{
 for(const modified of [old+'# local change\n',old.replace('192.168.7.1:80','0.0.0.0:80'),old.replace('BindToDevice=usb0\n','')])
  assert.throws(()=>upgradeUsbAdminSocket(modified),/admin_socket_unit_changed/);
});

// USB address setup is an ordinary service ordered after basic.target. A socket
// in sockets.target with default dependencies would create a boot ordering cycle.
const marker = '# meshpn-admin-owned-v1\n';
function render(legacy = false,address='192.168.7.1') {
 if(!['192.168.7.1','192.168.8.1'].includes(address))throw Error('admin_usb_address');
 return `[Unit]
Description=MeshPN administration bound to USB device
${legacy ? '' : 'DefaultDependencies=no\n'}After=clean-vpn-usb-rescue-address.service
Wants=clean-vpn-usb-rescue-address.service
${legacy ? '' : 'Conflicts=shutdown.target\nBefore=shutdown.target\n'}[Socket]
ListenStream=${address}:80
ListenStream=${address}:8443
BindToDevice=usb0
FreeBind=yes
Service=meshpn-admin-web.service
[Install]
WantedBy=${legacy ? 'sockets.target' : 'multi-user.target sys-subsystem-net-devices-usb0.device'}
`;
}
export const usbAdminSocketUnit = (address='192.168.7.1') => render(false,address);
export function upgradeUsbAdminSocket(current,address='192.168.7.1') {
 if (![marker + render(true,address), marker + render(false,address)].includes(current)) throw Error('admin_socket_unit_changed');
 return marker + render(false,address);
}

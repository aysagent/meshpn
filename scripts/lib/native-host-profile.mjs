// Host network identity is installation-time configuration, never HTTP input.
import assert from 'node:assert/strict';
export function nativeHostProfile(c={}) {
 const address=c.usb_address===undefined?'192.168.7.1':c.usb_address,uplink=c.uplink===undefined?'wlan0':c.uplink;
 assert.ok(['192.168.7.1','192.168.8.1'].includes(address),'native_usb_address');
 assert.ok(uplink==='auto'||/^(?:wlan[0-9]+|en[a-zA-Z0-9_.-]{1,13}|eth[0-9]+)$/.test(uplink),'native_uplink_interface');
 assert.ok(c.usb_backend===undefined||['dnsmasq','networkd'].includes(c.usb_backend),'native_usb_backend');
 return {address,subnet:address.replace(/\.1$/,'.0/24'),uplink};
}

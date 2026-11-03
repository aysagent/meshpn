#!/usr/bin/env bash
# Owned ECM gadget. DHCP must already be listening before UDC bind.
set -euo pipefail
modprobe libcomposite
cv_gadget=/sys/kernel/config/usb_gadget/g1
if [[ -d "$cv_gadget" ]]; then
  [[ "$(cat "$cv_gadget/strings/0x409/manufacturer")" == MeshPN ]] || exit 1
  [[ -d "$cv_gadget/functions/ecm.usb0" ]] || exit 1
else
  mkdir "$cv_gadget"
  printf '0x1d6b\n' > "$cv_gadget/idVendor"
  printf '0x0104\n' > "$cv_gadget/idProduct"
  printf '0x0100\n' > "$cv_gadget/bcdDevice"
  printf '0x0200\n' > "$cv_gadget/bcdUSB"
  mkdir "$cv_gadget/strings/0x409"
  cat /etc/machine-id > "$cv_gadget/strings/0x409/serialnumber"
  printf 'MeshPN\n' > "$cv_gadget/strings/0x409/manufacturer"
  printf 'USB Ethernet\n' > "$cv_gadget/strings/0x409/product"
  mkdir "$cv_gadget/configs/c.1" "$cv_gadget/functions/ecm.usb0"
  printf '02:00:00:00:00:01\n' > "$cv_gadget/functions/ecm.usb0/host_addr"
  printf '02:00:00:00:00:02\n' > "$cv_gadget/functions/ecm.usb0/dev_addr"
  ln -s "$cv_gadget/functions/ecm.usb0" "$cv_gadget/configs/c.1/ecm.usb0"
fi
if [[ -z "$(cat "$cv_gadget/UDC")" ]]; then
  cv_udcs=(/sys/class/udc/*)
  [[ ${#cv_udcs[@]} == 1 && -e "${cv_udcs[0]}" ]] || exit 1
  printf '%s\n' "${cv_udcs[0]##*/}" > "$cv_gadget/UDC"
fi
# This vendor kernel creates usb0 after bind. Never flush its rescue address.
for ((cv_wait=0;cv_wait<50;cv_wait++)); do
  [[ -e /sys/class/net/usb0 ]] && break
  sleep 0.1
done
ip address replace 192.168.7.1/24 dev usb0
ip link set usb0 up

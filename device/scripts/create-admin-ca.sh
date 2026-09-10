#!/usr/bin/env bash
# Generate a personal CA and a meshpn.local server identity on the host.
# The CA private key must never be uploaded to the dongle.
set -euo pipefail
umask 077
output="${1:-device/tls}"
if [[ -e "$output" ]]; then
  echo "Refusing to overwrite existing certificate directory: $output" >&2
  exit 1
fi
mkdir -p "$output"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
  -days 3650 -subj "/CN=MeshPN Personal Admin CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$output/ca.key" -out "$output/ca.crt"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
  -subj "/CN=meshpn.local" \
  -addext "subjectAltName=DNS:meshpn.local,DNS:meshpn.home.arpa,IP:192.168.7.1,IP:192.168.4.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout "$output/device.key" -out "$output/device.csr"
openssl x509 -req -in "$output/device.csr" -CA "$output/ca.crt" \
  -CAkey "$output/ca.key" -CAcreateserial -days 365 -sha256 -copy_extensions copy \
  -out "$output/device.crt"
openssl verify -CAfile "$output/ca.crt" -verify_hostname meshpn.local "$output/device.crt"
openssl x509 -in "$output/ca.crt" -noout -fingerprint -sha256
echo "Install/trust ca.crt on your hosts. Import device.crt + device.key in the HTTPS admin UI, then reboot."
echo "Keep ca.key private on this host. Requires OpenSSL 3.x."

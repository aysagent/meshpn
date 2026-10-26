#!/usr/bin/env bash
# Linux/amd64 worker used only by clean-vpn-native-macos-lab.mjs.
set -euo pipefail
umask 077

readonly LAB=/lab
readonly SOURCE=/source
readonly WORK=/lab/worktree
readonly STATE=/lab/state
readonly BASES=/lab/bases
readonly RESULTS=/lab/results
readonly TOOLS=/opt/meshpn-vm-tools
readonly NATIVE_QEMU=/opt/meshpn-native-qemu/qemu-system-x86_64

fail() { printf 'CLEAN_VPN_MACOS_LAB_ERROR=%s\n' "$1" >&2; exit 1; }
test "$(uname -m)" = x86_64 || fail container_not_amd64
test -d "$SOURCE/.git" || fail source_repository_missing
test -d "$LAB" || fail cache_volume_missing
mkdir -p "$WORK" "$STATE" "$BASES" "$RESULTS" /export
chmod 0700 "$LAB" "$WORK" "$STATE" "$BASES" "$RESULTS" /export 2>/dev/null || true

sync_source() {
  local next="$STATE/tracked-files.next" entry
  git -c safe.directory="$SOURCE" -C "$SOURCE" ls-files -z >"$next"
  if test -f "$STATE/tracked-files"; then
    while IFS= read -r -d '' entry; do
      case "$entry" in ''|/*|../*|*/../*|*/..) fail invalid_cached_source_path ;; esac
      rm -f -- "$WORK/$entry"
    done <"$STATE/tracked-files"
  fi
  # Preserve source mtimes so an unchanged tracked worktree does not make
  # CMake rebuild every C/C++ translation unit on each container run.
  (cd "$SOURCE" && cpio --null --pass-through --make-directories --unconditional \
    --preserve-modification-time "$WORK" <"$next" >/dev/null 2>&1)
  mv -f -- "$next" "$STATE/tracked-files"
}

source_key() {
  local entry
  while IFS= read -r -d '' entry; do
    case "$entry" in
      package.json|package-lock.json|scripts/*.mjs|scripts/*.js|scripts/*.sh|scripts/lib/*.mjs|scripts/autostart/*.sh|scripts/fixtures/usb-dns-v2-guard.txt|native/boring_tls/*.txt|native/boring_tls/*.cc|native/boring_tls/*.h|native/boring_tls/patches/*|native/tun_linux/*)
        test -f "$WORK/$entry" && sha256sum "$WORK/$entry"
        ;;
    esac
  done <"$STATE/tracked-files" | sort | sha256sum | cut -d' ' -f1
}

build_current() {
  cd "$WORK"
  if ! test -f node_modules/ws/package.json || ! test -f node_modules/@matrixai/logger/package.json; then
    # @infisical/quic@1.0.8 advertises an optional linux-arm package that was
    # never published. npm 11 validates that dangling edge even with
    # --omit=optional. Keep the repository lock untouched and remove only the
    # impossible edge from the private cached worktree used by this lab.
    node <<'NODE'
const fs = require('node:fs');
const file = 'package-lock.json';
const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
const name = '@infisical/quic-linux-arm';
const quic = lock.packages?.['node_modules/@infisical/quic'];
if (quic?.optionalDependencies?.[name] === '1.0.8' && !lock.packages[`node_modules/${name}`]) {
  delete quic.optionalDependencies[name];
  fs.writeFileSync(file, `${JSON.stringify(lock, null, 2)}\n`);
  console.error(`Ignoring unpublished optional dependency ${name}@1.0.8 in lab cache`);
}
NODE
    PUPPETEER_SKIP_DOWNLOAD=1 npm ci --ignore-scripts --omit=optional
  fi
  if ! test -f native/tun_linux/build/Release/tun_linux.node; then
    ./node_modules/.bin/node-gyp rebuild -C native/tun_linux
  fi
  cmake -S native/boring_tls -B native/boring_tls/build -DCMAKE_BUILD_TYPE=Release
  cmake --build native/boring_tls/build --target boring-tls-helper --parallel 2
  cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCVPN_SANITIZE=OFF -DCVPN_LOW_MEMORY_BUILD=OFF \
    "-DCVPN_BORINGSSL_SOURCE=$WORK/native/boring_tls/build/_deps/boringssl-src" \
    "-DCVPN_JSON_SOURCE=$WORK/native/boring_tls/build/_deps/json-src"
  cmake --build native/clean_vpn/build --parallel 2 --target \
    clean-vpn-engine clean-vpn-engine-fixture protocol-test dns-wire-test dns-relay-test \
    integration-test service-notify-test socket-test transparent-test \
    transparent-socket-test transparent-replay-test combo-test throughput-test tls-profile-test certificate-compression-test http2-alps-test
  ctest --test-dir native/clean_vpn/build --output-on-failure
}

latest_directory() {
  local parent="$1" pattern="$2"
  find "$parent" -mindepth 1 -maxdepth 1 -type d -name "$pattern" -print0 | \
    xargs -0 -r ls -1dt | head -n 1
}

prepare_base() {
  local release key root dns_dir host_dir
  release="$(cat /opt/meshpn-kernel-release)"
  key="$(printf '%s\n%s\n' "$(source_key)" "$release" | sha256sum | cut -d' ' -f1)"
  if test "${CVPN_REFRESH_BASE:-0}" = 1; then key="${key}-$(date -u +%Y%m%dT%H%M%SZ)"; fi
  root="$BASES/$key"
  if test -f "$STATE/host-base-path" && test "$(cat "$STATE/base-key" 2>/dev/null || true)" = "$key"; then
    host_dir="$(cat "$STATE/host-base-path")"
    if test -f "$host_dir/report.json" && node -e 'const r=require(process.argv[1]);if(r.status!=="passed")process.exit(1)' "$host_dir/report.json"; then
      printf '%s\n' "$host_dir"
      return
    fi
  fi
  mkdir -p "$root/dns" "$root/host"
  cd "$WORK"
  TMPDIR="$root/dns" node scripts/dns-vm-lab.mjs \
    "--tools=$TOOLS" "--kernel=/boot/vmlinuz-$release" "--kernel-release=$release" \
    --resolved=/usr/lib/systemd/systemd-resolved --case=cycle --nested-emulation \
    "--qemu=$NATIVE_QEMU"
  dns_dir="$(latest_directory "$root/dns" 'meshpn-dns-vm-*')"
  test -n "$dns_dir" && test -f "$dns_dir/report.json" || fail dns_base_missing
  TMPDIR="$root/host" node scripts/clean-vpn-host-boot-lab.mjs \
    "--tools=$TOOLS" "--kernel=/boot/vmlinuz-$release" "--kernel-release=$release" \
    --resolved=/usr/lib/systemd/systemd-resolved --dns-conntrack=/usr/sbin/conntrack \
    --dnsmasq=/usr/sbin/dnsmasq "--verified-report=$dns_dir/report.json" --firewall-backend=nft \
    --nested-emulation "--qemu=$NATIVE_QEMU"
  host_dir="$(latest_directory "$root/host" 'meshpn-host-boot-*')"
  test -n "$host_dir" && test -f "$host_dir/report.json" || fail host_base_missing
  node -e 'const r=require(process.argv[1]);if(r.status!=="passed")process.exit(1)' "$host_dir/report.json"
  printf '%s\n' "$key" >"$STATE/base-key"
  printf '%s\n' "$host_dir" >"$STATE/host-base-path"
  printf '%s\n' "$host_dir"
}

status() {
  local base latest
  base="$(cat "$STATE/host-base-path" 2>/dev/null || true)"
  latest="$(latest_directory "$RESULTS" 'meshpn-native-lab-*' 2>/dev/null || true)"
  node -e 'console.log(JSON.stringify({status:"ok",platform:process.platform,arch:process.arch,cache:{base:process.argv[1]||null,baseReady:!!process.argv[1]&&require("fs").existsSync(process.argv[1]+"/report.json"),latestResult:process.argv[2]||null}},null,2))' "$base" "$latest"
}

run_lab() {
  local mode="$1" base result exported
  build_current
  base="$(prepare_base | tail -n 1)"
  cd "$WORK"
  TMPDIR="$RESULTS" node scripts/clean-vpn-native-lab.mjs "$base" "$TOOLS/root" "$mode" \
    "--qemu=$NATIVE_QEMU" --nested-emulation
  result="$(latest_directory "$RESULTS" 'meshpn-native-lab-*')"
  test -n "$result" && test -f "$result/report.json" || fail native_report_missing
  node -e 'const r=require(process.argv[1]);if(r.status!=="passed")process.exit(1)' "$result/report.json"
  exported="/export/$(basename "$result")"
  test ! -e "$exported" || fail export_collision
  cp -a -- "$result" "$exported"
  printf 'CLEAN_VPN_MACOS_LAB=passed\nREPORT=%s\n' "$exported/report.json"
}

case "${1:-}" in
  tls-profiles)
    sync_source
    build_current
    cd "$WORK"
    node --test --test-concurrency=1 scripts/test-native-tls-profile.mjs scripts/test-native-data-plane.mjs scripts/test-native-session-events.mjs
    ;;
  multi-clients)
    sync_source
    build_current
    cd "$WORK"
    node --test --test-concurrency=1 scripts/test-native-clients.mjs scripts/test-native-multi-peer.mjs scripts/test-native-clients-real.mjs
    ;;
  status) status ;;
  prepare)
    sync_source
    build_current
    prepare_base >/dev/null
    status
    ;;
  run)
    test "$#" = 2 || fail run_mode_required
    case "$2" in
      --native-only|--native-systemd|--native-boot|--native-routes|--native-network|--native-site-boot|--native-transparent-boot|--native-combo-network|--native-combo-boot|--native-combo-load|--native-combo-benchmark) ;;
      *) fail invalid_run_mode ;;
    esac
    sync_source
    run_lab "$2"
    ;;
  *) fail expected_status_prepare_or_run ;;
esac

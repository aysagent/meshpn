FROM --platform=linux/arm64 ubuntu:24.04 AS native_qemu

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 \
 && mkdir -p /qemu-root \
 && paths="$(ldd /usr/bin/qemu-system-x86_64 | sed -n -e 's/.*=> \(\/[^ ]*\).*/\1/p' -e 's/^[[:space:]]*\(\/[^ ]*\)[[:space:]].*/\1/p')" \
 && cp --parents /usr/bin/qemu-system-x86_64 $paths /qemu-root \
 && if test -d /usr/lib/aarch64-linux-gnu/qemu; then cp -a --parents /usr/lib/aarch64-linux-gnu/qemu /qemu-root; fi \
 && /qemu-root/lib/ld-linux-aarch64.so.1 \
      --library-path /qemu-root/lib/aarch64-linux-gnu:/qemu-root/usr/lib/aarch64-linux-gnu \
      /qemu-root/usr/bin/qemu-system-x86_64 --version

FROM --platform=linux/amd64 node:24-bookworm-slim AS node_runtime

FROM --platform=linux/amd64 ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
COPY --from=node_runtime /usr/local/ /usr/local/

RUN printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      apt-utils bash build-essential ca-certificates cmake cpio dbus dbus-bin \
      dnsmasq e2fsprogs git golang-go iproute2 iptables kmod conntrack \
      linux-image-virtual ninja-build openssl patch perl pkg-config python3 \
      python3-setuptools qemu-system-common qemu-system-data qemu-system-x86 \
      seabios systemd systemd-resolved util-linux xz-utils zstd busybox-static \
 && rm -f /usr/sbin/policy-rc.d

RUN mkdir -p /opt/meshpn-vm-tools/root \
 && cd /opt/meshpn-vm-tools \
 && release="$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V | tail -n 1)" \
 && test -n "$release" \
 && apt-get install -y --no-install-recommends "linux-modules-extra-$release" \
 && for package in qemu-system-x86 qemu-system-common qemu-system-data seabios busybox-static; do \
      version="$(dpkg-query -W -f='${Version}' "$package")"; \
      apt-get download "$package=$version"; \
    done \
 && for archive in ./*.deb; do dpkg-deb -x "$archive" root; done \
 && test -f "/boot/vmlinuz-$release" \
 && find "/lib/modules/$release" -type f -name '*.ko.zst' -print0 | \
      xargs -0 -r -P6 -n1 bash -c 'zstd -q -d --rm "$1" -o "${1%.zst}"' _ \
 && find "/lib/modules/$release" -type f -name '*.ko.xz' -print0 | \
      xargs -0 -r -P6 -n1 xz -q -d \
 && depmod -a "$release" \
 && for module in iptable_filter ip6table_filter ipt_REJECT ip6t_REJECT xt_tcpudp dummy \
      nf_tables nft_compat nft_ct nft_chain_nat nft_nat nft_masq nft_redir \
      nft_reject_ipv4 nft_reject_ipv6 ip6table_nat xt_comment xt_multiport \
      nf_conntrack_netlink veth tun iptable_nat xt_conntrack xt_addrtype xt_nat \
      xt_MASQUERADE bridge stp llc xt_REDIRECT xt_mark iptable_mangle; do \
      modprobe --set-version "$release" --show-depends "$module" >/dev/null || { \
        printf 'required lab kernel module unavailable: %s\n' "$module" >&2; exit 1; \
      }; \
    done \
 && printf '%s\n' "$release" >/opt/meshpn-kernel-release \
 && qemu-system-x86_64 --version \
 && node --version \
 && test "$(dpkg --print-architecture)" = amd64

# systemd only recommends udev, while the cold-boot fixture needs the actual
# daemon and udevadm. Keep this in a separate layer so changing the fixture
# dependency does not invalidate the much larger kernel/tool cache above.
RUN apt-get install -y --no-install-recommends udev openssh-client openssh-server tcpdump \
 && test -x /usr/lib/systemd/systemd-udevd \
 && test -x /usr/bin/udevadm \
 && test -x /usr/sbin/sshd \
 && test -x /usr/bin/ssh \
 && test -x /usr/bin/tcpdump

COPY --from=native_qemu /qemu-root/ /opt/meshpn-native-qemu/root/
RUN printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'root=/opt/meshpn-native-qemu/root' \
      'export QEMU_MODULE_DIR="$root/usr/lib/aarch64-linux-gnu/qemu"' \
      'exec "$root/lib/ld-linux-aarch64.so.1" --library-path "$root/lib/aarch64-linux-gnu:$root/usr/lib/aarch64-linux-gnu" "$root/usr/bin/qemu-system-x86_64" "$@"' \
      >/opt/meshpn-native-qemu/qemu-system-x86_64 \
 && chmod 0755 /opt/meshpn-native-qemu/qemu-system-x86_64 \
 && /opt/meshpn-native-qemu/qemu-system-x86_64 --version

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 PUPPETEER_SKIP_DOWNLOAD=1
WORKDIR /lab/worktree

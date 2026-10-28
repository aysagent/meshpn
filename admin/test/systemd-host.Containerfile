# Disposable integration fixture only, never deploy as the admin frontend.
FROM localhost/clean-vpn-native-runtime:final-arm64 AS native
FROM docker.io/library/node:24-bookworm-slim AS node
FROM docker.io/library/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive container=podman
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus iproute2 iptables openssl g++ busybox \
    && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/bin/node
COPY --from=native /usr/local/bin/clean-vpn-engine /native/clean-vpn-engine
WORKDIR /project
COPY admin /project/admin
COPY scripts /project/scripts
COPY fixtures /project/fixtures
COPY socket_test.cc /tmp/socket_test.cc
RUN g++ -O2 /tmp/socket_test.cc -o /native/socket-test \
    && rm /tmp/socket_test.cc \
    && printf 'isolated-admin-lab-v1\n' >/etc/meshpn-admin-disposable-lab
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/bin/sh", "-c", "node admin/test/systemd-host-setup.mjs && exec /sbin/init"]

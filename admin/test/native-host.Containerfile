# Disposable systemd integration lab. No physical network or host bind mounts.
# Build admin/test/systemd-host.Containerfile as meshpn-admin-systemd-lab:local first.
FROM localhost/meshpn-admin-systemd-lab:local
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dbus conntrack avahi-daemon curl dnsutils git wpasupplicant \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service \
    && cp /native/clean-vpn-engine /usr/local/bin/clean-vpn-engine
COPY admin /project/admin
COPY scripts /project/scripts
COPY fixtures /project/fixtures
ENTRYPOINT ["/sbin/init"]

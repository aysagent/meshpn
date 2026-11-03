FROM localhost/clean-vpn-native-host-lab:20261029
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libavahi-client-dev avahi-daemon avahi-utils dnsmasq wpasupplicant \
    conntrack openssh-server openssh-client curl dnsutils git \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/sbin/init"]

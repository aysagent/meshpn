# Test-only independent packet observer. Never part of the VPN runtime.
ARG RUNTIME=localhost/clean-vpn-native-runtime:night-arm64
FROM ${RUNTIME}
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
 && rm -rf /var/lib/apt/lists/*
HEALTHCHECK NONE
ENTRYPOINT ["tcpdump"]

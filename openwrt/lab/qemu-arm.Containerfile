FROM localhost/clean-vpn-native-toolchain:night-arm64
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-system-arm && rm -rf /var/lib/apt/lists/*
RUN qemu-system-aarch64 --version
USER 1000:1000
ENTRYPOINT ["/usr/bin/qemu-system-aarch64"]

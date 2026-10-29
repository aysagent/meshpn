# Optional musl build. Use the same curated context as the Ubuntu runtime.
# Alpine 3.22.7 multi-platform index; no glibc binaries enter this image.
ARG BASE=docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
FROM ${BASE} AS build
RUN apk add --no-cache build-base cmake git go perl patch ca-certificates pkgconf
WORKDIR /src
ENV GIT_TERMINAL_PROMPT=0
ARG JOBS=1
COPY native/boring_tls/ /src/native/boring_tls/
RUN cmake -S native/boring_tls -B native/boring_tls/build -DCMAKE_BUILD_TYPE=Release
COPY native/clean_vpn/ /src/native/clean_vpn/
COPY fixtures/ /src/fixtures/
RUN apk add --no-cache linux-headers
RUN cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=Release -DCVPN_LOW_MEMORY_BUILD=ON \
 && cmake --build native/clean_vpn/build --target clean-vpn-engine --parallel "$JOBS" \
 && mkdir /out && cp native/clean_vpn/build/clean-vpn-engine /out/clean-vpn-engine \
 && strip /out/clean-vpn-engine \
 && cd /out && sha256sum clean-vpn-engine >engine.sha256

FROM ${BASE} AS runtime
RUN apk add --no-cache nodejs openssl iproute2 iptables iptables-legacy iputils-arping util-linux ca-certificates libstdc++
# Some shared control-plane/lab helpers use Debian's absolute sbin paths.
# Alpine keeps the binaries under /sbin; expose explicit aliases, not a PATH shim.
RUN for tool in ip iptables ip6tables iptables-save iptables-restore ip6tables-save ip6tables-restore; do \
      test -e "/usr/sbin/$tool" || ln -s "$(command -v "$tool")" "/usr/sbin/$tool"; \
    done
COPY --from=build /out/ /usr/local/bin/
RUN cd /usr/local/bin && sha256sum -c engine.sha256 && ./clean-vpn-engine --capabilities
COPY scripts/clean-vpn-native-runtime.mjs scripts/clean-vpn-native-runtime-health.mjs /opt/clean-vpn/
COPY scripts/lib/native-runtime-plan.mjs scripts/lib/native-runtime-address.mjs scripts/lib/native-relay-health.mjs scripts/lib/native-transparent-network.mjs /opt/clean-vpn/lib/
COPY scripts/containers/native-runtime-entrypoint.sh /usr/local/bin/native-runtime
COPY provenance.json /opt/clean-vpn/source-provenance.json
RUN chmod 0755 /usr/local/bin/native-runtime
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=2 CMD ["node", "/opt/clean-vpn/clean-vpn-native-runtime-health.mjs"]
ENTRYPOINT ["/usr/local/bin/native-runtime"]
CMD ["/config/engine.json"]

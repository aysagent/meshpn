# Build from a curated context made by clean-vpn-native-runtime-context.mjs.
# No repository-wide COPY: credentials, .git and lab artifacts never enter it.
ARG BASE=docker.io/library/ubuntu@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
ARG ENGINE_STAGE=build
FROM ${BASE} AS toolchain
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git golang-go perl patch ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

FROM toolchain AS build
ARG JOBS=2
ENV GIT_TERMINAL_PROMPT=0
COPY native/boring_tls/ /src/native/boring_tls/
RUN cmake -S native/boring_tls -B native/boring_tls/build -DCMAKE_BUILD_TYPE=Release
COPY native/clean_vpn/ /src/native/clean_vpn/
COPY fixtures/ /src/fixtures/
RUN cmake -S native/clean_vpn -B native/clean_vpn/build -DCMAKE_BUILD_TYPE=Release -DCVPN_LOW_MEMORY_BUILD=ON
RUN cmake --build native/clean_vpn/build --target clean-vpn-engine --parallel "$JOBS" \
 && mkdir /out && cp native/clean_vpn/build/clean-vpn-engine /out/clean-vpn-engine \
 && strip /out/clean-vpn-engine \
 && cd /out && sha256sum clean-vpn-engine >engine.sha256

# Explicit lab optimization, NOT a substitute for source builds. Hash-checked
# artifacts are copied from the audited build cache for the selected platform.
FROM scratch AS artifact
COPY artifacts/ /out/
FROM ${ENGINE_STAGE} AS selected

FROM ${BASE} AS runtime
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs iproute2 iptables ca-certificates libstdc++6 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=selected /out/ /usr/local/bin/
RUN cd /usr/local/bin && sha256sum -c engine.sha256 && ./clean-vpn-engine --capabilities
COPY scripts/clean-vpn-native-runtime.mjs scripts/clean-vpn-native-runtime-health.mjs /opt/clean-vpn/
COPY scripts/lib/native-runtime-plan.mjs /opt/clean-vpn/lib/
COPY scripts/containers/native-runtime-entrypoint.sh /usr/local/bin/native-runtime
COPY provenance.json /opt/clean-vpn/source-provenance.json
RUN chmod 0755 /usr/local/bin/native-runtime
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=2 CMD ["node", "/opt/clean-vpn/clean-vpn-native-runtime-health.mjs"]
ENTRYPOINT ["/usr/local/bin/native-runtime"]
CMD ["/config/engine.json"]

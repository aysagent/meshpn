# Uses the existing local systemd lab base. engine is the explicitly supplied,
# previously tested ARM64 artifact; this image does not claim a source rebuild.
ARG BASE=localhost/clean-vpn-host-admin-lab:source
FROM ${BASE}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tcpdump \
 && rm -rf /var/lib/apt/lists/*
COPY engine /usr/local/bin/clean-vpn-engine
ARG ENGINE_SHA256
RUN test -n "$ENGINE_SHA256" && echo "$ENGINE_SHA256  /usr/local/bin/clean-vpn-engine" | sha256sum -c -

# Curated native-runtime-context only. The supplied VPN image must be an audited
# source-built Ubuntu or Alpine runtime for the selected architecture.
ARG VPN_IMAGE=localhost/clean-vpn-native-runtime:quota-final-20261029
ARG ALPINE_BASE=docker.io/library/alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
ARG WEB_BASE=docker.io/library/node@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c
FROM ${VPN_IMAGE} AS vpn
COPY scripts/ /opt/clean-vpn/scripts/
COPY admin/lib/ /opt/clean-vpn/admin/lib/
ENTRYPOINT ["node", "/opt/clean-vpn/scripts/clean-vpn-container-broker.mjs"]
CMD ["/config/engine.json"]

FROM ${WEB_BASE} AS web
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY admin/ ./admin/
COPY scripts/lib/ ./scripts/lib/
COPY scripts/clean-vpn-container-web.mjs ./scripts/
USER node
CMD ["node", "scripts/clean-vpn-container-web.mjs", "/var/lib/meshpn-admin-web/web.json"]

FROM ${ALPINE_BASE} AS web-alpine
RUN apk add --no-cache nodejs openssl \
 && addgroup -g 1000 node && adduser -D -u 1000 -G node node
WORKDIR /app
COPY admin/ ./admin/
COPY scripts/lib/ ./scripts/lib/
COPY scripts/clean-vpn-container-web.mjs ./scripts/
USER node
CMD ["node", "scripts/clean-vpn-container-web.mjs", "/var/lib/meshpn-admin-web/web.json"]

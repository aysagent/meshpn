# Separate disposable browser image; never installs a browser or CA on the host.
FROM docker.io/library/node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium libnss3-tools openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /home/node/.pki/nssdb \
 && chown -R node:node /home/node/.pki
USER node
WORKDIR /source
ENV PUPPETEER_SKIP_DOWNLOAD=1

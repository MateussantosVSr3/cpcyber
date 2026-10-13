FROM node:22-bookworm-slim
ARG CODEX_VERSION=latest
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @openai/codex@${CODEX_VERSION} \
    && codex --version
WORKDIR /app
COPY --chown=node:node rpc.mjs server.mjs ./
RUN mkdir -p /home/node/.codex /tmp/sast-review && chown -R node:node /home/node/.codex /tmp/sast-review
ENV CODEX_HOME=/home/node/.codex HOST=0.0.0.0 CODEX_CA_CERTIFICATE=/etc/ssl/certs/ca-certificates.crt
USER node
CMD ["node", "server.mjs"]

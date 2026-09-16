ARG BASE_IMAGE=node-agent-telemetry-test:latest
FROM ${BASE_IMAGE}
ARG BUILD_PROXY=http://host.docker.internal:10886
RUN http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" apt-get update \
 && http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" apt-get install -y --no-install-recommends python3-pyftpdlib python3-openssl openssl iproute2 \
 && rm -rf /var/lib/apt/lists/*

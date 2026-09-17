FROM debian:bookworm-slim
ARG BUILD_PROXY=http://host.docker.internal:10886
RUN http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" apt-get update \
 && DEBIAN_FRONTEND=noninteractive http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" \
    apt-get install -y --no-install-recommends ca-certificates python3 python3-pyftpdlib \
    python3-openssl openssl iproute2 procps filezilla xvfb xdotool openbox dbus-x11 scrot \
 && rm -rf /var/lib/apt/lists/*

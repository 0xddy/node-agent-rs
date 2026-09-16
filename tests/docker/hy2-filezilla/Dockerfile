ARG BASE_IMAGE=node-agent-ftp-test:20260916
FROM ${BASE_IMAGE}
ARG BUILD_PROXY=http://host.docker.internal:10886
RUN http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" apt-get update \
 && DEBIAN_FRONTEND=noninteractive http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" \
    apt-get install -y --no-install-recommends filezilla xvfb xdotool openbox dbus-x11 scrot \
 && rm -rf /var/lib/apt/lists/*

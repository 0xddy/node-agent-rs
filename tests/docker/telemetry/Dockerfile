FROM debian:bookworm-slim
ARG BUILD_PROXY=http://host.docker.internal:10886
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" apt-get update \
 && http_proxy="$BUILD_PROXY" https_proxy="$BUILD_PROXY" apt-get install -y --no-install-recommends ca-certificates curl build-essential cmake pkg-config perl python3 \
 && rm -rf /var/lib/apt/lists/*
RUN https_proxy="$BUILD_PROXY" curl --fail --show-error --silent https://sh.rustup.rs -o /tmp/rustup.sh \
 && https_proxy="$BUILD_PROXY" http_proxy="$BUILD_PROXY" sh /tmp/rustup.sh -y --profile minimal --default-toolchain 1.91.1 \
 && rm /tmp/rustup.sh

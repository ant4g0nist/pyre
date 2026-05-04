# Dev image for Pyre: emsdk + node + JDK 21 + gradle.
# Run via lima or any plain docker host.
#
# Usage:
#   docker build -t pyre-dev -f docker/Dockerfile .
#   docker run --rm -it -v "$PWD":/work -w /work -p 5173:5173 pyre-dev
#
# Inside the container:
#   ./decompiler-wasm/build.sh
#   ./specs/stage-specs.sh
#   cd web && npm install && npm run dev -- --host 0.0.0.0

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG EMSDK_VERSION=latest
ARG NODE_MAJOR=22

# Base toolchain. python3 is needed by emsdk's installer, openjdk for
# Ghidra's gradle build that runs sleighc.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential cmake \
        python3 python3-pip xz-utils \
        openjdk-21-jdk-headless gradle \
    && rm -rf /var/lib/apt/lists/*

# Node via NodeSource — Ubuntu's apt node is stuck at 18.x.
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# emsdk into /opt so any user (incl. root) inherits the tooling.
RUN git clone --depth 1 https://github.com/emscripten-core/emsdk.git /opt/emsdk \
    && cd /opt/emsdk \
    && ./emsdk install $EMSDK_VERSION \
    && ./emsdk activate $EMSDK_VERSION

# Source emsdk env in every interactive shell — the build scripts auto-source
# too but this saves a step for ad-hoc work in the container.
RUN echo '. /opt/emsdk/emsdk_env.sh > /dev/null 2>&1' >> /etc/bash.bashrc

ENV PATH="/opt/emsdk:/opt/emsdk/upstream/emscripten:/opt/emsdk/upstream/bin:${PATH}"
ENV EMSDK="/opt/emsdk"

WORKDIR /work
EXPOSE 5173
CMD ["bash"]

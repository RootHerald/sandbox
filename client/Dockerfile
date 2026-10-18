FROM ubuntu:24.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y build-essential cmake pkg-config libtss2-dev libssl-dev libcurl4-openssl-dev swtpm swtpm-tools && rm -rf /var/lib/apt/lists/*
COPY sdk/linux-x64 /sandbox/sdk/linux-x64
COPY client/main.c client/platform.h client/platform_linux.c client/CMakeLists.txt client/CMakePresets.json /sandbox/client/
WORKDIR /sandbox/client
RUN cmake --preset linux
RUN cmake --build --preset linux

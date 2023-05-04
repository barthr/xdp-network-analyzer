FROM ubuntu:22.04

ARG GOVERSION=1.19.8
ARG ARCH=amd64

# Download development environment.
RUN apt-get update && \
    apt-get install -y \
        git \
        libbpf-dev \
        make \
        clang \
        iproute2 \
        gcc-multilib \
        llvm \
        libelf-dev

# Install Go specific version.
RUN apt-get install -y wget && \
    wget https://golang.org/dl/go${GOVERSION}.linux-${ARCH}.tar.gz && \
    tar -xf go${GOVERSION}.linux-${ARCH}.tar.gz && \
    mv go/ /usr/local/ && \
    ln -s /usr/local/go/bin/go /usr/local/bin/ && \
    rm -rf go${GOVERSION}.linux-${ARCH}.tar.gz

## Download libbpf and install it
RUN git clone --branch v1.2.0 https://github.com/libbpf/libbpf.git && \
    cd libbpf && \
    mkdir build root && \
    cd src && \
    BUILD_STATIC_ONLY=y OBJDIR=../build DESTDIR=../output make install && \
    UAPIDIR=../ouptut make install_uapi_headers
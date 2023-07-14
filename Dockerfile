FROM ubuntu:22.04

# Define variables.
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

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
  cd bpftool/src && \
  make && \
  mv ./bpftool /usr/bin/bpftool

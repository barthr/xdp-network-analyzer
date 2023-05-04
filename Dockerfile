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
FROM ubuntu:22.04

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

RUN git clone https://github.com/libbpf/bpftool.git && \
  cd bpftool/src && \
  make && \
  mv ./bpftool /usr/bin/bpftool
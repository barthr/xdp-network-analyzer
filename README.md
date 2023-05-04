## Network analyzer with XDP

This is a simple network analyzer that uses XDP to capture packets and process them in userspace. The control plane is
written in Go and the data plane is written in C. The data plane is loaded as an XDP program.

### Requirements

- Linux kernel >= 4.18
- Go >= 1.11
- libbpf
- clang
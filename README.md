## Network analyzer with XDP

This is a simple network analyzer that uses XDP to capture packets and process them in userspace. The control plane is
written in Go and the data plane is written in C. The data plane is loaded as an XDP program.

### Requirements

- Linux kernel >= 4.18
- Go >= 1.19
- Clang

### Building

For the XDP program a docker container is used including most of the required dependencies except libbpf. I am using
Fedora which includes libbpf in the kernel-devel package and mounted to the container this will create a xdp binary with
the correct dependencies setup.

However, these steps can change depending on your distro. If you are using a different distro follow the steps for your
given distro

To build the container run:

```bash
task builder
```

To build the XDP program run:

```bash
task xdp_build
```

To build the control plane go program run (this will require golang):

```bash
task build_control_plane

```
# linux-gre-keepalive

This eBPF program adds high-performance reply-only GRE keepalive support for Linux kernel.

## Usage

### Install Build Dependencies

Debian:

```shell
sudo apt install clang llvm libelf-dev gcc-multilib linux-headers-amd64
```

### Building

```shell
make all
```

### Enabling

Assume you have set up the GRE tunnel as `gre0`. To enable GRE keepalive:

```shell
ip link set dev gre0 xdp object gre_keepalive.o
```

To disable it:

```shell
ip link set dev gre0 xdp off
```

Note that this command must be invoked every time a new GRE tunnel is set up.

## References

Here's a list of awesome articles and projects I found useful:

* [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
* [xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)
* [dpino/xdp_ipv6_filter](https://github.com/dpino/xdp_ipv6_filter)
* [How GRE Keepalives Work](https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/63760-gre-keepalives-63760.html)
* [OISF/suricata](https://github.com/OISF/suricata)
* [iovisor/bpf-docs](https://github.com/iovisor/bpf-docs)
* [PaulTimmins/linux-gre-keepalive](https://github.com/PaulTimmins/linux-gre-keepalive)
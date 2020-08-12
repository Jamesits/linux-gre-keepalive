# linux-gre-keepalive

This eBPF program adds high-performance reply-only GRE keepalive support for Linux kernel.

[![Build Status](https://dev.azure.com/nekomimiswitch/General/_apis/build/status/linux-gre-keepalive?branchName=master)](https://dev.azure.com/nekomimiswitch/General/_build/latest?definitionId=78&branchName=master)

Note: If you don't want to install anything and don't care about some potential security problems, just enable the following 2 options to get native GRE keepalive support on Linux:
```
sysctl net.ipv4.conf.default.accept_local=1
sysctl net.ipv4.conf.all.accept_local=1
```

## Compatiblity

| Protocol 	| Linux name 	| XDP Executable   	| Tested Vendors  	| Comments    	|
|----------	|------------	|------------------	|-----------------	|-------------	|
| GRE      	| gre        	| keepalive_gre.o  	| Cisco, MikroTik 	|             	|
| GRE6     	| ip6gre     	| keepalive_gre6.o 	| MikroTik       	|             	|

## Usage

Simply load the correct XDP executable on the tunnel interface you just created. For example, assume you have set up the GRE tunnel as `gre0`, to enable GRE keepalive:

```shell
ip link set dev gre0 xdp object build/keepalive_gre.o
```

To disable it without removing the tunnel interface:

```shell
ip link set dev gre0 xdp off
```

Loading an executable on other types of interfaces is considered an undefined behavior.

## Caveats

### GRE on Cisco IOS XE

On Cisco IOS XE, you must explicitly configure an ip address or an ipv6 address to make the GRE tunnel actually send something. If you don't configure IP addresses, `debug tunnel keepalive` will still show keepalive packets being sent, but the other end won't receive anything. A valid configuration example:

```
interface Tunnel10
 ip address 10.0.0.1 255.255.255.0
 keepalive 1 2
 tunnel source GigabitEthernet1
 tunnel destination your.other.end.ip.address
 tunnel mode gre ip
```

### GRE6 (ip6gre) keepalive support

GRE6 keepalive is not supported by:

* [Cisco IOS XE](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/interface/configuration/xe-16-6/ir-xe-16-6-book/ir-gre-ipv6-tunls-xe.html#GUID-B8369497-671A-4B51-A749-A81971011A29)
* [Juniper JunOS](https://www.juniper.net/documentation/en_US/junos/topics/concept/gre-keepalive-time-overview.html)

MikroTik RouterOS implements their own GRE IPv6 keepalive with inner GRE header's proto field set to `0x86dd`. This have been implemented by us.

## Building

Assume we are on a Debian 10.

```shell
sudo apt install build-essential clang llvm libelf-dev gcc-multilib linux-headers-$(dpkg --print-architecture)
make all
```

### Debugging

View compiled bytecode:

```shell
llvm-objdump -S build/keepalive_gre.o
```

Enabling debugging output:

```c
#define DEBUG
#define DEBUG_PRINT_HEADER_SIZE 32
```

Then view debug output after enabling it by:

```shell
cat /sys/kernel/debug/tracing/trace_pipe
```

## References

Here's a list of awesome articles and projects I found useful:

* [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
* [xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)
* [dpino/xdp_ipv6_filter](https://github.com/dpino/xdp_ipv6_filter)
* [How GRE Keepalives Work](https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/63760-gre-keepalives-63760.html)
* [OISF/suricata](https://github.com/OISF/suricata)
* [iovisor/bpf-docs](https://github.com/iovisor/bpf-docs)
* [PaulTimmins/linux-gre-keepalive](https://github.com/PaulTimmins/linux-gre-keepalive)
* [An introduction to Linux virtual interfaces: Tunnels](https://developers.redhat.com/blog/2019/05/17/an-introduction-to-linux-virtual-interfaces-tunnels/)

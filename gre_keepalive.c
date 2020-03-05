/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// enable debug print
// #define DEBUG
// enable packet header dump
// #define DEBUG_PRINT_HEADER_SIZE 32

char _license[4] SEC("license") = "GPL";

struct gre_hdr {
	__be16 flags;
	__be16 proto;
};

// have to be static and __always_inline, otherwise you will have `Error fetching program/map!`
static __always_inline bool compare_ipv6_address(struct in6_addr *a, struct in6_addr *b) {
	#pragma unroll
	for (int i = 0; i < 16; ++i) {
		if (a->in6_u.u6_addr8[i] != b->in6_u.u6_addr8[i]) return false;
	}
	return true;
}

SEC("prog")
int xdp_gre_keepalive_func(struct xdp_md *ctx)
{
	// for border checking
	void *data_start = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// result
	__u32 action = XDP_PASS;

	// current parsed header position pointer
	void *dataptr = data_start;

	#ifdef DEBUG
		bpf_printk("New packet\n");
	#endif

	// debug print packet header
	#if (defined DEBUG_PRINT_HEADER_SIZE) && (DEBUG_PRINT_HEADER_SIZE > 0)
		// check for out of boarder access is necessary, kernel will run static analysis on our program
		if ((dataptr + DEBUG_PRINT_HEADER_SIZE) > data_end) {
			bpf_printk("Packet size too small, dump failed\n");
			goto out;
		}
		__u8 *data_raw = (__u8 *)dataptr;
		bpf_printk("Packet header dump:\n");
		#pragma unroll
		for (int i = 0; i < DEBUG_PRINT_HEADER_SIZE; ++i) {
			bpf_printk("#%d: %x\n", i, data_raw[i]);
		}
	#endif

	// decide if this is an IP packet or an IPv6 packet
	// to do this, we check the first byte of the packet
	__u8 outer_ip_type = 0;
	struct iphdr *outer_iphdr;
	struct ipv6hdr *outer_ipv6hdr;

	// if the packet is from GREv6 (tunnel mode ip6gre), then it starts with an ethernet header:
	// * dst MAC address (6 bytes)
	// * src MAC address (6 bytes)
	// * ethernet proto (0x86dd, 2 bytes)
	// Then comes IPv6 header.
	// So we skip the first 12 bytes and verify ethernet proto field and IPv6 header version field
	if ((dataptr + 15) > data_end) goto out;
	if (
		((__u16 *)dataptr)[6] == 0xdd86
		&& (((__u8 *)dataptr)[14] & 0xF0) == 0x60
		) {
		outer_ip_type = 6;
		dataptr += 14;
	} else if ((((__u8 *)dataptr)[0] & 0xF0) == 0x40) {
		// if the packet is from GREv4 (tunnel mode gre), then it starts straight with IP header
		outer_ip_type = 4;
	}

	#ifdef DEBUG
		bpf_printk("Outer ip type=%x\n", outer_ip_type);
	#endif

	// note: any bpf_printk inside this switch statement will make kernel static check fail
	// and I don't know why, so they are commented out
	switch (outer_ip_type) {
		case 4:
			// outer tunnel is GRE4
			// #ifdef DEBUG
			// 	bpf_printk("Outer GRE4\n");
			// #endif
			if (dataptr + sizeof(struct iphdr) > data_end) return -1;
			outer_iphdr = (struct iphdr *)dataptr;
			dataptr += sizeof(struct iphdr);
			break;
		case 6:
			// outer tunnel is GRE6
			// #ifdef DEBUG
			// 	bpf_printk("Outer GRE6\n");
			// #endif
			if (dataptr + sizeof(struct ipv6hdr) > data_end) return -1;
			outer_ipv6hdr = (struct ipv6hdr *)dataptr;
			dataptr += sizeof(struct ipv6hdr);
			break;
		default:
			// unknown packet type
			// #ifdef DEBUG
			// 	bpf_printk("Outer unknown ip type %x\n", outer_ip_type);
			// #endif
			goto out;
	}

	// now we are at the outer GRE header
	if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
	struct gre_hdr *outer_grehdr = (struct gre_hdr *)(dataptr);
	dataptr += sizeof(struct gre_hdr);
	#ifdef DEBUG
		bpf_printk("Outer GRE flags=0x%x proto=%x\n", outer_grehdr->flags, outer_grehdr->proto);
	#endif

	// here is all the headers we need to chop off before sending the packet back
	void *cutoff_pos = dataptr;

	// parse inner IP header
	if (outer_grehdr -> proto == bpf_htons(ETH_P_IP)) {
		if (dataptr + 1 > data_end) return -1;
		struct iphdr *inner_iphdr = dataptr;
		int ip_header_size = (inner_iphdr -> ihl) * 4;
		if (dataptr + 20 > data_end) return -1; // workaround kernel static check
		if (dataptr + ip_header_size > data_end) return -1;
		dataptr += ip_header_size;
		__u8 inner_ip_proto = inner_iphdr -> protocol;
		#ifdef DEBUG
			bpf_printk("IPv4 packet_size=0x%x, proto=0x%x\n", ip_header_size, inner_ip_proto);
		#endif

		// check if it is a GRE encapsulated in an IPv4 packet
		if (outer_ip_type != 4 || inner_ip_proto != IPPROTO_GRE) goto out;

		// get the inner GRE header
		if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
		struct gre_hdr *inner_grehdr = (struct gre_hdr *)(dataptr);
		dataptr += sizeof(struct gre_hdr);
		#ifdef DEBUG
			bpf_printk("Inner is GRE4, proto=%x\n", inner_grehdr -> proto);
		#endif

		// check if the GRE header is keepalive
		// we need: 
		// * proto == 0
		// * ip address match
		// 
		if (
			inner_grehdr -> proto != 0
			|| inner_iphdr -> saddr != outer_iphdr -> daddr
			|| inner_iphdr -> daddr != outer_iphdr -> saddr
			) goto out;
		#ifdef DEBUG
			bpf_printk("GRE4 keepalive received!\n");
		#endif

	} else if (outer_grehdr->proto == bpf_htons(ETH_P_IPV6)) {
		if (dataptr + sizeof(struct ipv6hdr) + 1 > data_end) return -1;
		struct ipv6hdr *inner_ipv6hdr = (struct ipv6hdr *)(dataptr);
		dataptr += sizeof(struct ipv6hdr);
		__u8 inner_ip_proto = inner_ipv6hdr -> nexthdr;
		#ifdef DEBUG
			bpf_printk("IPv6 proto=0x%x\n", inner_ip_proto);
		#endif

		// check if it is a GRE encapsulated in an IPv6 packet
		if (outer_ip_type != 6 || inner_ip_proto != IPPROTO_GRE) goto out;

		// get the inner GRE header
		if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
		struct gre_hdr *inner_grehdr = (struct gre_hdr *)(dataptr);
		dataptr += sizeof(struct gre_hdr);
		#ifdef DEBUG
			bpf_printk("Inner is GRE6, proto %x\n", inner_grehdr -> proto);
		#endif

		// check if the GRE packet is a keepalive packet
		if (
			inner_grehdr -> proto != 0xdd86 // seems to be the case for MikroTik RouterOS, TODO: verify compatibility with other vendors
			|| !compare_ipv6_address(&(outer_ipv6hdr -> saddr), &(inner_ipv6hdr -> daddr))
			|| !compare_ipv6_address(&(outer_ipv6hdr -> daddr), &(inner_ipv6hdr -> saddr))
			) goto out;
		#ifdef DEBUG
			bpf_printk("GRE6 keepalive received!\n");
		#endif

	} else {
		// unknown protocol
		#ifdef DEBUG
			bpf_printk("Unknown proto %x inside GRE", outer_grehdr->proto);
		#endif
		goto out;
	}

	// remove the header and send the packet back
	if (bpf_xdp_adjust_head(ctx, (int)(cutoff_pos - data_start))) return -1;
	action = XDP_TX;

out:
	return action;
}

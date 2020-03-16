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
#include "common.h"

// enable debug print
// #define DEBUG
// enable packet header dump
// #define DEBUG_PRINT_HEADER_SIZE 32

char _license[4] SEC("license") = "GPL";

SEC("prog")
int xdp_keepalive_gre6(struct xdp_md *ctx)
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

	struct ipv6hdr *outer_ipv6hdr;

	// if the packet is from GREv6 (tunnel mode ip6gre), then it starts with an ethernet header:
	// * dst MAC address (6 bytes)
	// * src MAC address (6 bytes)
	// * ethernet proto (0x86dd, 2 bytes)
	// Then comes IPv6 header.
	// So we skip the first 12 bytes and verify ethernet proto field and IPv6 header version field
	if ((dataptr + 15) > data_end) goto out;
	if (!(
        ((__u16 *)dataptr)[6] == 0xdd86
		&& (((__u8 *)dataptr)[14] & 0xF0) == 0x60
    )) {
        // cannot verify packet header
        goto out;
    }

    dataptr += 14; // skip to the IPv6 header

    if (dataptr + sizeof(struct ipv6hdr) > data_end) return -1;
    outer_ipv6hdr = (struct ipv6hdr *)dataptr;
    dataptr += sizeof(struct ipv6hdr);

	// now we are at the outer GRE header
	if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
	struct gre_hdr *outer_grehdr = (struct gre_hdr *)(dataptr);
	dataptr += sizeof(struct gre_hdr);
	#ifdef DEBUG
		bpf_printk("Outer GRE flags=0x%x proto=%x\n", outer_grehdr->flags, outer_grehdr->proto);
	#endif

	// here is all the headers we need to chop off before sending the packet back
	void *cutoff_pos = dataptr;

	// parse inner IP header (must be an IPv6 header too)
	if (outer_grehdr->proto == bpf_htons(ETH_P_IPV6)) {
		if (dataptr + sizeof(struct ipv6hdr) + 1 > data_end) return -1;
		struct ipv6hdr *inner_ipv6hdr = (struct ipv6hdr *)(dataptr);
		dataptr += sizeof(struct ipv6hdr);
		__u8 inner_ip_proto = inner_ipv6hdr -> nexthdr;
		#ifdef DEBUG
			bpf_printk("IPv6 proto=0x%x\n", inner_ip_proto);
		#endif

		// check if it is a GRE encapsulated in an IPv6 packet
		if (inner_ip_proto != IPPROTO_GRE) goto out;

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

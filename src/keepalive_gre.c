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
// enable Velocloud (firmware 4.3.0) to Zscaler GRE tunnel keepalive support
// by disabling cisco outer-saddr - inner-daddr and outer-daddr - inner-saddr check
// as velocloud uses actual physical and tunnel IP's for keepalive
// #define VELOCLOUD_KEEPALIVE_SUPPORT

char _license[4] SEC("license") = "GPL";

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

	struct iphdr *outer_iphdr;

	// GRE packet directly starts with an IPv4 header
	if ((dataptr + 1) > data_end) goto out;
	if ((((__u8 *)dataptr)[0] & 0xF0) != 0x40) {
		goto out;
	}

	if (dataptr + sizeof(struct iphdr) > data_end) return -1;
	outer_iphdr = (struct iphdr *)dataptr;
	dataptr += sizeof(struct iphdr);

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
		if (inner_ip_proto != IPPROTO_GRE) goto out;

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
			#ifndef VELOCLOUD_KEEPALIVE_SUPPORT
			|| inner_iphdr -> saddr != outer_iphdr -> daddr
			|| inner_iphdr -> daddr != outer_iphdr -> saddr
			#endif
			) goto out;
		#ifdef DEBUG
			bpf_printk("GRE4 keepalive received!\n");
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

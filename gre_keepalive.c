/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

char _license[4] SEC("license") = "GPL";

#define DEBUG_FAKE_HEADER_SIZE 32
struct debug_fake_hdr {
	__be16 data[32];
};

struct linux_cooked_hdr {
	char    reserved[12];
	__u32	saddr; // outer IP source address
	__u32	daddr; // outer IP destination address
};

struct gre_hdr {
	__be16 flags;
	__be16 proto;
};

SEC("prog")
int xdp_gre_keepalive_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *dataptr;
	// struct ethhdr *eth;
	// int eth_type;
	// int icmp_type;
	struct iphdr *outer_iphdr;
	struct ipv6hdr *outer_ipv6hdr;
	// __u16 echo_reply;
	// struct icmphdr_common *icmphdr;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	dataptr = data;

	// debug print header
	// if (dataptr + sizeof(struct debug_fake_hdr) > data_end) return -1;
	// struct debug_fake_hdr *debugfakehdr = (struct debug_fake_hdr *) dataptr;
	// bpf_printk("Linux reserved header debug (one number is 2 bits): \n");
	// #pragma unroll
	// for (int i = 0; i < DEBUG_FAKE_HEADER_SIZE / 2; i += 2) {
	// 	bpf_printk("%x %x\n", debugfakehdr->data[i], debugfakehdr->data[i+1]);
	// }

	// decide if this is an IP packet or an IPv6 packet
	// to do this, we check the second byte of the packet
	if ((dataptr + 1) > data_end) return -1;
	// bpf_printk("First 1 byte: %x\n", ((char *)dataptr)[0]);
	char outer_ip_type = (((char *)dataptr)[0] & 0xF0) >> 4;
	switch (outer_ip_type) {
		case 4:
			// outer tunnel is GRE4
			bpf_printk("Outer GRE4\n");
			if (dataptr + sizeof(struct iphdr) > data_end) return -1; // necessary for bypassing kernel access violation check
			outer_iphdr = (struct iphdr *)dataptr;
			dataptr += sizeof(struct iphdr);
			break;
		case 6:
			// outer tunnel is GRE6
			bpf_printk("Outer GRE6\n");
			if (dataptr + sizeof(struct ipv6hdr) > data_end) return -1;
			outer_ipv6hdr = (struct ipv6hdr *)dataptr;
			dataptr += sizeof(struct ipv6hdr);
			break;
		default:
			bpf_printk("Outer unknown %x\n", outer_ip_type);
			return -1;
	}

	// now we are at the outer GRE header
	if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
	struct gre_hdr *outer_grehdr = (struct gre_hdr *)(dataptr);
	dataptr += sizeof(struct gre_hdr);
	// bpf_printk("0x %x %x\n",grehdr->flags, grehdr->proto);

	void *cutoff_pos = dataptr;

	// parse inner IP header
	if (outer_grehdr -> proto == bpf_htons(ETH_P_IP)) {
		if (dataptr + 1 > data_end) return -1;
		struct iphdr *inner_iphdr = dataptr;
		int ip_header_size = (inner_iphdr -> ihl) * 4;
		if (dataptr + 20 > data_end) return -1; // workaround kernel static check
		if (dataptr + ip_header_size > data_end) return -1;
		dataptr += ip_header_size;
		bpf_printk("IPv4 packet_size=0x%x\n", ip_header_size);
		int inner_ip_proto = inner_iphdr -> protocol;
		bpf_printk("IPv4 proto=0x%x\n", inner_ip_proto);

		// check if it is a GRE encapsulated in an IPv4 packet
		if (outer_ip_type != 4 || inner_ip_proto != IPPROTO_GRE) goto out;

		bpf_printk("Inner is GRE\n");

		// get the inner GRE header
		if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
		struct gre_hdr *inner_grehdr = (struct gre_hdr *)(dataptr);
		dataptr += sizeof(struct gre_hdr);

		// check if the GRE header is keepalive
		bpf_printk("GRE proto %x\n", inner_grehdr -> proto);
		if (inner_grehdr -> proto != 0) goto out;
		bpf_printk("GRE keepalive!\n");

		// remove the header and send the packet back
		if (bpf_xdp_adjust_head(ctx, (int)(cutoff_pos - data))) return -1;
		action = XDP_TX;

	} else if (outer_grehdr->proto == bpf_htons(ETH_P_IPV6)) {
		if (dataptr + sizeof(struct ipv6hdr) + 1 > data_end) return -1;
		struct ipv6hdr *inner_ipv6hdr = (struct ipv6hdr *)(dataptr);
		dataptr += sizeof(struct ipv6hdr);
		int inner_ip_proto = inner_ipv6hdr -> nexthdr;

		bpf_printk("IPv6 proto=0x%x\n", inner_ip_proto);

		// check if it is a GRE encapsulated in an IPv6 packet
		if (outer_ip_type != 6 || inner_ip_proto != IPPROTO_GRE) goto out;

		// get the inner GRE header
		if (dataptr + sizeof(struct gre_hdr) > data_end) return -1;
		struct gre_hdr *inner_grehdr = (struct gre_hdr *)(dataptr);
		dataptr += sizeof(struct gre_hdr);

		// check if the GRE header is keepalive
		if (inner_grehdr -> proto != 0) goto out;
		bpf_printk("GRE6 keepalive!\n");

		// remove the header and send the packet back
		if (bpf_xdp_adjust_head(ctx, (int)(cutoff_pos - data))) return -1;
		action = XDP_TX;

	} else {
		// unknown protocol
		goto out;
	}

	action = XDP_TX;

out:
	return action;
}

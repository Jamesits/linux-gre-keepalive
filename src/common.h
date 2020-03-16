#pragma once
#ifndef __COMMON_H__
#define _COMMON_H__

struct gre_hdr {
	__be16 flags;
	__be16 proto;
};

// have to be static and __always_inline, otherwise you will have `Error fetching program/map!`
static __always_inline bool compare_ipv6_address(struct in6_addr *a, struct in6_addr *b) {
	#pragma unroll
	for (int i = 0; i < 4; ++i) {
		if (a->in6_u.u6_addr32[i] != b->in6_u.u6_addr32[i]) return false;
	}
	return true;
}

#endif
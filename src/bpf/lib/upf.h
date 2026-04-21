/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/udp.h>
#include <linux/icmpv6.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "upf-def.h"
#include "capture.h"
#include "if_rule.h"


/*
 *	MAPs
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BPF_UPF_USER_MAP_SIZE);
	__type(key, struct upf_egress_key);
	__type(value, struct upf_fwd_rule);
} user_egress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BPF_UPF_USER_MAP_SIZE);
	__type(key, struct upf_ingress_key);
	__type(value, struct upf_fwd_rule);
} user_ingress SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BPF_UPF_USER_COUNTER_MAP_SIZE);
	__type(key, __u32);
	__type(value, struct upf_urr);
} upf_urr SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 512);
	__type(key, int);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} upf_li_perf SEC(".maps");


#include "upf_urr.h"



/*
 * li
 */

static __always_inline void
upf_li_pkt(struct xdp_md *ctx, struct upf_fwd_rule *u, __u16 offset, __u16 dir_fl)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct upf_li_entry le = {
		.id = u->li_id,
		.flags = dir_fl,
		.payload_len = (__u16)(data_end - data),
		.offset = offset,
	};

	UPF_DBG("li: fwd %d bytes (off:%d)", le.payload_len, offset);
	bpf_perf_event_output(ctx, &upf_li_perf,
			      ((__u64)le.payload_len << 32) | BPF_F_CURRENT_CPU,
			      &le, sizeof(le));
}

/*
 * router advertisement
 * XXX: should be moved userland
 */

#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134

struct nd_router_advert
{
	__u32		nd_ra_reachable;   /* reachable time */
	__u32		nd_ra_retransmit;  /* retransmit timer */

	/* option: prefix information */
	__u8		nd_opt_pi_type;
	__u8		nd_opt_pi_len;
	__u8		nd_opt_pi_prefix_len;
	__u8		nd_opt_pi_flags_reserved;
	__u32		nd_opt_pi_valid_time;
	__u32		nd_opt_pi_preferred_time;
	__u32		nd_opt_pi_reserved2;
	struct in6_addr	nd_opt_pi_prefix;
};

struct ipv6_pseudo_hdr
{
    struct in6_addr saddr;
    struct in6_addr daddr;
    __be32          len;      /* upper-layer packet length */
    __u8            zero[3];
    __u8            nexthdr;
} __attribute__((packed));

static __always_inline int
upf_ra_make(struct xdp_md *ctx, struct if_rule_data *d,
	    void *data, void *data_end, struct ipv6hdr *ip6h, struct upf_fwd_rule *u)
{
	struct icmp6hdr *icmp6;
	struct nd_router_advert *nd_ra;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	int adj_sz;
	__u16 off_icmp6, off_ip6;
	__u8 tmp[16];
	__u8 nh;
	__u32 csum = 0;

	if (!IN6_IS_ADDR_LINKLOCAL(&ip6h->saddr))
		return XDP_DROP;

	/* drop anything that is not a router solicitation message */
	icmp6 = ipv6_skip_exthdr(ip6h, data_end, &nh);
	if (icmp6 == NULL ||
	    nh != IPPROTO_ICMPV6 ||
	    (void *)(icmp6 + 1) > data_end ||
	    icmp6->icmp6_type != ND_ROUTER_SOLICIT)
		return XDP_DROP;

	off_icmp6 = (void *)icmp6 - data;
	off_ip6 = (void *)ip6h - data;
	/* adjust packet to reply size */
	adj_sz = sizeof (*icmp6) + sizeof (*nd_ra) - (data_end - (void *)icmp6);
	if (bpf_xdp_adjust_tail(ctx, adj_sz) < 0)
		return XDP_ABORTED;

	/* reset all pointers */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	iph = (struct iphdr *)(data + d->pl_off);
	udph = (void *)(iph) + iph->ihl * 4;
	gtph = (struct gtphdr *)(udph + 1);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end ||
	    udph + 1 > data_end || gtph + 1 > data_end)
		return XDP_DROP;

	ip6h = data + off_ip6;
	icmp6 = data + off_icmp6;
	if (off_icmp6 > 300 ||
	    off_ip6 > 300 ||
	    (void *)(ip6h + 1) > data_end ||
	    (void *)icmp6 + sizeof (*icmp6) + sizeof (*nd_ra) > data_end)
		return XDP_DROP;

	__u32 atmp = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = atmp;
	iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + adj_sz);
	iph->check = 0;
	csum_ipv4(iph, sizeof(*iph), &csum);
	iph->check = csum;

	__u16 ptmp = udph->dest;
	udph->dest = udph->source;
	udph->source = ptmp;
	udph->check = 0;
	udph->len = bpf_htons(bpf_ntohs(udph->len) + adj_sz);

	gtph->teid = u->gtpu_remote_teid;
	gtph->length = bpf_htons(bpf_ntohs(gtph->length) + adj_sz);

	/* set dst_addr = src_addr. use fe80::1 as src_addr */
	__builtin_memcpy(ip6h->daddr.s6_addr, ip6h->saddr.s6_addr, 16);
	ip6h->saddr.s6_addr32[0] = __constant_htonl(0xfe800000);
	ip6h->saddr.s6_addr32[1] = 0;
	ip6h->saddr.s6_addr32[2] = 0;
	ip6h->saddr.s6_addr32[3] = __constant_htonl(0x00000001);
	ip6h->payload_len = bpf_htons(bpf_ntohs(ip6h->payload_len) + adj_sz);;

	/* build router advertisement */
	icmp6->icmp6_type = ND_ROUTER_ADVERT;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_hop_limit = 255;
	icmp6->icmp6_dataun.un_data8[1] = 0;
	icmp6->icmp6_rt_lifetime = __constant_htons(64800);
	nd_ra = (struct nd_router_advert *)(icmp6 + 1);
	nd_ra->nd_ra_reachable = 0;
	nd_ra->nd_ra_retransmit = 0;
	nd_ra->nd_opt_pi_type = 3;
	nd_ra->nd_opt_pi_len = 4;
	nd_ra->nd_opt_pi_prefix_len = 64;
	nd_ra->nd_opt_pi_flags_reserved = 0;
	nd_ra->nd_opt_pi_valid_time = ~0;
	nd_ra->nd_opt_pi_preferred_time = ~0;
	nd_ra->nd_opt_pi_reserved2 = 0;
	__builtin_memcpy(nd_ra->nd_opt_pi_prefix.s6_addr, u->ue_v6pfx, 8);
	__builtin_memset(nd_ra->nd_opt_pi_prefix.s6_addr + 8, 0x00, 8);

	/* compute icmpv6 checksum */
	struct ipv6_pseudo_hdr ph = {};
	ph.saddr = ip6h->saddr;
	ph.daddr = ip6h->daddr;
	ph.len = ip6h->payload_len;
	ph.nexthdr = IPPROTO_ICMPV6;
	__s64 r = bpf_csum_diff(0, 0, (__be32*)&ph, sizeof(ph), 0);
	if (r < 0)
		return XDP_DROP;
	r = bpf_csum_diff(0, 0, (__be32*)icmp6, (sizeof (*icmp6) + sizeof (*nd_ra)), r);
	if (r < 0)
		return XDP_DROP;
	icmp6->icmp6_cksum = csum_fold_helper(r);

	return if_rule_send_back_pkt(ctx, d);
}


/*
 * upf core gtp-u
 */

static __always_inline int
_encap_gtpu(struct xdp_md *ctx, struct if_rule_data *d, struct upf_fwd_rule *u)
{
	struct upf_urr *uu;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtphdr *gtph;
	void *data, *data_end;
	int adjust_sz, pkt_len;
	__u32 csum = 0;

	capture_xdp_to_userspc_in(ctx, &u->capture, BPF_CAPTURE_EFL_INPUT |
				  BPF_CAPTURE_EFL_CORE);

	uu = bpf_map_lookup_elem(&upf_urr, &u->urr_idx);
	if (uu == NULL)
		return XDP_DROP;

	if (uu->flags & UPF_FL_QUOTA_REACHED)
		goto drop;

	if (u->li_id)
		upf_li_pkt(ctx, u, d->pl_off, UPF_LI_FL_DIR_INGRESS);

	/* encap in gtp-u, make room */
	adjust_sz = sizeof(*iph) + sizeof(*udph) + sizeof(*gtph);
	if (bpf_xdp_adjust_head(ctx, -adjust_sz) < 0)
		return XDP_ABORTED;

	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

#if __clang_major__ == 21 && __clang_minor__ == 1
	/* fix '32-bit pointer arithmetic prohibited'.
	 * this could be a clang bug and should be removed */
	pkt_len = data_end - data;
	barrier_var(pkt_len);
	pkt_len -= d->pl_off;
#else
	pkt_len = data_end - data - d->pl_off;
#endif

	/* then write encap headers */
	iph = data + d->pl_off;
	udph = (struct udphdr *)(iph + 1);
	gtph = (struct gtphdr *)(udph + 1);
	if (d->pl_off > 256 || (void *)(gtph + 1) > data_end)
		goto drop;

	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = IPPROTO_UDP;
	iph->tos = 0;
	iph->tot_len = bpf_htons(pkt_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->check = 0;
	iph->saddr = u->gtpu_local_addr;
	iph->daddr = u->gtpu_remote_addr;
	csum_ipv4(iph, sizeof(*iph), &csum);
	iph->check = csum;

	pkt_len -= sizeof(*iph);
	udph->source = u->gtpu_local_port;
	udph->dest = u->gtpu_remote_port;
	udph->len = bpf_htons(pkt_len);
	udph->check = 0;

	pkt_len -= sizeof(*udph) + sizeof(*gtph);
	gtph->flags = GTPU_FLAGS;
	gtph->type = GTPU_TPDU;
	gtph->length = bpf_htons(pkt_len);
	gtph->teid = u->gtpu_remote_teid;

	d->dst_addr.ip4 = u->gtpu_remote_addr;

	/* metrics */
	++uu->dl_pkt;
	uu->dl_bytes += pkt_len;

	UPF_DBG("to_gtpu: encap len:%d teid:0x%08x src:%pI4:%d dst:%pI4:%d",
		pkt_len, bpf_ntohl(u->gtpu_remote_teid),
		&iph->saddr, bpf_ntohs(u->gtpu_local_port),
		&iph->daddr, bpf_ntohs(u->gtpu_remote_port));

	capture_xdp_to_userspc_out(d, &u->capture, BPF_CAPTURE_EFL_OUTPUT |
				   BPF_CAPTURE_EFL_ACCESS);

	upf_urr_check_dl(uu);

	return XDP_IFR_FORWARD;

 drop:
	++uu->dl_drop_pkt;

	return XDP_DROP;
}

/*
 *	Ingress direction (UE pov), ipv6 traffic from internet
 */
static __always_inline int
upf_handle_pubv6(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct upf_ingress_key k = {};
	struct upf_fwd_rule *u;
	struct ipv6hdr *ip6h;

	/* lookup user */
	ip6h = (struct ipv6hdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(ip6h + 1) > data_end)
		return XDP_DROP;

	k.flags = UE_IPV6;
	__builtin_memcpy(k.ue_addr.ip6.addr, ip6h->daddr.s6_addr, 16);
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL)
		return XDP_DROP;

	return _encap_gtpu(ctx, d, u);
}

/*
 *	Ingress direction (UE pov), ipv4 traffic from internet
 */
static __always_inline int
upf_handle_pub(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct upf_ingress_key k = {};
	struct upf_fwd_rule *u;
	struct iphdr *iph;

	if (d->flags & IF_RULE_FL_SRC_IPV6)
		return upf_handle_pubv6(ctx, d);

	/* lookup user */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_DROP;

	k.flags = UE_IPV4;
	k.ue_addr.ip4 = iph->daddr;
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL) {
#ifdef UPF_N4_IN_DATAPATH
		/* allow pfcp */
		struct udphdr *udph = (void *)(iph) + iph->ihl * 4;
		if (udph + 1 > data_end)
			return XDP_DROP;
		if (udph->dest == __constant_htons(8805))
			return XDP_PASS;
#endif
		return XDP_DROP;
	}

	return _encap_gtpu(ctx, d, u);
}


static __always_inline int
_handle_gtpu(struct xdp_md *ctx, struct if_rule_data *d,
	     struct iphdr *iph, struct udphdr *udph)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct upf_egress_key k;
	struct upf_fwd_rule *u;
	struct upf_urr *uu;
	struct iphdr *ip4h_inner;
	struct ipv6hdr *ip6h_inner;
	struct gtphdr *gtph;
	int adjust_sz, pkt_len;
	__u32 sum;

	gtph = (struct gtphdr *)(udph + 1);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* gtp-u 'management' packets will be handled by userapp */
	if (gtph->type != 0xff)
		return XDP_PASS;

	/* lookup user */
	k.gtpu_local_teid = gtph->teid;
	k.gtpu_local_addr = iph->daddr;
	k.gtpu_local_port = udph->dest;
	u = bpf_map_lookup_elem(&user_egress, &k);
	UPF_DBG("from_gtpu: lookup dst:%pI4:%d teid:%x%s",
		   &iph->daddr, bpf_ntohs(udph->dest), bpf_ntohl(gtph->teid),
		   u == NULL ? " => NOT FOUND" : "");
	if (u == NULL)
		return XDP_DROP;

	capture_xdp_to_userspc_in(ctx, &u->capture, BPF_CAPTURE_EFL_INPUT |
				  BPF_CAPTURE_EFL_ACCESS);

	uu = bpf_map_lookup_elem(&upf_urr, &u->urr_idx);
	if (uu == NULL)
		return XDP_DROP;

	if (uu->flags & UPF_FL_QUOTA_REACHED)
		goto drop;

#if __clang_major__ == 21 && __clang_minor__ == 1
	pkt_len = data_end - data;
	barrier_var(pkt_len);
	pkt_len -= d->pl_off;
#else
	pkt_len = data_end - data - d->pl_off;
#endif

	if ((u->flags & UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) ==
	    UPF_FWD_FL_ACT_KEEP_OUTER_HEADER) {
		/* forward gtp-u as-this */
		sum = csum_diff32(0, iph->saddr, u->gtpu_local_addr);
		sum = csum_diff32(sum, iph->daddr, u->gtpu_remote_addr);
		iph->saddr = u->gtpu_local_addr;
		iph->daddr = u->gtpu_remote_addr;
		--iph->ttl;
		iph->check = csum_replace(iph->check, sum - 1);

		if (udph->check) {
			sum = csum_diff16(sum, udph->source, u->gtpu_local_port);
			sum = csum_diff16(sum, udph->dest, u->gtpu_remote_port);
			sum = csum_diff32(sum, gtph->teid, u->gtpu_remote_teid);
			__u16 nsum = csum_replace(udph->check, sum);
			udph->check = nsum ?: 0xffff;
		}
		udph->source = u->gtpu_local_port;
		udph->dest = u->gtpu_remote_port;
		gtph->teid = u->gtpu_remote_teid;
		UPF_DBG("rewrite_gtpu: src:%pI4:%d dst:%pI4:%d teid:%x",
			   &iph->saddr, bpf_ntohs(udph->source),
			   &iph->daddr, bpf_ntohs(udph->dest),
			   bpf_ntohl(gtph->teid));

		/* metrics */
		++uu->ul_pkt;
		uu->ul_bytes += pkt_len;

		d->dst_addr.ip4 = iph->daddr;
		return XDP_IFR_FORWARD;
	}

	/* for futur nh lookup */
	ip4h_inner = (struct iphdr *)(gtph + 1);
	if (ip4h_inner + 1 > data_end)
		goto drop;
	switch (ip4h_inner->version) {
	case 4:
		d->dst_addr.ip4 = ip4h_inner->daddr;
		break;
	case 6:
		ip6h_inner = (struct ipv6hdr *)ip4h_inner;
		if (ip6h_inner + 1 > data_end)
			return XDP_DROP;
		__builtin_memcpy(d->dst_addr.ip6.addr,
				 ip6h_inner->daddr.s6_addr, 16);
		d->flags |= IF_RULE_FL_DST_IPV6;

		/* router solicitation from UE, answer */
		if (IN6_IS_ADDR_MULTICAST(&ip6h_inner->daddr))
			return upf_ra_make(ctx, d, data, data_end, ip6h_inner, u);

		break;
	default:
		goto drop;
	}

	/* decap gtp-u */
	adjust_sz = (void *)(gtph + 1) - (void *)iph;
	if (bpf_xdp_adjust_head(ctx, adjust_sz) < 0)
		return XDP_ABORTED;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	capture_xdp_to_userspc_out(d, &u->capture, BPF_CAPTURE_EFL_OUTPUT |
				   BPF_CAPTURE_EFL_CORE);

	/* metrics */
	++uu->ul_pkt;
	uu->ul_bytes += pkt_len - adjust_sz;

	upf_urr_check_ul(uu);

	if (u->li_id)
		upf_li_pkt(ctx, u, d->pl_off, UPF_LI_FL_DIR_EGRESS);

	return XDP_IFR_FORWARD;

 drop:
	++uu->ul_drop_pkt;

	return XDP_DROP;
}


/*
 *	Egress direction (UE pov), traffic from GTP-U endpoint
 */
static __attribute__((noinline)) int
upf_handle_gtpu(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph;
	struct udphdr *udph;

	/* check input gtp-u (proto udp and port) */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_DROP;

	udph = (void *)(iph) + iph->ihl * 4;
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != __constant_htons(GTPU_PORT))
		return XDP_DROP;

	return _handle_gtpu(ctx, d, iph, udph);
}


/*
 *	Choose between gtp-u and l3 side
 */
static __attribute__((noinline)) int
upf_traffic_selector(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph;
	struct udphdr *udph;

	if (d->flags & IF_RULE_FL_SRC_IPV6)
		return upf_handle_pubv6(ctx, d);

	/* check input gtp-u (proto udp and port) */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->protocol != IPPROTO_UDP)
		return upf_handle_pub(ctx, d);

	udph = (void *)(iph) + iph->ihl * 4;
	if (udph + 1 > data_end)
		return XDP_DROP;

	/* this is our gtp-u ! */
	if (udph->dest == __constant_htons(GTPU_PORT))
		return _handle_gtpu(ctx, d, iph, udph);

	return upf_handle_pub(ctx, d);
}

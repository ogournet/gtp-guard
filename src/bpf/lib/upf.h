/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <time.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/udp.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

#include "gtpu.h"
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
 * upf core gtp-u
 */

static __always_inline int
_encap_gtpu(struct xdp_md *ctx, struct if_rule_data *d, struct upf_fwd_rule *u, int v6)
{
	struct upf_urr *uu;
	struct iphdr *iph;
	struct udphdr *udph;
	struct gtpuhdr *gtph;
	void *data, *data_end;
	int adjust_sz, pl_len;
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
	adjust_sz = sizeof(*iph) + sizeof(*udph) + GTPU_HLEN_SHORT;
	if (u->flags & UPF_FWD_FL_GTP_EXTHDR)
		adjust_sz += 8;
	if (bpf_xdp_adjust_head(ctx, -adjust_sz) < 0)
		return XDP_ABORTED;

	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

#if __clang_major__ == 21 && __clang_minor__ == 1
	/* fix '32-bit pointer arithmetic prohibited'.
	 * this could be a clang bug and should be removed */
	pl_len = data_end - data;
	barrier_var(pl_len);
	pl_len -= d->pl_off;
#else
	pl_len = data_end - data - d->pl_off;
#endif

	/* then write encap headers */
	iph = data + d->pl_off;
	udph = (struct udphdr *)(iph + 1);
	gtph = (struct gtpuhdr *)(udph + 1);
	if (d->pl_off > 256 || (void *)(gtph + 1) > data_end)
		goto drop;

	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = IPPROTO_UDP;
	iph->tos = 0;
	iph->tot_len = bpf_htons(pl_len);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->check = 0;
	iph->saddr = u->gtpu_local_addr;
	iph->daddr = u->gtpu_remote_addr;
	csum_ipv4(iph, sizeof(*iph), &csum);
	iph->check = csum;

	pl_len -= sizeof(*iph);
	udph->source = u->gtpu_local_port;
	udph->dest = u->gtpu_remote_port;
	udph->len = bpf_htons(pl_len);
	udph->check = 0;

	pl_len -= sizeof(*udph) + GTPU_HLEN_SHORT;
	gtph->flags = GTPU_FL_V1 | GTPU_FL_PT;
	gtph->type = GTPU_TYPE_TPDU;
	gtph->length = bpf_htons(pl_len);
	gtph->teid = u->gtpu_remote_teid;
	if (u->flags & UPF_FWD_FL_GTP_EXTHDR) {
		pl_len -= 8;
		gtph->flags |= GTPU_FL_E;
		gtph->seqnum = 0;
		gtph->npdu_num = 0;
		gtph->exthdr_type = GTPU_ETYPE_PDU_SESSION_CONTAINER;
		if (gtph->exthdr + 4 > data_end)
			goto drop;
		gtph->exthdr[0] = 1;	/* len */
		gtph->exthdr[1] = 0;
		gtph->exthdr[2] = 5;	/* qfi */
		gtph->exthdr[3] = GTPU_ETYPE_NONE;
	}

	d->dst_addr.ip4 = u->gtpu_remote_addr;

	/* metrics */
	if (v6) {
		++u->fwd_v6_pkt;
		u->fwd_v6_bytes += pl_len;
	} else {
		++u->fwd_v4_pkt;
		u->fwd_v4_bytes += pl_len;
	}
	++uu->dl_pkt;
	uu->dl_bytes += pl_len;

	UPF_DBG("to_gtpu: encap len:%d teid:0x%08x src:%pI4:%d dst:%pI4:%d",
		pl_len, bpf_ntohl(u->gtpu_remote_teid),
		&iph->saddr, bpf_ntohs(u->gtpu_local_port),
		&iph->daddr, bpf_ntohs(u->gtpu_remote_port));

	capture_xdp_to_userspc_out(d, &u->capture, BPF_CAPTURE_EFL_OUTPUT |
				   BPF_CAPTURE_EFL_ACCESS);

	upf_urr_check_dl(uu);

	return XDP_IFR_FORWARD;

 drop:
	if (v6)
		++u->drop_v6_pkt;
	else
		++u->drop_v4_pkt;

	return XDP_DROP;
}

/*
 *	Ingress direction (UE pov), ipv6 traffic from internet
 */
static __always_inline int
_upf_handle_pubv6(struct xdp_md *ctx, struct if_rule_data *d)
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
	__builtin_memcpy(k.ue_ip6pfx.addr, ip6h->daddr.s6_addr, 8);
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL)
		return (d->flags & IF_RULE_FL_IS_LOCAL_DST) ? XDP_PASS : XDP_DROP;

	return _encap_gtpu(ctx, d, u, 1);
}

static __no_inline int
upf_handle_pubv6(struct xdp_md *ctx, struct if_rule_data *d)
{
	return _upf_handle_pubv6(ctx, d);
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
		return _upf_handle_pubv6(ctx, d);

	/* lookup user */
	iph = (struct iphdr *)(data + d->pl_off);
	if (d->pl_off > 256 || (void *)(iph + 1) > data_end)
		return XDP_DROP;

	k.flags = UE_IPV4;
	k.ue_ip4 = iph->daddr;
	u = bpf_map_lookup_elem(&user_ingress, &k);
	if (u == NULL)
		return (d->flags & IF_RULE_FL_IS_LOCAL_DST) ? XDP_PASS : XDP_DROP;

	return _encap_gtpu(ctx, d, u, 0);
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
	struct iphdr *ip4h_inner = NULL;
	struct ipv6hdr *ip6h_inner;
	struct gtpuhdr *gtph;
	int adjust_sz, pkt_len, i;
	__u16 gtph_len;
	__u32 sum;

	gtph = (struct gtpuhdr *)(udph + 1);
	if (gtph + 1 > data_end)
		return XDP_DROP;

	/* gtp-u 'management' packets will be handled by userapp */
	if (gtph->type != 0xff)
		return XDP_PASS;

	/* lookup user */
	k.gtpu_local_teid = gtph->teid;
	k.gtpu_local_addr = iph->daddr;
	u = bpf_map_lookup_elem(&user_egress, &k);
	UPF_DBG("from_gtpu: lookup dst:%pI4:%d teid:%x%s",
		   &iph->daddr, bpf_ntohs(udph->dest), bpf_ntohl(gtph->teid),
		   u == NULL ? " => NOT FOUND" : "");
	if (u == NULL)
		return XDP_IFR_NOT_HANDLED;

	capture_xdp_to_userspc_in(ctx, &u->capture, BPF_CAPTURE_EFL_INPUT |
				  BPF_CAPTURE_EFL_ACCESS);

	uu = bpf_map_lookup_elem(&upf_urr, &u->urr_idx);
	if (uu == NULL)
		return XDP_DROP;

	if (uu->flags & UPF_FL_QUOTA_REACHED)
		goto drop;

	if (gtph->flags & GTPU_FL_E) {
		gtph_len = GTPU_HLEN_LONG;
		__u8 gtph_et = gtph->exthdr_type;
		__u8 *gtph_e = (__u8 *)(gtph + 1);
#pragma unroll
		for (i = 0; gtph_et && i < GTPU_EXTHDR_MAX; i++) {
			if (unlikely(gtph_e + 1 > data_end))
				return XDP_DROP;
			__u8 gtph_el = *gtph_e << 2;
			if (unlikely(!gtph_el || gtph_e + gtph_el > data_end))
				return XDP_DROP;
			gtph_et = gtph_e[gtph_el - 1];
			gtph_len += gtph_el;
		}
		if (unlikely(gtph_et)) {
			UPF_DBG("increase GTPU_EXTHDR_MAX");
			return XDP_DROP;
		}

	} else if (gtph->flags & (GTPU_FL_S | GTPU_FL_PN)) {
		gtph_len = GTPU_HLEN_LONG;

	} else {
		gtph_len = GTPU_HLEN_SHORT;
	}

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

		/* metrics (pkt_len includes gtpu) */
		++u->fwd_v4_pkt;
		u->fwd_v4_bytes += pkt_len;
		++uu->ul_pkt;
		uu->ul_bytes += pkt_len;

		d->dst_addr.ip4 = iph->daddr;
		return XDP_IFR_FORWARD;
	}

	ip4h_inner = (struct iphdr *)((void *)gtph + gtph_len);
	adjust_sz = (void *)(ip4h_inner) - (void *)iph;
	pkt_len -= adjust_sz;

	/* for futur nh lookup */
	if (ip4h_inner + 1 > data_end)
		goto drop;
	switch (ip4h_inner->version) {
	case 4:
		d->dst_addr.ip4 = ip4h_inner->daddr;
		++u->fwd_v4_pkt;
		u->fwd_v4_bytes += pkt_len;
		break;
	case 6:
		ip6h_inner = (struct ipv6hdr *)ip4h_inner;
		if (ip6h_inner + 1 > data_end)
			return XDP_DROP;
		__builtin_memcpy(d->dst_addr.ip6.addr,
				 ip6h_inner->daddr.s6_addr, 16);
		d->flags |= IF_RULE_FL_DST_IPV6;

		/* router solicitation from UE, let userapp handle */
		if (IN6_IS_ADDR_MULTICAST(&ip6h_inner->daddr) &&
		    IN6_IS_ADDR_LINKLOCAL(&ip6h_inner->saddr))
			return XDP_PASS;

		++u->fwd_v6_pkt;
		u->fwd_v6_bytes += pkt_len;
		break;
	default:
		UPF_DBG("unknown ipproto_version=%d in inner", ip4h_inner->version);
		goto drop;
	}

	/* decap gtp-u */
	if (bpf_xdp_adjust_head(ctx, adjust_sz) < 0)
		return XDP_ABORTED;
	d->flags |= IF_RULE_FL_XDP_ADJUSTED;

	capture_xdp_to_userspc_out(d, &u->capture, BPF_CAPTURE_EFL_OUTPUT |
				   BPF_CAPTURE_EFL_CORE);

	++uu->ul_pkt;
	uu->ul_bytes += pkt_len;

	upf_urr_check_ul(uu);

	if (u->li_id)
		upf_li_pkt(ctx, u, d->pl_off, UPF_LI_FL_DIR_EGRESS);

	return XDP_IFR_FORWARD;

 drop:
	ip4h_inner = (struct iphdr *)(gtph + 1);
	if (ip4h_inner + 1 < data_end && ip4h_inner->version == 6)
		++u->drop_v6_pkt;
	else
		++u->drop_v4_pkt;

	return XDP_DROP;
}


/*
 *	Egress direction (UE pov), traffic from GTP-U endpoint
 */
static __no_inline int
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
		return (d->flags & IF_RULE_FL_IS_LOCAL_DST) ?
			XDP_PASS : XDP_IFR_NOT_HANDLED;

	udph = (void *)(iph) + iph->ihl * 4;
	if (udph + 1 > data_end)
		return XDP_DROP;

	if (udph->dest != __constant_htons(GTPU_PORT))
		return (d->flags & IF_RULE_FL_IS_LOCAL_DST) ?
			XDP_PASS : XDP_IFR_NOT_HANDLED;

	return _handle_gtpu(ctx, d, iph, udph);
}


/*
 *	Choose between gtp-u and l3 side
 */
static __no_inline int
upf_traffic_selector(struct xdp_md *ctx, struct if_rule_data *d)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *iph;
	struct udphdr *udph;

	if (d->flags & IF_RULE_FL_SRC_IPV6)
		return _upf_handle_pubv6(ctx, d);

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

/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include <linux/if_ether.h>
#include <linux/if_vlan.h>

#include "lib/cgn.h"


static inline void
swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];
	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}


/*
 * attach to interface, get l2 packet
 */
SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *ethh = data;
	struct vlan_hdr *vlanh;
	struct iphdr *iph;
	void *payload;
	__u16 eth_type, vlan = 0;
	int ret;

	if ((void *)(ethh + 1) > data_end)
		return XDP_DROP;

	eth_type = ethh->h_proto;

	/* handle outer VLAN tag */
	if (eth_type == __constant_htons(ETH_P_8021Q) ||
	    eth_type == __constant_htons(ETH_P_8021AD)) {
		vlanh = (struct vlan_hdr *)(ethh + 1);
		if ((void *)(vlanh + 1) > data_end)
			return XDP_DROP;
		vlan = bpf_ntohs(vlanh->vlan_tci) & 0x0fff;
		eth_type = vlanh->next_proto;
		payload = vlanh + 1;
	} else {
		payload = ethh + 1;
	}

	/* XXX kind of hardcoded */
	int from_priv = vlan == 290;

	switch (eth_type) {
	case __constant_htons(ETH_P_IP):
		/* check ipv4 header */
		if ((void *)((struct iphdr *)(payload) + 1) > data_end)
			return 1;

		ret = cgn_pkt_handle(ctx, payload, from_priv);
		if (!(!from_priv && ret == 10))
			bpf_printk("handled pkt from priv:%d ret:%d", from_priv, ret);
		if (ret > 0)
			return XDP_DROP;
		break;

	default:
		return XDP_PASS;
	}

	if (hit_bug || ret < 0) {
		hit_bug = 0;
		return XDP_ABORTED;
	}

	/* XXX also kind of hacky: TX to the other vlan */
	if (vlan) {
		if (from_priv)
			vlan = __constant_htons(291);
		else
			vlan = __constant_htons(290);
		vlanh->vlan_tci = vlan;
	}
	swap_src_dst_mac(ethh);

	bpf_printk("fwd packet from priv:%d to vlan %d",
		   from_priv, bpf_ntohs(vlan));
	return XDP_TX;
}


const char _mode[] = "cgn";
char _license[] SEC("license") = "GPL";

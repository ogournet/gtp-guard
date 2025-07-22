/* SPDX-License-Identifier: AGPL-3.0-or-later */

#include "lib/traf_acl.h"
#include "lib/cgn.h"


SEC("xdp")
int cgn_entry(struct xdp_md *ctx)
{
	struct traf_acl_data d = {};
	int action, ret;

	action = traf_acl_parse_pkt(ctx, &d);
	bpf_printk("got packet, action=%d", action);

	switch (action) {
	case 0 ... 9:
		return action;

	case 10:
		ret = cgn_pkt_handle(ctx, d.payload, 1);
		break;
	case 11:
		ret = cgn_pkt_handle(ctx, d.payload, 0);
		break;

	default:
		return XDP_PASS;
	}

	if (hit_bug || ret < 0) {
		hit_bug = 0;
		return XDP_ABORTED;
	}
	if (ret == 0)
		return traf_acl_rewrite_pkt(ctx, &d);
	return XDP_DROP;
}

const char _mode[] = "cgn";
char _license[] SEC("license") = "GPL";

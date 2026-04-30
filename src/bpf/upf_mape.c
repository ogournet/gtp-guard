/* SPDX-License-Identifier: AGPL-3.0-or-later */


#include "lib/if_rule.h"
#include "lib/upf.h"
#include "lib/mape.h"


/*
 * UPF + MAP-E
 */

SEC("xdp")
int upf_mape_entry(struct xdp_md *ctx)
{
	struct if_rule_data d = { };
	int action;

	action = if_rule_parse_pkt(ctx, &d);
	if (action <= XDP_REDIRECT)
		return action;

	if (action == XDP_IFR_DEFAULT_ROUTE) {
		/* ipv6: encap gtp-u */
		if (d.flags & IF_RULE_FL_SRC_IPV6) {
			action = upf_handle_pubv6(ctx, &d);
			goto handled;
		}

		/* ipv4: check if is it a gtp-u tunnel */
		action = upf_handle_gtpu(ctx, &d);
		if (action == XDP_IFR_NOT_HANDLED) {
			/* no: encap mape-v4, then encap gtp-u */
			action = mape_encap(ctx, &d);
			if (action == XDP_IFR_FORWARD)
				action = upf_handle_pubv6(ctx, &d);

		} else if (action == XDP_IFR_FORWARD && !
			   (d.flags & IF_RULE_FL_DST_IPV6)) {
			/* yes: and payload is v6: try decap map-e */
			action = mape_decap(ctx, &d);
			if (action == XDP_IFR_NOT_HANDLED)
				action = XDP_IFR_FORWARD;
		}
	}

 handled:
	if (action == XDP_IFR_FORWARD)
		return if_rule_rewrite_pkt(ctx, &d);

	return action;
}

const char _mode[] = "if_rules,capture,upf,mape";

char _license[] SEC("license") = "GPL";

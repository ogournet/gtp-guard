/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Procol). GTP is
 *              widely used for data-plane in mobile core-network. gtp-guard
 *              implements a set of 3 main frameworks:
 *              A Proxy feature for data-plane tweaking, a Routing facility
 *              to inter-connect and a Firewall feature for filtering,
 *              rewriting and redirecting.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include "lib/gtp_fwd.h"
#include "lib/gtp_mirror.h"


SEC("xdp")
int xdp_fwd(struct xdp_md *ctx)
{
	return gtp_fwd(ctx);
}

SEC("tcx/ingress")
int tc_gtp_mirror(struct __sk_buff *skb)
{
	return gtp_mirror(skb);
}

const char _mode[] = "gtp_fwd,gtp_mirror";
char _license[] SEC("license") = "GPL";

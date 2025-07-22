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
 *              Olivier Gournet, <gournet.olivier@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU Affero General Public
 *              License Version 3.0 as published by the Free Software Foundation;
 *              either version 3.0 of the License, or (at your option) any later
 *              version.
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */


/* system includes */
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <libbpf.h>

/* local includes */
#include "tools.h"
#include "inet_server.h"
#include "inet_utils.h"
#include "list_head.h"
#include "bitops.h"
#include "vty.h"
#include "command.h"
#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "cgn.h"
#include "bpf/lib/cgn-def.h"
#include "bpf/lib/flow-def.h"


/*
 *	BPF stuff
 */

/*
 * this is were we bind things together:
 *   - one carrier-grade-nat
 *   - one bfp-program
 *   - one or many interfaces
 */
static int
cgn_bpf_bind_itf(gtp_bpf_prog_t *p, gtp_interface_t *iface)
{
	gtp_interface_t **itf;
	struct cgn_ctx *c;

	if (!*iface->cgn_name) {
		log_message(LOG_INFO, "iface '%s': mandatory config "
			    "carrier-grade-nat is not set",
			    iface->ifname, iface->cgn_name);
		return -1;
	}

	/* interface references carrier-grade-nat config bloc */
	c = cgn_ctx_get_by_name(iface->cgn_name);
	if (c == NULL) {
		log_message(LOG_INFO, "iface '%s': carrier-grade-nat '%s'"
			    " is not defined", iface->ifname, iface->cgn_name);
		return -1;
	}
	if (c->prg != NULL && c->prg != p) {
		log_message(LOG_INFO, "carrier-grade-nat '%s'"
			    " already bound to bpf-pgrogram '%s'",
			    c->name, c->prg->name);
		return -1;
	}
	assert(p->data == NULL || p->data == c);

	/* attach interface to cgn */
	if (__test_bit(GTP_INTERFACE_FL_CGNAT_NET_IN_BIT, &iface->flags))
		itf = &c->iface_priv;
	else if (__test_bit(GTP_INTERFACE_FL_CGNAT_NET_OUT_BIT, &iface->flags))
		itf = &c->iface_pub;
	else
		abort();
	if (*itf != NULL) {
		log_message(LOG_INFO, "iface '%s': carrier-grade-nat '%s'"
			    " is already attached to interface '%s'",
			    iface->ifname, iface->cgn_name, (*itf)->ifname);
		return -1;
	}

	/* link everything together */
	p->data = c;
	c->prg = p;
	*itf = iface;

	if (c->iface_pub != NULL && c->iface_priv != NULL) {
		log_message(LOG_INFO, "carrier-grade-nat:'%s'"
			    " configuration is done, starting",
			    c->name);

		/* add traffic rules */
		traf_acl_add(p, c->iface_priv, c->iface_pub, 10);
		traf_acl_add(p, c->iface_pub, c->iface_priv, 11);

		/* XXX start thread etc... */
	}

	return 0;
}


static int
cgn_bpf_opened(gtp_bpf_prog_t *p, struct bpf_object *obj)
{
	struct cgn_ctx *c = p->data;
	struct bpf_map *m;
	uint64_t icmp_to;

	if (c == NULL) {
		log_message(LOG_INFO, "cgn bpf program '%s' not attached to "
			    "a cgn block", p->name);
		return -1;
	}

	printf("%s\n", __func__);

	p->bpf_maps = calloc(sizeof(gtp_bpf_maps_t), BPF_CGN_MAP_CNT);

	icmp_to = c->timeout_icmp * NSEC_PER_SEC;
	uint32_t bl_flow_max = c->flow_per_user / c->block_per_user;

	gtp_bpf_prog_var_t consts_var[] = {
		{ .name = "ipbl_n", .value = &c->cgn_addr_n,
		  .size = sizeof (c->cgn_addr_n) },
		{ .name = "bl_n", .value = &c->block_count,
		  .size = sizeof (c->block_count) },
		{ .name = "bl_user_max", .value = &c->block_per_user,
		  .size = sizeof (c->block_per_user) },
		{ .name = "bl_flow_max", .value = &bl_flow_max,
		  .size = sizeof (bl_flow_max) },
		{ .name = "port_count", .value = &c->block_size,
		  .size = sizeof (c->block_size) },
		{ .name = "icmp_timeout", .value = &icmp_to,
		  .size = sizeof (icmp_to) },
		{ NULL },
	};
	gtp_bpf_prog_obj_update_var(obj, consts_var);

	/* 'allocate' bpf maps */
	m = bpf_object__find_map_by_name(obj, "v4_blocks");
	if ((p->bpf_maps[BPF_CGN_MAP_V4_BLOCKS].map = m) == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, c->cgn_addr_n) != 0) {
		log_message(LOG_INFO, "set v4_blocks.max_entries failed");
		return -1;
	}
	c->block_msize = sizeof (struct cgn_v4_ipblock) +
		sizeof (struct cgn_v4_block) * c->block_count;
	if (bpf_map__set_value_size(m, c->block_msize) != 0) {
		log_message(LOG_INFO, "set v4_blocks.value_size = %d failed",
			    c->block_msize);
		return -1;
	}

	m = bpf_object__find_map_by_name(obj, "v4_free_blocks");
	if ((p->bpf_maps[BPF_CGN_MAP_V4_FREE_BLOCKS].map = m) == NULL)
		return -1;
	if (bpf_map__set_max_entries(m, c->block_count + 1) != 0) {
		log_message(LOG_INFO, "set free_blocks_cnt.max_entries failed");
		return -1;
	}
	if (bpf_map__set_value_size(m, (c->cgn_addr_n + 3) * sizeof (int)) != 0) {
		log_message(LOG_INFO, "set free_blocks_cnt.value_size failed");
		return -1;
	}

	m = bpf_object__find_map_by_name(obj, "users");
	if ((p->bpf_maps[BPF_CGN_MAP_USERS].map = m) == NULL)
		return -1;
	m = bpf_object__find_map_by_name(obj, "flow_port_timeouts");
	if ((p->bpf_maps[BPF_CGN_MAP_FLOW_PORT_TIMEOUTS].map = m) == NULL)
		return -1;

	return 0;
}

static int
cgn_bpf_loaded(gtp_bpf_prog_t *p, struct bpf_object *obj)
{
	struct cgn_ctx *c = p->data;
	struct cgn_v4_ipblock *ipbl;
	struct bpf_map *m;
	const size_t fmsize = (c->cgn_addr_n + 3) * sizeof (int);
	uint32_t i, l, k;
	uint8_t d[c->block_msize];
	void *free_area;
	int *free_cnt;

	printf("%s\n", __func__);

	/* prepare memory to be copied to maps */
	free_cnt = free_area = malloc(fmsize);
	m = p->bpf_maps[BPF_CGN_MAP_V4_BLOCKS].map;

	/* fill blocks */
	for (i = 0; i < c->cgn_addr_n; i++) {
		memset(d, 0, c->block_msize);
		ipbl = (struct cgn_v4_ipblock *)d;
		ipbl->ipbl_idx = i;
		ipbl->fr_idx = i;
		ipbl->cgn_addr = c->cgn_addr[i];
		for (l = 0; l < c->block_count; l++) {
			ipbl->b[l].ipbl_idx = i;
			ipbl->b[l].bl_idx = l;
			ipbl->b[l].cgn_port_start =
				c->port_start + l * c->block_size;
			ipbl->b[l].cgn_port_next = ipbl->b[l].cgn_port_start;
		}
		free_cnt[2 + i] = i;

		bpf_map__update_elem(m, &i, sizeof (i),
				     d, c->block_msize, 0);
	}
	free_cnt[0] = 0;
	free_cnt[1] = c->cgn_addr_n;
	free_cnt[i + 2] = 0;

	/* on startup, all blocks are unused, so only the first line contains
	 * indexes. */
	m = p->bpf_maps[BPF_CGN_MAP_V4_FREE_BLOCKS].map;
	i = 0;
	bpf_map__update_elem(m, &i, sizeof (i), free_area, fmsize, 0);
	free(free_area);

	/* set flow port timeout */
	m = p->bpf_maps[BPF_CGN_MAP_FLOW_PORT_TIMEOUTS].map;
	for (i = 0; i < 1 << 16; i++) {
		union flow_timeout_config val = {};

		k = i;
		val.udp = c->timeout_by_port[i].udp ?: c->timeout.udp;
		bpf_map__update_elem(m, &k, sizeof (k), &val, sizeof (val), 0);

		k = (1 << 16) | i;
		val.tcp_synfin = c->timeout_by_port[i].tcp_synfin ?:
			c->timeout.tcp_synfin;
		val.tcp_est = c->timeout_by_port[i].tcp_est ?: c->timeout.tcp_est;
		bpf_map__update_elem(m, &k, sizeof (k), &val, sizeof (val), 0);
	}

	return 0;
}

static void
cgn_bpf_direct_tx_lladdr_updated(gtp_bpf_prog_t *p, gtp_interface_t *iface)
{
	struct cgn_ctx *c = p->data;

	printf("%s: ctx:%p\n", __func__, c);
	/* bind_itf did not happen yet */
	if (c == NULL)
		return;

	if (iface == c->iface_pub)
		traf_acl_update_lladdr(p, c->iface_priv, c->iface_pub);
	else if (iface == c->iface_priv)
		traf_acl_update_lladdr(p, c->iface_pub, c->iface_priv);
	else
		printf("%s: no itf found\n", __func__);
}



static gtp_bpf_prog_tpl_t gtp_bpf_tpl_cgn = {
	.mode = BPF_PROG_MODE_CGN,
	.description = "carrier-grade-nat",
	.load_on_attach = true,
	.bind_itf = cgn_bpf_bind_itf,
	.opened = cgn_bpf_opened,
	.loaded = cgn_bpf_loaded,
	.direct_tx_lladdr_updated = cgn_bpf_direct_tx_lladdr_updated,
};

static void __attribute__((constructor))
gtp_bpf_fwd_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_cgn);
}

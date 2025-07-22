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

#include <stddef.h>
#include <libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>

#include "tools.h"
#include "inet_server.h"
#include "inet_utils.h"
#include "list_head.h"
#include "vty.h"
#include "command.h"
#include "gtp_data.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "cgn.h"
#include "bpf/lib/traf_acl-def.h"

void
traf_acl_add(gtp_bpf_prog_t *p, gtp_interface_t *from,
	     gtp_interface_t *to, int action)
{
	struct bpf_map *m;
	struct traf_acl_key k = {};
	struct traf_acl_rule r = {};
	int ret;

	m = bpf_object__find_map_by_name(p->bpf_obj, "traf_acl");
	if (m == NULL)
		return;

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	r.action = action;
	r.ifindex = to->ifindex;
	r.vlan_id = to->vlan_id;
	memcpy(r.h_local, to->hw_addr, ETH_ALEN);
	memcpy(r.h_remote, to->direct_tx_hw_addr, ETH_ALEN);

	printf("add acl if:%d vlan:%d gre:%d sizeof:%ld\n", k.ifindex, k.vlan_id,
	       k.gre_remote, sizeof (k));

	ret = bpf_map__update_elem(m, &k, sizeof (k), &r, sizeof (r), BPF_NOEXIST);
	if (ret) {
		printf("cannot add / update rule! (%d)\n", ret);
	}
}

void
traf_acl_update_lladdr(gtp_bpf_prog_t *p, gtp_interface_t *from,
		       gtp_interface_t *to)
{
	struct bpf_map *m;
	struct traf_acl_key k = {};
	struct traf_acl_rule r = {};
	int ret;

	m = bpf_object__find_map_by_name(p->bpf_obj, "traf_acl");
	if (m == NULL)
		return;

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	ret = bpf_map__lookup_elem(m, &k, sizeof (k), &r, sizeof (r), 0);
	if (ret) {
		printf("cannot get rule on update! (%d)\n", ret);
		return;
	}

	memcpy(r.h_remote, to->direct_tx_hw_addr, ETH_ALEN);

	ret = bpf_map__update_elem(m, &k, sizeof (k), &r, sizeof (r), BPF_EXIST);
	if (ret) {
		printf("cannot update rule! (%d)\n", ret);
	}

}

void
traf_acl_del(gtp_bpf_prog_t *p, gtp_interface_t *from)
{
	struct bpf_map *m;
	struct traf_acl_key k = {};

	m = bpf_object__find_map_by_name(p->bpf_obj, "traf_acl");
	if (m == NULL)
		return;

	k.ifindex = from->ifindex;
	k.vlan_id = from->vlan_id;

	bpf_map__delete_elem(m, &k, sizeof (k), 0);
}

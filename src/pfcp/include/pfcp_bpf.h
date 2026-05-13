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
 * Copyright (C) 2023-2026 Alexandre Cassen, <acassen@gmail.com>
 */

#pragma once

#include "pfcp_teid.h"
#include "pfcp_session.h"

struct pfcp_router;
struct gtp_bpf_prog;

struct pfcp_ttc_cmd
{
	struct upf_ttc_cmd	tc;
	struct list_head	clist;
};

struct pfcp_bpf_data
{
	struct list_head	pfcp_router_list;

	struct bpf_map		*user_egress;
	struct bpf_map		*user_ingress;
	struct bpf_map		*upf_li_perf;

	/* ttc */
	struct bpf_map		*upf_ttc;
	uint8_t			*ttc_alloc;
	int			ttc_alloc_cur;
	int			ttc_ctl_prog_fd;
	struct pfcp_bpf_data_thread **ctl_task;

	/* mbr */
	struct bpf_map		*upf_mbr;
	uint8_t			*mbr_alloc;
	int			mbr_alloc_cur;
	void			*mbr_map;
	size_t			mbr_map_size;

	/* upf_events ring_buffer */
	struct ring_buffer	*rbuf;
	struct thread		*rbuf_th;
};

/* Prototypes */
int pfcp_bpf_ttc_ctl(struct pfcp_session *s, struct upf_ttc_cmd *tc);
int pfcp_bpf_teid_action(struct pfcp_router *r, int action, struct pfcp_teid *t,
			 struct ue_ip_address *ue);
int pfcp_bpf_action(struct pfcp_session *s, struct pfcp_fwd_rule *r,
		    struct pfcp_teid *t, struct ue_ip_address *ue);
int pfcp_bpf_teid_vty(struct vty *vty, struct gtp_bpf_prog *p, int dir,
		      struct ue_ip_address *ue, struct pfcp_teid *t);
uint32_t pfcp_bpf_alloc_ttc_idx(struct pfcp_session *s);
void pfcp_bpf_release_ttc_idx(struct pfcp_session *s, uint32_t ttc_idx);
struct upf_mbr *pfcp_bpf_mbr_data(struct pfcp_session *s, uint32_t mbr_idx);
uint32_t pfcp_bpf_alloc_mbr_idx(struct pfcp_session *s);
void pfcp_bpf_release_mbr_idx(struct pfcp_session *s, uint32_t mbr_idx);
uint64_t pfcp_bpf_lookup_seid(struct pfcp_router *r, const struct upf_egress_key *ek);

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

#pragma once

typedef struct _gtp_bpf_prog gtp_bpf_prog_t;
typedef struct _gtp_interface gtp_interface_t;

/* default protocol timeout values */
#define CGN_PROTO_TIMEOUT_TCP_EST	600
#define CGN_PROTO_TIMEOUT_TCP_SYNFIN	120
#define CGN_PROTO_TIMEOUT_UDP		120
#define CGN_PROTO_TIMEOUT_ICMP		120

/* timeout are in seconds */
struct port_timeout_config
{
	uint16_t udp;
	uint16_t tcp_synfin;
	uint16_t tcp_est;
};

/* bpf maps */
enum {
	BPF_CGN_MAP_V4_BLOCKS = 0,
	BPF_CGN_MAP_V4_FREE_BLOCKS,
	BPF_CGN_MAP_USERS,
	BPF_CGN_MAP_FLOW_PORT_TIMEOUTS,
	BPF_CGN_MAP_CNT
};

struct cgn_ctx
{
	char			name[GTP_NAME_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	list_head_t		next;

	/* links to bpf-prog and interfaces */
	gtp_bpf_prog_t		*prg;
	gtp_interface_t		*iface_pub;
	gtp_interface_t		*iface_priv;

	/* conf. read-only after bpf prog is opened */
	uint32_t		*cgn_addr;	/* array of size 'cgn_addr_n' */
	uint32_t		cgn_addr_n;
	uint16_t		port_start;
	uint16_t		port_end;
	uint32_t		block_size;	/* # of port per block */
	uint32_t		block_count;	/* # of block per ip */
	uint32_t		flow_per_user;	/* max # of flow per user */
	uint8_t			block_per_user;	/* max # of blocks per user */
	struct port_timeout_config timeout;
	struct port_timeout_config timeout_by_port[0x10000];
	uint16_t		timeout_icmp;

	/* internal */
	int			block_msize;

	/* metrics */
};

/* cgn.c */
int cgn_ctx_compact_cgn_addr(struct cgn_ctx *c, uint64_t *out);
int cgn_ctx_dump(struct cgn_ctx *c, char *b, size_t s);
struct cgn_ctx *cgn_ctx_get_by_name(const char *name);
void cgn_ctx_release(struct cgn_ctx *cgn);
struct cgn_ctx *cgn_ctx_alloc(const char *name);
int cgn_init(void);
int cgn_destroy(void);

/* cgn_vty.c */
int cgn_vty_init(void);

/* traf_acl.c */
void traf_acl_add(gtp_bpf_prog_t *p, gtp_interface_t *from,
		  gtp_interface_t *to, int action);
void traf_acl_update_lladdr(gtp_bpf_prog_t *p, gtp_interface_t *from,
			    gtp_interface_t *to);
void traf_acl_del(gtp_bpf_prog_t *p, gtp_interface_t *from);

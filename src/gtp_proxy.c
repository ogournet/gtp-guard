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

#include <sys/prctl.h>

#include "gtp_data.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_server.h"
#include "gtp_proxy.h"
#include "gtp_dpd.h"
#include "gtp_sqn.h"
#include "gtp_proxy_hdl.h"
#include "bitops.h"
#include "memory.h"
#include "inet_utils.h"
#include "bpf/lib/gtp_fwd-def.h"

/* Extern data */
extern struct data *daemon_data;


/*
 *	Helpers
 */
int
gtp_proxy_gtpc_teid_destroy(struct gtp_teid *teid)
{
	struct gtp_session *s = teid->session;
	struct gtp_server *srv = s->srv;
	struct gtp_proxy *ctx = srv->ctx;

	gtp_vteid_unhash(&ctx->vteid_tab, teid);
	gtp_teid_unhash(&ctx->gtpc_teid_tab, teid);
	gtp_vsqn_unhash(&ctx->vsqn_tab, teid);
	return 0;
}

int
gtp_proxy_gtpu_teid_destroy(struct gtp_teid *teid)
{
	struct gtp_session *s = teid->session;
	struct gtp_server *srv = s->srv;
	struct gtp_proxy *ctx = srv->ctx;

	gtp_vteid_unhash(&ctx->vteid_tab, teid);
	gtp_teid_unhash(&ctx->gtpu_teid_tab, teid);
	return 0;
}

static void
gtp_proxy_fwd_addr_get(struct gtp_teid *teid, struct sockaddr_storage *from, struct sockaddr_in *to)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) from;

	if (addr4->sin_addr.s_addr == teid->sgw_addr.sin_addr.s_addr) {
		*to = teid->pgw_addr;
	} else {
		*to = teid->sgw_addr;
	}

	if (teid->family == GTP_INIT)
		to->sin_port = htons(GTP_C_PORT);
}

int
gtp_proxy_ingress_init(struct inet_server *srv)
{
	return 0;
}

int
gtp_proxy_ingress_process(struct inet_server *srv, struct sockaddr_storage *addr_from)
{
	struct gtp_server *s = srv->ctx;
	struct gtp_proxy *ctx = s->ctx;
	struct gtp_server *s_egress = &ctx->gtpc_egress;
	struct sockaddr_in addr_to;
	struct gtp_teid *teid;
	int fd = srv->fd;

	/* GTP-U handling */
	if (__test_bit(GTP_FL_UPF_BIT, &s->flags)) {
		teid = gtpu_proxy_handle(s, addr_from);
		if (!teid)
			return -1;

		inet_server_snd(srv, srv->fd, srv->pbuff, (struct sockaddr_in *) addr_from);
		return 0;
	}

	/* GTP-C handling */
	teid = gtpc_proxy_handle(s, addr_from);
	if (!teid)
		return -1;

	/* Select appropriate socket. If egress channel is configured
	 * then split socket */
	if (__test_bit(GTP_FL_CTL_BIT, &s_egress->flags)) {
		if (__test_bit(GTP_FL_GTPC_INGRESS_BIT, &s->flags))
			fd = ctx->gtpc_egress.s.fd;
		else if (__test_bit(GTP_FL_GTPC_EGRESS_BIT, &s->flags))
			fd = ctx->gtpc.s.fd;
	}

	/* Set destination address */
	gtp_proxy_fwd_addr_get(teid, addr_from, &addr_to);
	inet_server_snd(srv, TEID_IS_DUMMY(teid) ? srv->fd : fd, srv->pbuff,
			TEID_IS_DUMMY(teid) ? (struct sockaddr_in *) addr_from : &addr_to);
	gtpc_proxy_handle_post(s, teid);

	return 0;
}

static void
_set_base_rules(struct gtp_proxy *ctx)
{
	struct if_rule_key k = {};
	struct gtp_if_rule ifr_ingress = {
		.from = ctx->iface_ingress,
		.to = ctx->iface_egress,
		.key = &k,
		.key_size = sizeof (k),
		.action = 10,
		.prio = 100,
	};
	struct gtp_if_rule ifr_egress = {
		.from = ctx->iface_egress,
		.to = ctx->iface_ingress,
		.key = &k,
		.key_size = sizeof (k),
		.action = 11,
		.prio = 100,
	};
	gtp_interface_rule_add(&ifr_ingress);
	gtp_interface_rule_add(&ifr_egress);
}

static void
_set_tun_rules(struct gtp_proxy *ctx)
{
	struct if_rule_key k1 = {
		.selector_addr = addr_toip4(&ctx->iface_ingress->addr)
	};
	struct if_rule_key k2 = {
		.selector_addr = addr_toip4(&ctx->iface_egress->addr)
	};

	/* ipip-egress */
	struct if_rule_key k3 = {
		.selector_addr = addr_toip4(&ctx->iface_egress->addr)
	};
	struct if_rule_key k4 = {
		.selector_addr = htonl(0xc0a83d01), // XXX install from teid ?
	};

	struct gtp_if_rule ifr1 = {
		.from = ctx->iface_ingress,
		.to = ctx->iface_tun,
		.key = &k1,
		.key_size = sizeof (k1),
		.action = 12,
		.prio = 100,
	};
	struct gtp_if_rule ifr2 = {
		.from = ctx->iface_egress,
		.to = ctx->iface_tun,
		.key = &k2,
		.key_size = sizeof (k2),
		.action = 13,
		.prio = 100,
	};
	struct gtp_if_rule ifr3 = {
		.from = ctx->iface_tun,
		.to = ctx->iface_ingress,
		.key = &k3,
		.key_size = sizeof (k3),
		.action = 14,
		.prio = 100,
	};
	struct gtp_if_rule ifr4 = {
		.from = ctx->iface_tun,
		.to = ctx->iface_egress,
		.key = &k4,
		.key_size = sizeof (k4),
		.action = 15,
		.prio = 100,
	};
	gtp_interface_rule_add(&ifr1);
	gtp_interface_rule_add(&ifr2);
	gtp_interface_rule_add(&ifr3);
	gtp_interface_rule_add(&ifr4);
}

void
gtp_proxy_set_rules(struct gtp_proxy *ctx)
{
	printf("set rule: %d\n", ctx->rules_set);

	/* set new traffic rules */
	if (ctx->bind_ingress && ctx->bind_egress &&
	    ctx->bind_ipip && !(ctx->tun_flags & IPTNL_FL_DEAD)) {
		if (ctx->rules_set == 0) {
			_set_base_rules(ctx);
			ctx->rules_set = 1;
		}
		if (ctx->rules_set == 1) {
			_set_tun_rules(ctx);
			ctx->rules_set = 2;
		}

	} else if (ctx->bind_ingress && ctx->bind_egress) {
		if (ctx->rules_set == 0) {
			_set_base_rules(ctx);
			ctx->rules_set = 1;
		}
		if (ctx->rules_set == 2) {
			gtp_interface_rule_del_iface(ctx->iface_tun);
			ctx->rules_set = 1;
		}

	} else {
		if (ctx->rules_set == 2) {
			gtp_interface_rule_del_iface(ctx->iface_tun);
			ctx->rules_set = 1;
		}
		if (ctx->rules_set == 1) {
			gtp_interface_rule_del_iface(ctx->iface_ingress);
			gtp_interface_rule_del_iface(ctx->iface_egress);
			ctx->rules_set = 0;
		}
	}

	printf("set rule done: %d\n", ctx->rules_set);
}

void
gtp_proxy_iface_event_cb(struct gtp_interface *iface,
			 enum gtp_interface_event type,
			 void *ud, void *arg)
{
	struct gtp_proxy *ctx = ud;

	printf("iface:%s event %d\n", iface->ifname, type);

	switch (type) {
	case GTP_INTERFACE_EV_PRG_BIND:
		if (iface == ctx->iface_ingress)
			ctx->bind_ingress = true;
		if (iface == ctx->iface_egress)
			ctx->bind_egress = true;
		if (iface == ctx->iface_tun)
			ctx->bind_ipip = true;
		break;

	case GTP_INTERFACE_EV_PRG_UNBIND:
	case GTP_INTERFACE_EV_DESTROYING:
		if (iface == ctx->iface_ingress)
			ctx->bind_ingress = false;
		if (iface == ctx->iface_egress)
			ctx->bind_egress = false;
		if (iface == ctx->iface_tun)
			ctx->bind_ipip = false;
		break;

	case GTP_INTERFACE_EV_VTY_SHOW:
	{
		struct vty *vty = arg;
		if (iface == ctx->iface_ingress)
			vty_out(vty, " gtp-proxy:%s side gtpu-ingress\n",
				ctx->name);
		if (iface == ctx->iface_egress)
			vty_out(vty, " gtp-proxy:%s side gtpu-egress\n",
				ctx->name);
		if (iface == ctx->iface_tun)
			vty_out(vty, " gtp-proxy:%s side gtpu-tun\n",
				ctx->name);
		break;
	}
	default:
		break;
	}

	gtp_proxy_set_rules(ctx);

	if (type == GTP_INTERFACE_EV_DESTROYING) {
		if (iface == ctx->iface_ingress)
			ctx->iface_ingress = NULL;
		if (iface == ctx->iface_egress)
			ctx->iface_egress = NULL;
		if (iface == ctx->iface_tun)
			ctx->iface_tun = NULL;
	}
}


struct gtp_proxy *
gtp_proxy_get(const char *name)
{
	struct gtp_proxy *ctx;
	size_t len = strlen(name);

	list_for_each_entry(ctx, &daemon_data->gtp_proxy_ctx, next) {
		if (!memcmp(ctx->name, name, len))
			return ctx;
	}

	return NULL;
}

struct gtp_proxy *
gtp_proxy_init(const char *name)
{
	struct gtp_proxy *new;

	PMALLOC(new);
	if (!new) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&new->next);
	INIT_LIST_HEAD(&new->iptnl.decap_pfx_vlan);
	strncpy(new->name, name, GTP_NAME_MAX_LEN - 1);
	list_add_tail(&new->next, &daemon_data->gtp_proxy_ctx);

	/* Init hashtab */
	gtp_htab_init(&new->gtpc_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->gtpu_teid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->vteid_tab, CONN_HASHTAB_SIZE);
	gtp_htab_init(&new->vsqn_tab, CONN_HASHTAB_SIZE);

	return new;
}

int
gtp_proxy_ctx_server_destroy(struct gtp_proxy *ctx)
{
	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpc_egress);
	gtp_server_destroy(&ctx->gtpu);
	gtp_dpd_destroy(ctx);
	return 0;
}

int
gtp_proxy_ctx_destroy(struct gtp_proxy *ctx)
{
	gtp_htab_destroy(&ctx->gtpc_teid_tab);
	gtp_htab_destroy(&ctx->gtpu_teid_tab);
	gtp_htab_destroy(&ctx->vteid_tab);
	gtp_htab_destroy(&ctx->vsqn_tab);
	list_head_del(&ctx->next);
	FREE(ctx);
	return 0;
}

int
gtp_proxy_server_destroy(void)
{
	struct gtp_proxy *c;

	list_for_each_entry(c, &daemon_data->gtp_proxy_ctx, next)
		gtp_proxy_ctx_server_destroy(c);

	return 0;
}

int
gtp_proxy_destroy(void)
{
	struct gtp_proxy *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_proxy_ctx, next) {
		gtp_proxy_ctx_destroy(c);
	}

	return 0;
}

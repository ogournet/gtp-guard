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

#include <arpa/inet.h>
#include <sys/prctl.h>

#include "gtp_data.h"
#include "gtp_teid.h"
#include "gtp_session.h"
#include "gtp_server.h"
#include "gtp_proxy.h"
#include "gtp_dpd.h"
#include "gtp_sqn.h"
#include "gtp_bpf_utils.h"
#include "gtp_proxy_hdl.h"
#include "bitops.h"
#include "memory.h"
#include "inet_utils.h"
#include "utils.h"
#include "jhash.h"
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

	gtp_vteid_unhash(ctx->vteid_tab, teid);
	gtp_teid_unhash(ctx->gtpc_teid_tab, teid);
	gtp_vsqn_unhash(ctx->vsqn_tab, teid);
	return 0;
}

int
gtp_proxy_gtpu_teid_destroy(struct gtp_teid *teid)
{
	struct gtp_session *s = teid->session;
	struct gtp_server *srv = s->srv;
	struct gtp_proxy *ctx = srv->ctx;

	gtp_vteid_unhash(ctx->vteid_tab, teid);
	gtp_teid_unhash(ctx->gtpu_teid_tab, teid);
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

static int
_show_key(const struct gtp_if_rule *r, char *buf, int size)
{
	const struct if_rule_key *k = r->key;
	char sb[128], db[128];

	if (!k->saddr && !k->daddr) {
		*buf = 0;
		return 0;
	}
	return scnprintf(buf, size, "src_addr:%s dst_addr:%s",
			 inet_ntop(AF_INET, &k->saddr, sb, sizeof (sb)),
			 inet_ntop(AF_INET, &k->daddr, db, sizeof (db)));
}

static void
_set_base_rules(struct gtp_proxy *ctx, bool add)
{
	struct if_rule_key k = {};
	struct gtp_if_rule ifr1 = {
		.from = ctx->iface_ingress,
		.to = ctx->iface_egress,
		.key = &k,
		.key_size = sizeof (k),
		.action = 10,
		.prio = 200,
	};
	if (add)
		gtp_interface_rule_add(&ifr1);
	else
		gtp_interface_rule_del(&ifr1);

	if (ctx->iface_ingress != ctx->iface_egress) {
		struct gtp_if_rule ifr2 = {
			.from = ctx->iface_egress,
			.to = ctx->iface_ingress,
			.key = &k,
			.key_size = sizeof (k),
			.action = 10,
			.prio = 100,
		};
		if (add)
			gtp_interface_rule_add(&ifr2);
		else
			gtp_interface_rule_del(&ifr2);
	}

	gtp_interface_rule_set_custom_key_stringify(ctx->bpf_prog, _show_key);
}

static void
_set_tun_rules(struct gtp_proxy *ctx, uint32_t addr, bool egress, bool add)
{
	bool xlat_before = false, xlat_after = false;
	uint32_t local;

	if ((ctx->ipip_xlat == 2 && !egress) ||
	    (ctx->ipip_xlat == 1 && egress) ||
	    ctx->ipip_xlat == 3)
		xlat_before = true;
	if ((ctx->ipip_xlat == 1 && !egress) ||
	    (ctx->ipip_xlat == 2 && egress) ||
	    ctx->ipip_xlat == 3)
		xlat_after = true;

	if (!egress || (local = inet_sockaddrip4(&ctx->gtpu_egress.s.addr)) == (uint32_t)-1)
		local = inet_sockaddrip4(&ctx->gtpu.s.addr);

	/* rule to put into tunnel */
	struct if_rule_key k = {
		.saddr = addr,
		.daddr = local,
	};
	struct gtp_if_rule ifr = {
		.from = egress ? ctx->iface_egress : ctx->iface_ingress,
		.to = ctx->ipip_iface,
		.key = &k,
		.key_size = sizeof (k),
		.action = xlat_before ? 11 : 12,
		.prio = 100,
	};
	if (add)
		gtp_interface_rule_add(&ifr);
	else
		gtp_interface_rule_del(&ifr);

	if (!xlat_before) {
		/* rule from tunnel, same packet, will xlat */
		struct gtp_if_rule ifr = {
			.from = ctx->ipip_iface,
			.to = egress ? ctx->iface_egress : ctx->iface_ingress,
			.key = &k,
			.key_size = sizeof (k),
			.action = 13,
			.prio = 100,
		};
		if (add)
			gtp_interface_rule_add(&ifr);
		else
			gtp_interface_rule_del(&ifr);
	}

	if (xlat_after) {
		/* rule from tunnel, xlat'ed on other side  */
		struct if_rule_key k = {
			.saddr = local,
			.daddr = addr,
		};
		struct gtp_if_rule ifr = {
			.from = ctx->ipip_iface,
			.to = egress ? ctx->iface_egress : ctx->iface_ingress,
			.key = &k,
			.key_size = sizeof (k),
			.action = 14,
			.prio = 100,
		};
		if (add)
			gtp_interface_rule_add(&ifr);
		else
			gtp_interface_rule_del(&ifr);
	}

	printf("%s tun rule %s local %x dst %x, xlat:%d xlat_before:%d after:%d "
	       "| to ipip:%d\n",
	       add ? "add" : "del",
	       egress ? "egress" : "ingress",
	       local, addr,
	       ctx->ipip_xlat,
	       xlat_before, xlat_after,
	       ifr.action);
}

static void
_set_all_tun_rules(struct gtp_proxy *ctx, bool add)
{
	struct gtp_proxy_remote_addr *a;
	int i;

	for (i = 0; i < GTP_PROXY_REMOTE_ADDR_HSIZE; i++)
		hlist_for_each_entry(a, &ctx->ipip_ingress[i], hlist)
			_set_tun_rules(ctx, a->addr, false, add);
	for (i = 0; i < GTP_PROXY_REMOTE_ADDR_HSIZE; i++)
		hlist_for_each_entry(a, &ctx->ipip_egress[i], hlist)
			_set_tun_rules(ctx, a->addr, true, add);
}

/* set new traffic rules */
void
gtp_proxy_rules_set(struct gtp_proxy *ctx)
{
	int rule_set = ctx->rules_set;

	if (ctx->rules_set == 0 && ctx->bind_ingress && ctx->bind_egress) {
		_set_base_rules(ctx, true);
		ctx->rules_set = 1;
	}

	if (ctx->bind_ingress && ctx->bind_egress &&
	    ctx->ipip_bind && !ctx->ipip_dead) {
		if (ctx->rules_set == 1) {
			_set_all_tun_rules(ctx, true);
			ctx->rules_set = 2;
		}

	} else if (ctx->rules_set == 2) {
		_set_all_tun_rules(ctx, false);
		ctx->rules_set = 1;
	}

	if (ctx->rules_set == 1 && !(ctx->bind_ingress && ctx->bind_egress)) {
		_set_base_rules(ctx, false);
		ctx->rules_set = 0;
	}

	if (rule_set != ctx->rules_set)
		printf("set rule: %d => %d\n", rule_set, ctx->rules_set);
}

int
gtp_proxy_rules_remote_exists(struct gtp_proxy *ctx, __be32 addr, bool *egress)
{
	struct gtp_proxy_remote_addr *a;
	uint32_t h;

	h = jhash_1word(addr, 0) % GTP_PROXY_REMOTE_ADDR_HSIZE;
	hlist_for_each_entry(a, &ctx->ipip_ingress[h], hlist) {
		if (a->addr == addr) {
			*egress = false;
			return 0;
		}
	}
	hlist_for_each_entry(a, &ctx->ipip_egress[h], hlist) {
		if (a->addr == addr) {
			*egress = true;
			return 0;
		}
	}

	return -1;
}

void
gtp_proxy_rules_remote_set(struct gtp_proxy *ctx, __be32 addr,
			   int action, bool egress)
{
	struct gtp_proxy_remote_addr *a;
	struct hlist_head *head;
	uint32_t h;

	printf("%s %s addr: 0x%x\n",
	       action == RULE_ADD ? "add" : "del",
	       egress ? "pgw" : "sgw",
	       addr);

	h = jhash_1word(addr, 0) % GTP_PROXY_REMOTE_ADDR_HSIZE;
	head = egress ? &ctx->ipip_egress[h] : &ctx->ipip_ingress[h];
	hlist_for_each_entry(a, head, hlist) {
		if (a->addr == addr) {
			if (action == RULE_DEL) {
				if (ctx->rules_set == 2)
					_set_tun_rules(ctx, addr, egress, false);
				hlist_del(&a->hlist);
				free(a);
			}
			return;
		}
	}
	if (action == RULE_DEL)
		return;

	a = malloc(sizeof (*a));
	if (a == NULL)
		return;
	a->addr = addr;
	hlist_add_head(&a->hlist, head);
	if (ctx->rules_set == 2)
		_set_tun_rules(ctx, addr, egress, true);
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
		break;

	case GTP_INTERFACE_EV_PRG_UNBIND:
	case GTP_INTERFACE_EV_DESTROYING:
		if (iface == ctx->iface_ingress)
			ctx->bind_ingress = false;
		if (iface == ctx->iface_egress)
			ctx->bind_egress = false;
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
		break;
	}
	default:
		break;
	}

	gtp_proxy_rules_set(ctx);

	if (type == GTP_INTERFACE_EV_DESTROYING) {
		if (iface == ctx->iface_ingress)
			ctx->iface_ingress = NULL;
		if (iface == ctx->iface_egress)
			ctx->iface_egress = NULL;
	}
}

void
gtp_proxy_iface_tun_event_cb(struct gtp_interface *iface,
			     enum gtp_interface_event type,
			     void *ud, void *arg)
{
	struct gtp_proxy *ctx = ud;

	printf("iface:%s event %d\n", iface->ifname, type);

	switch (type) {
	case GTP_INTERFACE_EV_PRG_BIND:
		ctx->ipip_bind = true;
		break;
	case GTP_INTERFACE_EV_PRG_UNBIND:
	case GTP_INTERFACE_EV_DESTROYING:
		ctx->ipip_bind = false;
		break;
	case GTP_INTERFACE_EV_VTY_SHOW:
	{
		struct vty *vty = arg;
		vty_out(vty, " gtp-proxy:%s gtpu-ipip\n", ctx->name);
		break;
	}
	default:
		break;
	}

	gtp_proxy_rules_set(ctx);

	if (type == GTP_INTERFACE_EV_DESTROYING)
		ctx->ipip_iface = NULL;
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
gtp_proxy_alloc(const char *name)
{
	struct gtp_proxy *ctx;

	PMALLOC(ctx);
	if (!ctx) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&ctx->next);
	INIT_LIST_HEAD(&ctx->iptnl.decap_pfx_vlan);
	strncpy(ctx->name, name, GTP_NAME_MAX_LEN - 1);
	list_add_tail(&ctx->next, &daemon_data->gtp_proxy_ctx);

	/* Init hashtab */
	ctx->gtpc_teid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	ctx->gtpu_teid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	ctx->vteid_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	ctx->vsqn_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));

	ctx->ipip_ingress = calloc(GTP_PROXY_REMOTE_ADDR_HSIZE,
				   sizeof (struct hlist_head));
	ctx->ipip_egress = calloc(GTP_PROXY_REMOTE_ADDR_HSIZE,
				  sizeof (struct hlist_head));

	return ctx;
}

static void
gtp_proxy_ctx_server_stop(struct gtp_proxy *ctx)
{
	struct gtp_proxy_remote_addr *a;
	struct hlist_node *tmp;
	int i;

	if (ctx->ipip_iface) {
		gtp_interface_unregister_event(ctx->ipip_iface,
					       gtp_proxy_iface_tun_event_cb);
		gtp_proxy_iface_tun_event_cb(ctx->ipip_iface,
					     GTP_INTERFACE_EV_DESTROYING,
					     ctx, NULL);
	}
	if (ctx->iface_ingress) {
		gtp_interface_unregister_event(ctx->iface_ingress,
					       gtp_proxy_iface_event_cb);
		gtp_proxy_iface_event_cb(ctx->iface_ingress,
					 GTP_INTERFACE_EV_DESTROYING,
					 ctx, NULL);
	}
	if (ctx->iface_egress) {
		gtp_interface_unregister_event(ctx->iface_egress,
					       gtp_proxy_iface_event_cb);
		gtp_proxy_iface_event_cb(ctx->iface_egress,
					 GTP_INTERFACE_EV_DESTROYING,
					 ctx, NULL);
	}
	for (i = 0; i < GTP_PROXY_REMOTE_ADDR_HSIZE; i++) {
		hlist_for_each_entry_safe(a, tmp, &ctx->ipip_ingress[i], hlist) {
			hlist_del(&a->hlist);
			free(a);
		}
		hlist_for_each_entry_safe(a, tmp, &ctx->ipip_egress[i], hlist) {
			hlist_del(&a->hlist);
			free(a);
		}
	}

	gtp_server_destroy(&ctx->gtpc);
	gtp_server_destroy(&ctx->gtpc_egress);
	gtp_server_destroy(&ctx->gtpu);
	gtp_server_destroy(&ctx->gtpu_egress);
	gtp_dpd_destroy(ctx);
}

void
gtp_proxy_ctx_destroy(struct gtp_proxy *ctx)
{
	gtp_proxy_ctx_server_stop(ctx);
	free(ctx->ipip_ingress);
	free(ctx->ipip_egress);
	free(ctx->gtpc_teid_tab);
	free(ctx->gtpu_teid_tab);
	free(ctx->vteid_tab);
	free(ctx->vsqn_tab);
	list_del(&ctx->next);
	FREE(ctx);
}

void
gtp_proxy_server_stop(void)
{
	struct gtp_proxy *c;

	list_for_each_entry(c, &daemon_data->gtp_proxy_ctx, next)
		gtp_proxy_ctx_server_stop(c);
}

void
gtp_proxy_destroy(void)
{
	struct gtp_proxy *c, *_c;

	list_for_each_entry_safe(c, _c, &daemon_data->gtp_proxy_ctx, next)
		gtp_proxy_ctx_destroy(c);
}

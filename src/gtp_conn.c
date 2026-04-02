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

#include "gtp_conn.h"
#include "gtp_session.h"
#include "logger.h"
#include "jhash.h"
#include "bitops.h"
#include "memory.h"


/* Local data */
static struct hlist_head *gtp_imsi_tab;
static struct hlist_head *gtp_imei_tab;
static struct hlist_head *gtp_msisdn_tab;


/*
 *	IMSI Hashtab handling
 */
static struct hlist_head *
gtp_conn_hashkey(struct hlist_head *h, uint64_t id)
{
	return h + (jhash_2words((uint32_t)id, (uint32_t) (id >> 32), 0) & CONN_HASHTAB_MASK);
}

static struct gtp_conn *
gtp_conn_get_by_type(int type, uint64_t id)
{
	struct hlist_head *head = NULL;
	struct gtp_conn *c;

	switch (type) {
	case GTP_CONN_F_IMSI_HASHED:
		head = gtp_conn_hashkey(gtp_imsi_tab, id);
		break;
	case GTP_CONN_F_IMEI_HASHED:
		head = gtp_conn_hashkey(gtp_imei_tab, id);
		break;
	case GTP_CONN_F_MSISDN_HASHED:
		head = gtp_conn_hashkey(gtp_msisdn_tab, id);
		break;
	}

	hlist_for_each_entry(c, head, h_imsi) {
		switch (type) {
		case GTP_CONN_F_IMSI_HASHED:
			if (c->imsi == id)
				return c;
			break;
		case GTP_CONN_F_IMEI_HASHED:
			if (c->imei == id)
				return c;
			break;
		case GTP_CONN_F_MSISDN_HASHED:
			if (c->msisdn == id)
				return c;
			break;
		}
	}

	return NULL;
}

struct gtp_conn *
gtp_conn_get_by_imsi(uint64_t imsi)
{
	return gtp_conn_get_by_type(GTP_CONN_F_IMSI_HASHED, imsi);
}

struct gtp_conn *
gtp_conn_get_by_imei(uint64_t imei)
{
	return gtp_conn_get_by_type(GTP_CONN_F_IMEI_HASHED, imei);
}

struct gtp_conn *
gtp_conn_get_by_msisdn(uint64_t msisdn)
{
	return gtp_conn_get_by_type(GTP_CONN_F_MSISDN_HASHED, msisdn);
}

static void
gtp_conn_hash(struct gtp_conn *c)
{
	struct hlist_head *head;

	head = gtp_conn_hashkey(gtp_imsi_tab, c->imsi);
	hlist_add_head(&c->h_imsi, head);
	__set_bit(GTP_CONN_F_IMSI_HASHED, &c->flags);

	if (c->imei) {
		head = gtp_conn_hashkey(gtp_imei_tab, c->imei);
		hlist_add_head(&c->h_imei, head);
		__set_bit(GTP_CONN_F_IMEI_HASHED, &c->flags);
	}

	if (c->msisdn) {
		head = gtp_conn_hashkey(gtp_msisdn_tab, c->msisdn);
		hlist_add_head(&c->h_msisdn, head);
		__set_bit(GTP_CONN_F_MSISDN_HASHED, &c->flags);
	}
}

static void
gtp_conn_unhash(struct gtp_conn *c)
{
	hlist_del(&c->h_imsi);
	__clear_bit(GTP_CONN_F_IMSI_HASHED, &c->flags);

	if (__test_and_clear_bit(GTP_CONN_F_IMEI_HASHED, &c->flags))
		hlist_del(&c->h_imei);

	if (__test_and_clear_bit(GTP_CONN_F_MSISDN_HASHED, &c->flags))
		hlist_del(&c->h_msisdn);
}

int
gtp_conn_vty(struct vty *vty, int (*vty_conn) (struct vty *, struct gtp_conn *, void *),
	     uint64_t imsi, void *arg)
{
	struct gtp_conn *c;
	int i;

	if (imsi) {
		c = gtp_conn_get_by_imsi(imsi);
		if (!c)
			return -1;
		(*vty_conn) (vty, c, arg);
		return 0;
	}

	/* Iterate */
	for (i = 0; i < CONN_HASHTAB_SIZE; i++) {
		hlist_for_each_entry(c, &gtp_imsi_tab[i], h_imsi) {
			(*vty_conn) (vty, c, arg);
		}
	}

	return 0;
}

/*
 *	Connection related
 */
void
gtp_conn_init(struct gtp_conn *c, uint64_t imsi, uint64_t imei, uint64_t msisdn)
{
	c->imsi = imsi;
	c->imei = imei;
	c->msisdn = msisdn;
	c->ts = time(NULL);
	INIT_LIST_HEAD(&c->gtp_sessions);
	INIT_LIST_HEAD(&c->pppoe_sessions);

	gtp_conn_hash(c);
}

struct gtp_conn *
gtp_conn_alloc(uint64_t imsi, uint64_t imei, uint64_t msisdn)
{
	struct gtp_conn *new;

	PMALLOC(new);
	gtp_conn_init(new, imsi, imei, msisdn);

	return new;
}

struct gtp_conn *
gtp_conn_refinc(struct gtp_conn *c)
{
	++c->refcnt;
	return c;
}

void
gtp_conn_refdec(struct gtp_conn *c)
{
	if (c == NULL)
		return;

	if (--c->refcnt == 0) {
		log_message(LOG_INFO, "IMSI:%ld - no more sessions - Releasing tracking"
			            , c->imsi);
		gtp_conn_unhash(c);
		free(c);
	}
}


/*
 *	Connection tracking init
 */
int
gtp_conn_module_init(void)
{
	gtp_imsi_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	gtp_imei_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	gtp_msisdn_tab = calloc(CONN_HASHTAB_SIZE, sizeof(struct hlist_head));
	return 0;
}

int
gtp_conn_module_destroy(void)
{
	struct hlist_node *n;
	struct gtp_conn *c;
	int i;

	for (i = 0; i < CONN_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(c, n, &gtp_imsi_tab[i], h_imsi) {
			gtp_sessions_free(c);
			FREE(c);
		}
	}

	free(gtp_imsi_tab);
	free(gtp_imei_tab);
	free(gtp_msisdn_tab);
	return 0;
}

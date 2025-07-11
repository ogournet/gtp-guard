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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */

/* system includes */
#include <sys/prctl.h>
#include <fnmatch.h>

/* local includes */
#include "gtp_guard.h"

/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Utilities
 */
void
gtp_apn_foreach(int (*hdl) (gtp_apn_t *, void *), void *arg)
{
	list_head_t *l = &daemon_data->gtp_apn;
	gtp_apn_t *apn;

	list_for_each_entry(apn, l, next)
		(*(hdl)) (apn, arg);
}

/*
 *	Rewrite rule related
 */
gtp_rewrite_rule_t *
gtp_rewrite_rule_alloc(gtp_apn_t *apn, list_head_t *l)
{
	gtp_rewrite_rule_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);

	pthread_mutex_lock(&apn->mutex);
	list_add_tail(&new->next, l);
	pthread_mutex_unlock(&apn->mutex);

	return new;
}

static int
gtp_rewrite_rule_destroy(gtp_apn_t *apn, list_head_t *l)
{
	gtp_rewrite_rule_t *r, *_r;

	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry_safe(r, _r, l, next) {
		list_head_del(&r->next);
		FREE(r);
	}
	pthread_mutex_unlock(&apn->mutex);
	return 0;
}


/*
 *	APN Resolv cache maintain
 */
int
apn_resolv_cache_realloc(gtp_apn_t *apn)
{
	gtp_resolv_ctx_t *ctx;
	list_head_t l, old_naptr;
	int err;

	/* Context init */
	ctx = gtp_resolv_ctx_alloc(apn);
	if (!ctx)
		return -1;

	if (!ctx->realm) {
		log_message(LOG_INFO, "%s(): no realm available to resolv naptr... keeping previous..."
				    , __FUNCTION__);
		gtp_resolv_ctx_destroy(ctx);
		return -1;
	}

	/* Create temp resolv */
	INIT_LIST_HEAD(&l);
	err = gtp_resolv_naptr(ctx, &l, "%s.%s", apn->name, ctx->realm);
	if (err) {
		log_message(LOG_INFO, "%s(): Unable to update resolv cache while resolving naptr... keeping previous..."
				    , __FUNCTION__);
		gtp_resolv_ctx_destroy(ctx);
		return -1;
	}

	err = gtp_resolv_pgw(ctx, &l);
	if (err) {
		log_message(LOG_INFO, "%s(): Unable to update resolv cache while resolving pgw... keeping previous..."
				    , __FUNCTION__);
		gtp_resolv_ctx_destroy(ctx);
		return -1;
	}

	/* Swap list and update refs */
	log_message(LOG_INFO, "%s(): APN:%s - Performing resolv-cache update"
			    , __FUNCTION__, apn->name);
	pthread_mutex_lock(&apn->mutex);
	list_copy(&old_naptr, &apn->naptr);
	list_copy(&apn->naptr, &l);
	pthread_mutex_unlock(&apn->mutex);

	/* Release previous elements */
	if (!list_empty(&old_naptr))
		log_message(LOG_INFO, "%s(): APN:%s - Releasing old resolv-cache"
				    , __FUNCTION__, apn->name);
	gtp_naptr_destroy(&old_naptr);
	apn->last_update = time(NULL);

	gtp_resolv_ctx_destroy(ctx);
	return 0;
}


void *
apn_resolv_cache_task(void *arg)
{
	gtp_apn_t *apn = arg;
	struct timeval tval;
	struct timespec timeout;

        /* Our identity */
        prctl(PR_SET_NAME, "resolv_cache", 0, 0, 0, 0);

  cache_process:
	/* Schedule interruptible timeout */
	pthread_mutex_lock(&apn->cache_mutex);
	gettimeofday(&tval, NULL);
	timeout.tv_sec = tval.tv_sec + apn->resolv_cache_update;
	timeout.tv_nsec = tval.tv_usec * 1000;
	pthread_cond_timedwait(&apn->cache_cond, &apn->cache_mutex, &timeout);
	pthread_mutex_unlock(&apn->cache_mutex);

	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		goto cache_finish;

	/* Update */
	apn_resolv_cache_realloc(apn);

	goto cache_process;

  cache_finish:
	return NULL;
}

int
apn_resolv_cache_signal(gtp_apn_t *apn)
{
	pthread_mutex_lock(&apn->cache_mutex);
	pthread_cond_signal(&apn->cache_cond);
	pthread_mutex_unlock(&apn->cache_mutex);
	return 0;
}

static int
apn_resolv_cache_destroy(gtp_apn_t *apn)
{
	apn_resolv_cache_signal(apn);
	pthread_join(apn->cache_task, NULL);
	gtp_naptr_destroy(&apn->naptr);
	return 0;
}


/*
 *	Static IP Pool related
 */
gtp_ip_pool_t *
gtp_ip_pool_alloc(uint32_t network, uint32_t netmask)
{
	gtp_ip_pool_t *new;

	PMALLOC(new);
	if (!new)
		return NULL;
	new->network = network;
	new->netmask = netmask;
	new->lease = (bool *) MALLOC(ntohl(~netmask) * sizeof(bool));
	new->next_lease_idx = 10;

	return new;
}

void
gtp_ip_pool_destroy(gtp_ip_pool_t *ip_pool)
{
	if (!ip_pool)
		return;

	FREE(ip_pool->lease);
	FREE(ip_pool);
}

uint32_t
gtp_ip_pool_get(gtp_apn_t *apn)
{
	gtp_ip_pool_t *ip_pool = apn->ip_pool;
	int idx;

	if (!ip_pool)
		return 0;

	/* fast-path */
	idx = ip_pool->next_lease_idx;
	if (!ip_pool->lease[idx])
		goto match;

	/* slow-path */
	for (idx = 10; idx < ntohl(~ip_pool->netmask)-10; idx++) {
		if (!ip_pool->lease[idx]) {
			goto match;
		}
	}

	return 0;

  match:
	ip_pool->lease[idx] = true;
	ip_pool->next_lease_idx = idx + 1;
	return htonl(ntohl(ip_pool->network) + idx);
}

int
gtp_ip_pool_put(gtp_apn_t *apn, uint32_t addr_ip)
{
	gtp_ip_pool_t *ip_pool = apn->ip_pool;
	int idx;

	if (!ip_pool)
		return 0;

	idx = ntohl(addr_ip & ~ip_pool->network);
	ip_pool->lease[idx] = false;
	ip_pool->next_lease_idx = idx;
	return 0;
}

/*
 *	PCO related
 */
static gtp_pco_t *
gtp_pco_alloc(void)
{
	gtp_pco_t *pco;

	PMALLOC(pco);
	if (!pco)
		return NULL;
	INIT_LIST_HEAD(&pco->ns);

	return pco;
}

static void
gtp_pco_destroy(gtp_pco_t *pco)
{
	gtp_ns_t *ns, *_ns;

	if (!pco)
		return;

	list_for_each_entry_safe(ns, _ns, &pco->ns, next) {
		list_head_del(&ns->next);
		FREE(ns);
	}

	FREE(pco);
}

/*
 *	HPLMN related
 */
gtp_plmn_t *
gtp_apn_hplmn_alloc(gtp_apn_t *apn, uint8_t *plmn)
{
	gtp_plmn_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	memcpy(new->plmn, plmn, GTP_PLMN_MAX_LEN);

	pthread_mutex_lock(&apn->mutex);
	list_add_tail(&new->next, &apn->hplmn);
	pthread_mutex_unlock(&apn->mutex);

	return new;
}

static void
__gtp_apn_hplmn_del(gtp_plmn_t *p)
{
	list_head_del(&p->next);
	FREE(p);
}

void
gtp_apn_hplmn_del(gtp_apn_t *apn, gtp_plmn_t *p)
{
	pthread_mutex_lock(&apn->mutex);
	__gtp_apn_hplmn_del(p);
	pthread_mutex_unlock(&apn->mutex);
}

void
gtp_apn_hplmn_destroy(gtp_apn_t *apn)
{
	list_head_t *l = &apn->hplmn;
	gtp_plmn_t *p, *_p;

	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry_safe(p, _p, l, next) {
		__gtp_apn_hplmn_del(p);
	}
	pthread_mutex_unlock(&apn->mutex);
}

static gtp_plmn_t *
__gtp_apn_hplmn_get(gtp_apn_t *apn, uint8_t *plmn)
{
	list_head_t *l = &apn->hplmn;
	gtp_plmn_t *p;

	list_for_each_entry(p, l, next) {
		if (!bcd_plmn_cmp(p->plmn, plmn)) {
			return p;
		}
	}

	return NULL;
}

gtp_plmn_t *
gtp_apn_hplmn_get(gtp_apn_t *apn, uint8_t *plmn)
{
	gtp_plmn_t *p;

	pthread_mutex_lock(&apn->mutex);
	p = __gtp_apn_hplmn_get(apn, plmn);
	pthread_mutex_unlock(&apn->mutex);

	return p;
}


/*
 *	APN related
 */
gtp_apn_t *
gtp_apn_alloc(const char *name)
{
	gtp_apn_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->naptr);
	INIT_LIST_HEAD(&new->service_selection);
	INIT_LIST_HEAD(&new->imsi_match);
	INIT_LIST_HEAD(&new->oi_match);
	INIT_LIST_HEAD(&new->hplmn);
	INIT_LIST_HEAD(&new->next);
        pthread_mutex_init(&new->mutex, NULL);
	bsd_strlcpy(new->name, name, GTP_APN_MAX_LEN - 1);

	/* FIXME: lookup before insert */
	list_add_tail(&new->next, &daemon_data->gtp_apn);

	/* Point default pGW to list head */

	return new;
}

gtp_pco_t *
gtp_apn_pco(gtp_apn_t *apn)
{
	if (apn->pco)
		return apn->pco;
	apn->pco = gtp_pco_alloc();

	return apn->pco;
}

int
gtp_apn_destroy(void)
{
	list_head_t *l = &daemon_data->gtp_apn;
	gtp_apn_t *apn, *_apn;

	list_for_each_entry_safe(apn, _apn, l, next) {
		gtp_service_destroy(apn);
		gtp_rewrite_rule_destroy(apn, &apn->imsi_match);
		gtp_rewrite_rule_destroy(apn, &apn->oi_match);
		gtp_ip_pool_destroy(apn->ip_pool);
		gtp_pco_destroy(apn->pco);
		apn_resolv_cache_destroy(apn);
		gtp_apn_hplmn_destroy(apn);
		list_head_del(&apn->next);
		FREE(apn);
	}

	return 0;
}

gtp_apn_t *
gtp_apn_get(const char *name)
{
	gtp_apn_t *apn;

	list_for_each_entry(apn, &daemon_data->gtp_apn, next) {
		if (!fnmatch(apn->name, name, 0))
			return apn;

	}

	return NULL;
}

int
gtp_apn_cdr_commit(gtp_apn_t *apn, gtp_cdr_t *cdr)
{
	if (!cdr)
		return -1;

	if (!apn->cdr_spool) {
		gtp_cdr_destroy(cdr);
		return -1;
	}

	return gtp_cdr_spool_q_add(apn->cdr_spool, cdr);
}


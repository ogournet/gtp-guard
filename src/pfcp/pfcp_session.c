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

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "pfcp_session.h"
#include "pfcp_router.h"
#include "pfcp_bpf.h"
#include "gtp_cpu.h"
#include "gtp_cpu_sched.h"
#include "utils.h"
#include "bitops.h"
#include "logger.h"
#include "jhash.h"
#include "cpu.h"

/* Extern data */
extern struct thread_master *master;

/* Local data */
static struct hlist_head *pfcp_session_tab;
static int pfcp_sessions_count;
static int *pfcp_sessions_per_cpu;
static int pfcp_sessions_nr_cpus;

/* Local func */
static void pfcp_session_expire(struct thread *t);


/*
 *	PFCP Session hash handling
 */
static struct hlist_head *
pfcp_session_hashkey(struct hlist_head *h, uint64_t id)
{
	return h + (jhash_2words((uint32_t)id, (uint32_t) (id >> 32), 0) & PFCP_SESSION_HASHTAB_MASK);
}

static struct pfcp_session *
_pfcp_session_get(struct hlist_head *h, uint64_t id)
{
	struct hlist_head *head = pfcp_session_hashkey(h, id);
	struct pfcp_session *s;

	hlist_for_each_entry(s, head, hlist) {
		if (s->seid == id)
			return s;
	}

	return NULL;
}

struct pfcp_session *
pfcp_session_get(uint64_t id)
{
	return _pfcp_session_get(pfcp_session_tab, id);
}

static int
_pfcp_session_hash(struct hlist_head *h, struct pfcp_session *s)
{
	struct hlist_head *head = pfcp_session_hashkey(h, s->seid);

	if (__test_and_set_bit(PFCP_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): pfcp-session:0x%" PRIx64 " already hashed !!!"
				    , __FUNCTION__, s->seid);
		return -1;
	}

	hlist_add_head(&s->hlist, head);
	return 0;
}

static int
_pfcp_session_unhash(struct hlist_head *h, struct pfcp_session *s)
{
	if (!s)
		return -1;

	if (!__test_and_clear_bit(PFCP_SESSION_FL_HASHED, &s->flags)) {
		log_message(LOG_INFO, "%s(): pfcp-session:0x%" PRIx64 " already unhashed !!!"
				    , __FUNCTION__, s->seid);
		return -1;
	}
	hlist_del_init(&s->hlist);
	return 0;
}

int
pfcp_session_unhash(struct pfcp_session *s)
{
	return _pfcp_session_unhash(pfcp_session_tab, s);
}

int
pfcp_session_hash(struct pfcp_session *s)
{
	return _pfcp_session_hash(pfcp_session_tab, s);
}

/*
 *	PFCP UE handling
 */
struct pfcp_ue *
pfcp_ue_alloc(uint64_t imsi, uint64_t imei, uint64_t msisdn)
{
	struct pfcp_ue *ue;

	ue = calloc(1, sizeof (*ue));
	if (ue == NULL)
		return NULL;
	gtp_conn_init(&ue->c, imsi, imei, msisdn);
	INIT_LIST_HEAD(&ue->pfcp_sessions);
	return ue;
}


/*
 *	PFCP Sessions handling
 */
int
pfcp_sessions_count_read(void)
{
	return pfcp_sessions_count;
}

void
pfcp_session_mod_timer(struct pfcp_session *s, int timeout)
{
	if (!s->timer)
		s->timer = thread_add_timer(master, pfcp_session_expire, s,
					    (uint64_t) timeout * TIMER_HZ);
	else
		thread_mod_timer(s->timer, (uint64_t) timeout * TIMER_HZ);
}

static void
pfcp_session_add_timer(struct pfcp_session *s)
{
	struct gtp_apn *apn = s->apn;

	if (!apn->session_lifetime)
		return;

	/* Sort it by timeval */
	pfcp_session_mod_timer(s, apn->session_lifetime);
}

static uint64_t
pfcp_session_seid_alloc(struct pfcp_router *r)
{
	struct pfcp_session *s;
	uint64_t seid = 0;
	int retry = 0;

shoot_again:
	/* TODO: Do we really need random seid ? it avoid seid prediction
	 * but need proper security investigation to ensure if it is really
	 * needed. For now, asume random is best... */
	seid = xorshift_prng(&r->seed);
	s = pfcp_session_get(seid);
	if (!s)
		return seid;

	/* allocation active loop prevention */
	if (retry++ < 5)
		goto shoot_again;

	return 0;
}

struct pfcp_session *
pfcp_session_alloc(struct pfcp_ue *ue, struct gtp_apn *apn, struct pfcp_router *r)
{
	struct gtp_cpu_sched_group *grp;
	struct pfcp_session *s;
	uint64_t seid;

	s = calloc(1, sizeof (*s));
	if (!s) {
		errno = ENOMEM;
		return NULL;
	}
	INIT_LIST_HEAD(&s->next);
	INIT_LIST_HEAD(&s->pdr_list);
	INIT_LIST_HEAD(&s->far_list);
	INIT_LIST_HEAD(&s->qer_list);
	INIT_LIST_HEAD(&s->urr_list);
	INIT_LIST_HEAD(&s->te_list);
	INIT_LIST_HEAD(&s->urr_cmd_pending_list);
	s->apn = apn;
	s->ue = ue;
	s->router = r;
	time_now_to_calendar(&s->creation_time);
	seid = pfcp_session_seid_alloc(r);
	if (!seid) {
		log_message(LOG_INFO, "%s(): Something weird while allocating seid !!!"
				    , __FUNCTION__);
		free(s);
		return NULL;
	}
	s->seid = seid;

	/* APN override router sched if configured */
	grp = apn->cpu_sched ? : r->cpu_sched;
	s->cpu = gtp_cpu_sched_elect(grp);

	/* CDR context */
	if (apn->cdr_spool)
		s->cdr = gtp_cdr_alloc();

	list_add_tail(&s->next, &ue->pfcp_sessions);
	gtp_conn_refinc(&ue->c);
	__sync_add_and_fetch(&pfcp_sessions_count, 1);
	if (pfcp_sessions_per_cpu && s->cpu < pfcp_sessions_nr_cpus)
		__sync_add_and_fetch(&pfcp_sessions_per_cpu[s->cpu], 1);

	pfcp_session_hash(s);
	pfcp_session_add_timer(s);
	__sync_add_and_fetch(&apn->session_count, 1);

	/* Automatically start capture */
	if (ue->capture.flags) {
		char capname[200];
		s->data_cap = ue->capture;
		snprintf(capname, sizeof (capname), "%ld", ue->c.imsi);
		gtp_capture_start(&s->data_cap, r->bpf_prog, capname);

		/* on signaling path, we always want full packets and both path */
		memset(&s->sig_cap, 0x00, sizeof (s->sig_cap));
		s->sig_cap.flags = GTP_CAPTURE_FL_INPUT | GTP_CAPTURE_FL_OUTPUT;
		s->sig_cap.cap_len = ~0;
		gtp_capture_start(&s->sig_cap, s->router->bpf_prog, capname);
	}

	return s;
}

struct gtp_range_partition *
gtp_resolve_rp(struct gtp_apn *apn, struct pfcp_router *router, int type)
{
	if (apn->rp[type])
		return apn->rp[type];
	return pfcp_router_rp_get(router, type);
}

int
pfcp_session_alloc_ue_ip(struct pfcp_session *s, sa_family_t af)
{
	struct gtp_apn *apn = s->apn;
	struct gtp_cpu_sched_group *grp;
	struct gtp_range_partition *rp;
	struct gtp_range_part *part;
	struct ue_ip_address *ue_ip = &s->ue_ip;
	struct in_addr *v4 = &ue_ip->v4;
	struct in6_addr *v6 = &ue_ip->v6;
	struct gtp_apn_ip_pool *ap;
	struct ip_pool *p;
	int type, err;

	type = (af == AF_INET) ? GTP_RANGE_PARTITION_IPV4 : GTP_RANGE_PARTITION_IPV6;
	rp = gtp_resolve_rp(apn, s->router, type);
	if (rp) {
		grp = apn->cpu_sched ? : s->router->cpu_sched;
		part = gtp_cpu_sched_get_part(grp, rp, s->cpu);
		if (!part)
			goto nospc;
		p = part->ip_pool;
	} else {
		ap = gtp_apn_ip_pool_get_by_family(apn, af);
		if (!ap)
			goto nospc;
		p = ap->p->pool;
	}

	switch (af) {
	case AF_INET:
		err = ip_pool_get(p, v4);
		if (err)
			goto nospc;
		ue_ip->flags |= UE_CHV4|UE_IPV4;
		ue_ip->pool_v4 = p;
		break;

	case AF_INET6:
		err = ip_pool_get(p, v6);
		if (err)
			goto nospc;
		ue_ip->flags |= UE_CHV6|UE_IPV6;
		ue_ip->pool_v6 = p;
		break;

	default:
		goto nospc;
	}

	return 0;
nospc:
	errno = ENOSPC;
	return -1;
}

void
pfcp_session_release(struct pfcp_session *s)
{
	if (s->data_cap.entry_id)
		gtp_capture_stop(&s->data_cap);
	if (s->sig_cap.entry_id)
		gtp_capture_stop(&s->sig_cap);

	if (pfcp_sessions_per_cpu && s->cpu < pfcp_sessions_nr_cpus)
		__sync_sub_and_fetch(&pfcp_sessions_per_cpu[s->cpu], 1);
	thread_del(s->timer);
	__sync_sub_and_fetch(&s->apn->session_count, 1);
	gtp_apn_cdr_commit(s->apn, s->cdr);
	pfcp_session_delete(s);
	pfcp_session_unhash(s);
	pfcp_session_release_ue_ip(s);
	pfcp_session_release_teid(s);

	list_del(&s->next);
	gtp_conn_refdec(&s->ue->c);
	__sync_sub_and_fetch(&pfcp_sessions_count, 1);

	free(s);
}


/*
 *	Session expiration handling
 */
static void
pfcp_session_expire(struct thread *t)
{
	struct pfcp_session *s = THREAD_ARG(t);

	log_message(LOG_INFO, "IMSI:%ld - Expiring pfcp-session-id:0x%" PRIx64 ""
			    , s->ue->c.imsi, s->seid);
	pfcp_session_release(s);
}

void
pfcp_session_ue_release(struct pfcp_ue *ue)
{
	struct pfcp_session *s, *_s;

	list_for_each_entry_safe(s, _s, &ue->pfcp_sessions, next)
		pfcp_session_release(s);
}


/*
 *	PFCP Sessions.
 */
int
pfcp_sessions_cpu_count(int cpu)
{
	if (!pfcp_sessions_per_cpu || cpu < 0 || cpu >= pfcp_sessions_nr_cpus)
		return 0;
	return pfcp_sessions_per_cpu[cpu];
}

int
pfcp_sessions_init(void)
{
	pfcp_sessions_nr_cpus = cpu_nr_possible();
	if (pfcp_sessions_nr_cpus > 0)
		pfcp_sessions_per_cpu = calloc(pfcp_sessions_nr_cpus, sizeof(int));
	pfcp_session_tab = calloc(PFCP_SESSION_HASHTAB_SIZE, sizeof(struct hlist_head));
	gtp_cpu_register_pfcp_count(pfcp_sessions_cpu_count);
	return 0;
}

int
pfcp_sessions_destroy(void)
{
	struct hlist_node *n;
	struct pfcp_session *s;
	int i;

	for (i = 0; i < PFCP_SESSION_HASHTAB_SIZE; i++) {
		hlist_for_each_entry_safe(s, n, &pfcp_session_tab[i], hlist) {
			pfcp_session_release(s);
		}
	}

	free(pfcp_session_tab);
	free(pfcp_sessions_per_cpu);
	pfcp_sessions_per_cpu = NULL;
	return 0;
}

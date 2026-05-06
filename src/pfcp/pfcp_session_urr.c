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
 * Copyright (C) 2026 Alexandre Cassen, <acassen@gmail.com>
 */

#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include "utils.h"
#include "mempool.h"
#include "pfcp_ie.h"
#include "pfcp_session.h"
#include "pfcp_router.h"
#include "pfcp_bpf.h"
#include "pfcp_msg.h"
#include "inet_server.h"



int
urrs_find_by_urr_id(const struct urrs *us, uint32_t urr_id)
{
	int i;

	for (i = 0; i < us->n; i++)
		if (us->u[i].urr_id == urr_id)
			return i;
	return -1;
}

int
urrs_grow(struct urrs *us, int new_msize)
{
	if (!us->msize) {
		mpool_init(&us->mp);
		if (new_msize < 30)
			new_msize = next_power_of_2(new_msize + 1);
	}
	if (new_msize <= us->msize)
		return 0;

	if (mpool_prealloc(&us->mp, new_msize *
			   (sizeof(struct urr) +
			    sizeof(struct urr_volume) * 3 +
			    sizeof(struct urr_time))) < 0)
		return -1;

	/* zrealloc doesn't need to be checked, memory is pre-allocated */
	us->u = mpool_realloc(&us->mp, us->u,
			      new_msize * sizeof(struct urr));
	us->vol_threshold = mpool_zrealloc(&us->mp, us->vol_threshold,
					   new_msize * sizeof(struct urr_volume));
	us->vol_next = mpool_zrealloc(&us->mp, us->vol_next,
				      new_msize * sizeof(struct urr_volume));
	us->vol_quota = mpool_zrealloc(&us->mp, us->vol_quota,
				       new_msize * sizeof(struct urr_volume));
	us->time = mpool_zrealloc(&us->mp, us->time,
				  new_msize * sizeof(struct urr_time));
	us->msize = new_msize;

	return 0;
}



/********************************************************************/
/* merging urrs to upf_ttc */

static void
urrs_merge_flags(const struct urrs *us, struct upf_ttc_cmd *tc)
{
	union pfcp_measurement_method mm;
	int i;

	tc->flags &= ~(UPF_FL_MEAS_VOL | UPF_FL_MEAS_TIME |
		       UPF_FL_QUOTA_EXPLICIT_BLOCK);
	for (i = 0; i < us->n; i++) {
		mm = us->u[i].measurement_method;
		tc->flags |= (mm.volum ? UPF_FL_MEAS_VOL : 0) |
			(mm.durat ? UPF_FL_MEAS_TIME : 0) |
			(us->u[i].quota_blocked ? UPF_FL_QUOTA_EXPLICIT_BLOCK : 0);
		us->u[i].ttc_idx = tc->ttc_idx;
	}
}

/* group close thresholds to reduce status report generation */
static inline uint64_t
_merge_th(uint64_t cur, uint64_t val, int pct)
{
	if (!cur)
		return val;
	if (!pct)
		return min(cur, val);
	if (val <= cur)
		return (cur - val) * 100 / cur <= (uint64_t)pct
			? cur : val;
	return (val - cur) * 100 / val <= (uint64_t)pct
		? val : cur;
}

static void
urrs_merge_volume_threshold(const struct urrs *us,
			    struct upf_ttc_cmd *tc, int pct)
{
	int i;

	tc->total_th = 0;
	tc->ul_th = 0;
	tc->dl_th = 0;

	for (i = 0; i < us->n; i++) {
		if (!us->u[i].measurement_method.volum || !us->u[i].triggers.volth)
			continue;

		if (us->vol_threshold[i].to)
			tc->total_th = _merge_th(tc->total_th,
						 us->vol_threshold[i].to, pct);
		if (us->vol_threshold[i].ul)
			tc->ul_th = _merge_th(tc->ul_th,
					      us->vol_threshold[i].ul, pct);
		if (us->vol_threshold[i].dl)
			tc->dl_th = _merge_th(tc->dl_th,
					      us->vol_threshold[i].dl, pct);
	}
}

static void
urrs_merge_volume_quota(const struct urrs *us, struct upf_ttc_cmd *tc)
{
	int i;

	tc->total_qu = 0;
	tc->ul_qu = 0;
	tc->dl_qu = 0;

	for (i = 0; i < us->n; i++) {
		if (!us->u[i].measurement_method.volum || !us->u[i].triggers.volqu)
			continue;

		if (us->vol_quota[i].to)
			tc->total_qu = !tc->total_qu ? us->vol_quota[i].to
				: min(tc->total_qu, us->vol_quota[i].to);
		if (us->vol_quota[i].ul)
			tc->ul_qu = !tc->ul_qu ? us->vol_quota[i].ul
				: min(tc->ul_qu, us->vol_quota[i].ul);
		if (us->vol_quota[i].dl)
			tc->dl_qu = !tc->dl_qu ? us->vol_quota[i].dl
				: min(tc->dl_qu, us->vol_quota[i].dl);
	}
}

static void
urrs_merge_time(const struct urrs *us, struct upf_ttc_cmd *tc)
{
	union pfcp_measurement_method mm;
	union pfcp_reporting_triggers tr;
	struct urr_time *ut;
	int i;

	tc->time_th = 0;
	tc->time_qu = 0;
	tc->time_periodic = 0;
	tc->time_inactivity = 0;
	tc->inactivity_det_time = 0;

	for (i = 0; i < us->n; i++) {
		mm = us->u[i].measurement_method;
		tr = us->u[i].triggers;
		ut = &us->time[i];

		if (mm.durat && tr.timth && ut->threshold)
			tc->time_th = min(tc->time_th ?: ~0U, ut->threshold);
		if (mm.durat && tr.timqu && ut->quota)
			tc->time_qu = min(tc->time_qu ?: ~0U, ut->quota);
		if (mm.durat && ut->inactivity_detection)
			tc->inactivity_det_time =
				min(tc->inactivity_det_time ?: ~0U,
				    ut->inactivity_detection);
		if (tr.perio && ut->periodic)
			tc->time_periodic = min(tc->time_periodic ?: ~0U,
						ut->periodic);
		if (tr.quhti && ut->quota_holdtime)
			tc->time_inactivity = min(tc->time_inactivity ?: ~0U,
						  ut->quota_holdtime);
	}
}

static void
urrs_build_linked_by(struct urrs *us)
{
	int i, k, target;
	struct urr *u;

	for (i = 0; i < us->n; i++)
		us->u[i].linked_by = 0;

	for (i = 0; i < us->n; i++) {
		u = &us->u[i];
		for (k = 0; k < u->linked_urr_n; k++) {
			target = urrs_find_by_urr_id(us, u->linked_urr_id[k]);
			if (target >= 0)
				us->u[target].linked_by |= (1U << i);
		}
	}
}


/********************************************************************/
/* generate a report */

struct urr_report {
	int id;
	union pfcp_usage_report_trigger	rtrig;
};

static int
_report_add(struct urr_report *r, int n, int idx,
	    union pfcp_usage_report_trigger rtrig)
{
	int i;

	for (i = 0; i < n; i++) {
		if (r[i].id == idx) {
			r[i].rtrig.trigger_flags |= rtrig.trigger_flags;
			return 0;
		}
	}
	r[n].id = idx;
	r[n].rtrig = rtrig;
	return 1;
}

/* generate a status report, to be sent immediately.
 * do remember current counter position, next status report will be build from
 * these values */
static int
_report_build_ies(struct urrs *us, int idx, struct pkt_buffer *pbuff,
		  int type, union pfcp_usage_report_trigger rtrig,
		  uint32_t qurr_ref)
{
	struct pfcp_metrics_pkt ul, dl;
	struct urr *u = &us->u[idx];
	bool vol = us->u[idx].measurement_method.volum;
	int duration = -1;

	u->start_time = u->end_time;
	u->end_time = time_now_to_ntp();

	if (vol) {
		pfcp_metrics_pkt_sub(&u->ul, &u->last_report_ul, &ul);
		pfcp_metrics_pkt_sub(&u->dl, &u->last_report_dl, &dl);
		u->last_report_ul = u->ul;
		u->last_report_dl = u->dl;
	}

	if (us->u[idx].measurement_method.durat) {
		duration = u->duration - u->last_report_duration;
		u->last_report_duration = u->duration;
	}

	return pfcp_ie_put_usage_report(pbuff, type, u->urr_id, u->seqn++,
					rtrig, qurr_ref,
					u->pkt_first_time, u->pkt_last_time,
					u->start_time, u->end_time, duration,
					vol ? &ul : NULL, vol ? &dl : NULL);
}

/* build and send a triggered report */
static void
urrs_build_and_send_report(struct pfcp_session *s, struct urrs *us,
			   struct urr_report *r, int n)
{
	struct pfcp_server *srv = &s->router->s;
	struct f_seid *remote_seid = &s->remote_seid;
	struct pkt *p;
	struct pkt_buffer *pbuff;
	int err, i;

	p = __pkt_queue_get(&srv->pkt_q);
	if (p == NULL) {
		logfc_err(s->log, "Error getting pkt from queue");
		return;
	}

	pbuff = p->pbuff;
	pfcp_msg_header_init(pbuff, PFCP_SESSION_REPORT_REQUEST,
			     remote_seid->id,
			     htonl(++srv->seqn << 8));
	err = pfcp_ie_put_report_type(pbuff,
				      PFCP_IE_REPORT_TYPE_USAR);

	for (i = 0; !err && i < n; i++)
		err = _report_build_ies(us, r[i].id, pbuff, PFCP_IE_USAGE_REPORT,
					r[i].rtrig, 0);

	if (err) {
		logfc_err(s->log, "Error building report pkt");
		goto end;
	}

	gtp_capture_data(&s->sig_cap, pbuff->head,
			 pkt_buffer_len(pbuff),
			 &s->remote_seid.addr,
			 (const sockaddr_t *)&s->router->s.s.addr,
			 GTP_CAPTURE_FL_OUTPUT);

	inet_server_snd(&srv->s, srv->s.fd, pbuff,
			&s->remote_seid.addr);
end:
	__pkt_queue_put(&srv->pkt_q, p);
}

int
urrs_put_modification_reports(struct urrs *us, struct pkt_buffer *pbuff)
{
	const union pfcp_usage_report_trigger immer = { .immer = 1 };
	const union pfcp_usage_report_trigger liusa = {	.immer = 1, .liusa = 1 };
	struct urr_report r[us->n];
	struct urr *lu;
	uint32_t linked;
	int i, n = 0, err;

	/* collect queried URRs + their linked URRs */
	for (i = 0; i < us->n; i++) {
		if (!us->u[i].queried)
			continue;

		n += _report_add(r, n, i, immer);

		linked = us->u[i].linked_by;
		while (linked) {
			lu = &us->u[__builtin_ctz(linked)];
			linked &= linked - 1;

			/* skip linked URRs with null measurements */
			if (pfcp_metrics_pkt_is_null(&lu->ul) &&
			    pfcp_metrics_pkt_is_null(&lu->dl) &&
			    lu->duration <= 0)
				continue;

			n += _report_add(r, n, lu->id, liusa);
		}
	}

	/* build IEs */
	for (i = 0; i < n; i++) {
		err = _report_build_ies(us, r[i].id, pbuff,
					PFCP_IE_USAGE_REPORT_MODIFICATION,
					r[i].rtrig, us->query_ref);
		if (err)
			return -1;
	}

	/* reset query state */
	for (i = 0; i < us->n; i++)
		us->u[i].queried = false;

	return 0;
}

int
urrs_put_deletion_reports(struct urrs *us, struct pkt_buffer *pbuff)
{
	const union pfcp_usage_report_trigger rtrig = {	.immer = 1, .termr = 1 };
	int i, err;

	for (i = 0; i < us->n; i++) {
		err = _report_build_ies(us, i, pbuff, PFCP_IE_USAGE_REPORT_DELETION,
					rtrig, 0);
		if (err)
			return -1;
	}

	return 0;
}


/********************************************************************/
/* callback from BPF -> userspace */

/* update counters from BPF */
int
urrs_report_ingest(struct urrs *us, const struct upf_ttc_report_data *rd,
		   uint32_t mono2ntptime_off)
{
	int i;

	for (i = 0; i < us->n; i++) {
		struct urr *u = &us->u[i];

		if (u->ttc_idx != rd->r.ttc_idx)
			continue;

		u->pkt_first_time = rd->report_first_pkt
			? rd->report_first_pkt + mono2ntptime_off : 0;
		u->pkt_last_time = rd->report_last_pkt
			? rd->report_last_pkt + mono2ntptime_off : 0;

		if (us->u[i].measurement_method.volum) {
			u->ul.bytes = rd->ul_bytes;
			u->ul.count = rd->ul_pkt;
			u->dl.bytes = rd->dl_bytes;
			u->dl.count = rd->dl_pkt;
		}

		if (us->u[i].measurement_method.durat)
			u->duration = rd->duration;
	}

	return 0;
}

static bool
_check_volume_th(const struct urrs *us, int i)
{
	const struct urr *u = &us->u[i];

	if (us->vol_threshold[i].to &&
	    u->ul.bytes - u->last_report_ul.bytes +
	    u->dl.bytes - u->last_report_dl.bytes >= us->vol_threshold[i].to)
		return true;
	if (us->vol_threshold[i].dl &&
	    u->dl.bytes - u->last_report_dl.bytes >= us->vol_threshold[i].dl)
		return true;
	if (us->vol_threshold[i].ul &&
	    u->ul.bytes - u->last_report_ul.bytes >= us->vol_threshold[i].ul)
		return true;
	return false;
}

static union pfcp_usage_report_trigger
_report_has_trigged(const struct urrs *us, int slot,
		    uint16_t report_flags)
{
	union pfcp_usage_report_trigger rtrig = {};

	if ((report_flags & UPF_TRIG_FL_VOLTH) && us->u[slot].triggers.volth &&
	    _check_volume_th(us, slot))
		rtrig.volth = 1;
	if ((report_flags & UPF_TRIG_FL_VOLQU) && us->u[slot].triggers.volqu)
		rtrig.volqu = 1;
	if ((report_flags & UPF_TRIG_FL_TIMTH) && us->u[slot].triggers.timth)
		rtrig.timth = 1;
	if ((report_flags & UPF_TRIG_FL_TIMQU) && us->u[slot].triggers.timqu)
		rtrig.timqu = 1;
	if ((report_flags & UPF_TRIG_FL_PERIO) && us->u[slot].triggers.perio)
		rtrig.perio = 1;
	if ((report_flags & UPF_TRIG_FL_QUHTI) && us->u[slot].triggers.quhti)
		rtrig.quhti = 1;

	return rtrig;
}

/* advance volth_next for URRs that triggered: next = next + th.
 * then find the smallest delta to the nearest next trigger point
 * across all URRs sharing this TTC. */
static void
_recalc_thresholds(struct pfcp_session *s,
		   const struct upf_ttc_report_data *urd)
{
	struct urrs *us = &s->urrs;
	struct upf_ttc_cmd *tc = &us->ttc[0];
	uint64_t total, delta;
	uint64_t prev_to = tc->total_th;
	uint64_t prev_ul = tc->ul_th;
	uint64_t prev_dl = tc->dl_th;
	int i;

	total = urd->ul_bytes + urd->dl_bytes;

	tc->total_th = 0;
	tc->ul_th = 0;
	tc->dl_th = 0;
	for (i = 0; i < us->n; i++) {
		if (us->u[i].ttc_idx != urd->r.ttc_idx)
			continue;

		/* advance URRs whose next trigger point was reached */
		while (us->vol_next[i].to && us->vol_next[i].to <= total)
			us->vol_next[i].to += us->vol_threshold[i].to;
		while (us->vol_next[i].ul && us->vol_next[i].ul <= urd->ul_bytes)
			us->vol_next[i].ul += us->vol_threshold[i].ul;
		while (us->vol_next[i].dl && us->vol_next[i].dl <= urd->dl_bytes)
			us->vol_next[i].dl += us->vol_threshold[i].dl;

		if (us->vol_next[i].to) {
			delta = us->vol_next[i].to - total;
			tc->total_th = !tc->total_th ? delta : min(tc->total_th, delta);
		}
		if (us->vol_next[i].ul) {
			delta = us->vol_next[i].ul - urd->ul_bytes;
			tc->ul_th = !tc->ul_th ? delta : min(tc->ul_th, delta);
		}
		if (us->vol_next[i].dl) {
			delta = us->vol_next[i].dl - urd->dl_bytes;
			tc->dl_th = !tc->dl_th ? delta : min(tc->dl_th, delta);
		}
	}

	/* update next threshold if changed.
	 * allow small delta, threshold can go over by packet size */
	if (!(prev_to - tc->total_th <= 1500 &&
	      prev_ul - tc->ul_th <= 1500 &&
	      prev_dl - tc->dl_th <= 1500)) {
		tc->cmd = UPF_TTC_CMD_UPDATE;
		pfcp_bpf_ttc_ctl(s, tc);
	}
}

void
urrs_report_triggered(struct pfcp_session *s,
		      const struct upf_ttc_report_data *urd)
{
	const union pfcp_usage_report_trigger liusa = { .liusa = 1 };
	union pfcp_usage_report_trigger rtrig;
	struct urrs *us = &s->urrs;
	struct urr_report r[us->n];
	uint32_t linked;
	int i, n = 0;

	if (!us->n)
		return;

	/* collect triggering URRs that match this ttc_idx */
	for (i = 0; i < us->n; i++) {
		if (us->u[i].ttc_idx != urd->r.ttc_idx)
			continue;

		rtrig = _report_has_trigged(us, i, urd->r.report_flags);
		if (!rtrig.trigger_flags)
			continue;

		n += _report_add(r, n, i, rtrig);

		/* add URRs that link to us via bitmap */
		linked = us->u[i].linked_by;
		while (linked) {
			n += _report_add(r, n, __builtin_ctz(linked), liusa);
			linked &= linked - 1;
		}
	}

	if (!n)
		return;

	/* adjust BPF thresholds for next trigger */
	if (urd->r.report_flags & UPF_TRIG_FL_VOLTH)
		_recalc_thresholds(s, urd);

	urrs_build_and_send_report(s, us, r, n);
}



/********************************************************************/
/* parse urr IEs helpers */


#define URR_CHG_NONE			0
#define URR_CHG_VOLUME_THRESHOLD	(1 << 0)
#define URR_CHG_VOLUME_QUOTA		(1 << 1)
#define URR_CHG_TIME_THRESHOLD		(1 << 2)
#define URR_CHG_TIME_QUOTA		(1 << 3)
#define URR_CHG_TIME_PERIODIC		(1 << 4)
#define URR_CHG_TRIGGERS		(1 << 5)
#define URR_CHG_MEASUREMENT_METHOD	(1 << 6)
#define URR_CHG_INACTIVITY		(1 << 7)
#define URR_CHG_QUOTA_HOLDTIME		(1 << 8)


/* work around variable-length IE */
static void
_parse_volume_optfield(uint8_t tovol, uint8_t ulvol, uint8_t dlvol,
		       uint64_t ie_total, uint64_t ie_uplink, uint64_t ie_downlink,
		       uint64_t *out_to, uint64_t *out_ul, uint64_t *out_dl)
{
	*out_to = 0;
	*out_ul = 0;
	*out_dl = 0;

	if (tovol)
		*out_to = be64toh(ie_total);
	if (ulvol) {
		if (tovol)
			*out_ul = be64toh(ie_uplink);
		else
			*out_ul = be64toh(ie_total);
	}
	if (dlvol) {
		if (tovol && ulvol)
			*out_dl = be64toh(ie_downlink);
		else if (tovol ^ ulvol)
			*out_dl = be64toh(ie_uplink);
		else
			*out_dl = be64toh(ie_total);
	}
}

static void
_parse_volume_threshold(const struct pfcp_ie_volume_threshold *vth,
			uint64_t *out_to, uint64_t *out_ul, uint64_t *out_dl)
{
	_parse_volume_optfield(vth->tovol, vth->ulvol, vth->dlvol,
			       vth->total_volume, vth->uplink_volume,
			       vth->downlink_volume, out_to, out_ul, out_dl);
}

static void
_parse_volume_quota(const struct pfcp_ie_volume_quota *vqu,
		    uint64_t *out_to, uint64_t *out_ul, uint64_t *out_dl)
{
	_parse_volume_optfield(vqu->tovol, vqu->ulvol, vqu->dlvol,
			       vqu->total_volume, vqu->uplink_volume,
			       vqu->downlink_volume, out_to, out_ul, out_dl);
}

static int
urrs_create(struct urrs *us, struct pfcp_ie_create_urr *ie,
	    const int *static_pdr_link, int nr_static_pdr_link)
{
	int idx = us->n;
	struct urr *u = &us->u[idx];
	int i;

	memset(u, 0, sizeof(*u));
	u->id = idx;
	u->urr_id = ntohl(ie->urr_id->value);
	u->action = PFCP_ACT_CREATE;
	u->start_time = time_now_to_ntp();
	u->end_time = u->start_time;

	us->u[idx].measurement_method = ie->measurement_method->v;
	if (!us->u[idx].measurement_method.durat)
		u->duration = -1;

	us->u[idx].triggers = ie->reporting_triggers->v;

	if (ie->measurement_information)
		us->u[idx].measurement_info = ie->measurement_information->v;

	if (ie->inactivity_detection_time)
		us->time[idx].inactivity_detection =
			ntohl(ie->inactivity_detection_time->value);

	if (ie->quota_holding_time)
		us->time[idx].quota_holdtime =
			ntohl(ie->quota_holding_time->value);

	if (ie->volume_threshold) {
		_parse_volume_threshold(ie->volume_threshold,
					&us->vol_threshold[idx].to,
					&us->vol_threshold[idx].ul,
					&us->vol_threshold[idx].dl);
		us->vol_next[idx] = us->vol_threshold[idx];
	}

	if (ie->volume_quota) {
		_parse_volume_quota(ie->volume_quota,
				    &us->vol_quota[idx].to,
				    &us->vol_quota[idx].ul,
				    &us->vol_quota[idx].dl);
		if (!us->vol_quota[idx].to &&
		    !us->vol_quota[idx].ul &&
		    !us->vol_quota[idx].dl)
			u->quota_blocked = true;
		else if (!u->triggers.volth)
			u->triggers.volqu = 1;
	}

	if (ie->time_threshold)
		us->time[idx].threshold =
			ntohl(ie->time_threshold->time_threshold);

	if (ie->time_quota) {
		us->time[idx].quota = ntohl(ie->time_quota->value);
		if (!u->triggers.timqu && !u->triggers.timth)
			u->triggers.timqu = 1;
	}

	if (ie->measurement_period)
		us->time[idx].periodic =
			ntohl(ie->measurement_period->measurement_period);

	if (ie->nr_linked_urr_id) {
		u->linked_urr_n = ie->nr_linked_urr_id;
		u->linked_urr_id = mpool_zalloc(&us->mp,
				u->linked_urr_n * sizeof(uint32_t));
		for (i = 0; i < u->linked_urr_n; i++)
			u->linked_urr_id[i] =
				ntohl(ie->linked_urr_id[i]->value);
	}

	for (i = 0; i < nr_static_pdr_link; i++)
		if (static_pdr_link[i] == (int) u->urr_id)
			u->auto_attach = true;

	++us->n;

	return idx;
}

static int
urrs_update(struct urrs *us, struct pfcp_ie_update_urr *ie)
{
	uint64_t v, to, ul, dl;
	uint32_t changed = URR_CHG_NONE;
	struct urr *u;
	int idx, i;

	idx = urrs_find_by_urr_id(us, ntohl(ie->urr_id->value));
	if (idx < 0)
		return -1;

	if (ie->measurement_method) {
		us->u[idx].measurement_method = ie->measurement_method->v;
		changed |= URR_CHG_MEASUREMENT_METHOD;
	}

	if (ie->reporting_triggers) {
		us->u[idx].triggers = ie->reporting_triggers->v;
		changed |= URR_CHG_TRIGGERS;
	}

	if (ie->measurement_information)
		us->u[idx].measurement_info = ie->measurement_information->v;

	if (ie->inactivity_detection_time) {
		us->time[idx].inactivity_detection =
			ntohl(ie->inactivity_detection_time->value);
		changed |= URR_CHG_INACTIVITY;
	}

	if (ie->quota_holding_time) {
		us->time[idx].quota_holdtime =
			ntohl(ie->quota_holding_time->value);
		changed |= URR_CHG_QUOTA_HOLDTIME;
	}

	if (ie->volume_threshold) {
		_parse_volume_threshold(ie->volume_threshold, &to, &ul, &dl);
		if (us->vol_threshold[idx].to != to ||
		    us->vol_threshold[idx].ul != ul ||
		    us->vol_threshold[idx].dl != dl) {
			us->vol_threshold[idx].to = to;
			us->vol_threshold[idx].ul = ul;
			us->vol_threshold[idx].dl = dl;
			changed |= URR_CHG_VOLUME_THRESHOLD;
		}
	}

	if (ie->volume_quota) {
		_parse_volume_quota(ie->volume_quota, &to, &ul, &dl);
		if (us->vol_quota[idx].to != to ||
		    us->vol_quota[idx].ul != ul ||
		    us->vol_quota[idx].dl != dl) {
			us->vol_quota[idx].to = to;
			us->vol_quota[idx].ul = ul;
			us->vol_quota[idx].dl = dl;
			changed |= URR_CHG_VOLUME_QUOTA;
		}
		if ((!to && !ul && !dl) ^ !!us->u[idx].quota_blocked) {
			us->u[idx].quota_blocked = !to && !ul && !dl;
			changed |= URR_CHG_VOLUME_QUOTA;
		}
		if (!us->u[idx].triggers.volth)
			us->u[idx].triggers.volqu = 1;
	}

	if (ie->time_threshold) {
		v = ntohl(ie->time_threshold->time_threshold);
		if (us->time[idx].threshold != v) {
			us->time[idx].threshold = v;
			changed |= URR_CHG_TIME_THRESHOLD;
		}
	}

	if (ie->time_quota) {
		v = ntohl(ie->time_quota->value);
		if (us->time[idx].quota != v) {
			us->time[idx].quota = v;
			changed |= URR_CHG_TIME_QUOTA;
		}
		if (!us->u[idx].triggers.timqu &&
		    !us->u[idx].triggers.timth)
			us->u[idx].triggers.timqu = 1;
	}

	if (ie->measurement_period) {
		v = ntohl(ie->measurement_period->measurement_period);
		if (us->time[idx].periodic != v) {
			us->time[idx].periodic = v;
			changed |= URR_CHG_TIME_PERIODIC;
		}
	}

	if (ie->linked_urr_id) {
		u = &us->u[idx];
		u->linked_urr_n = ie->nr_linked_urr_id;
		u->linked_urr_id =
			mpool_zalloc(&us->mp, u->linked_urr_n * sizeof(uint32_t));
		for (i = 0; i < u->linked_urr_n; i++)
			u->linked_urr_id[i] = ntohl(ie->linked_urr_id[i]->value);
	}

	if (changed)
		us->u[idx].action = PFCP_ACT_UPDATE;
	return changed;
}

/* warning: can change urr idx layout inside urrs */
static void
urrs_remove(struct urrs *us, uint32_t urr_id)
{
	int idx;

	idx = urrs_find_by_urr_id(us, urr_id);
	if (idx < 0)
		return;

	us->n--;
	if (idx == us->n)
		return;

	us->u[idx] = us->u[us->n];
	us->u[idx].id = idx;
	us->time[idx].inactivity_detection = us->time[us->n].inactivity_detection;
	us->time[idx].quota_holdtime = us->time[us->n].quota_holdtime;
	us->vol_threshold[idx] = us->vol_threshold[us->n];
	us->vol_next[idx] = us->vol_next[us->n];
	us->vol_quota[idx] = us->vol_quota[us->n];
	us->time[idx] = us->time[us->n];
}


/********************************************************************/
/* handle Session Establishement/Modification requests */


int
urrs_on_create(struct pfcp_session *s,
	       struct pfcp_session_establishment_request *req)
{
	struct pfcp_router *router = s->router;
	struct urrs *us = &s->urrs;
	struct upf_ttc_cmd *tc;
	uint32_t idx;
	int i;

	if (urrs_grow(us, req->nr_create_urr))
		return -1;

	for (i = 0; i < req->nr_create_urr; i++)
		urrs_create(us, req->create_urr[i],
			    router->urr_static_pdr_link,
			    ARRAY_SIZE(router->urr_static_pdr_link));

	if (!us->n)
		return 0;

	urrs_build_linked_by(us);

	/* allocate a single shared TTC for all URRs.
	 * future: per-SDF/application filter grouping */
	if (!us->ttc_n) {
		idx = pfcp_bpf_alloc_ttc_idx(s);
		if (!idx)
			return -1;
		us->ttc = mpool_zalloc(&us->mp,	sizeof(struct upf_ttc_cmd));
		us->ttc[0].seid = s->seid;
		us->ttc[0].ttc_idx = idx;
		us->ttc_n = 1;
		us->ttc_msize = 1;
	}

	tc = &us->ttc[0];
	tc->cmd = UPF_TTC_CMD_INIT;
	urrs_merge_flags(us, tc);
	urrs_merge_volume_threshold(us, tc, router->urr_merge_threshold_pct);
	urrs_merge_volume_quota(us, tc);
	urrs_merge_time(us, tc);
	pfcp_bpf_ttc_ctl(s, tc);

	return 0;
}

int
urrs_on_modify(struct pfcp_session *s,
	       struct pfcp_session_modification_request *req)
{
	struct pfcp_router *router = s->router;
	struct pfcp_ie_query_urr_reference *ie_urr_ref = req->query_urr_reference;
	struct urrs *us = &s->urrs;
	struct upf_ttc_cmd *tc;
	uint32_t changed = URR_CHG_NONE;
	int bpf_action = 0;
	bool query_all;
	int i;

	/* mark URRs for query */
	query_all = req->pfcpsmreq_flags && req->pfcpsmreq_flags->qaurr;
	for (i = 0; i < us->n; i++) {
		us->u[i].queried = query_all;
		if (!us->u[i].queried) {
			int q;
			for (q = 0; q < req->nr_query_urr; q++)
				if (us->u[i].urr_id == ntohl(req->query_urr[q]->urr_id->value))
					us->u[i].queried = true;
		}
		if (us->u[i].queried)
			bpf_action = UPF_TTC_CMD_REPORT;
	}

	us->query_ref = ie_urr_ref ? ie_urr_ref->value : 0;

	/* remove */
	for (i = 0; i < req->nr_remove_urr; i++)
		urrs_remove(us,
			    ntohl(req->remove_urr[i]->urr_id->value));

	/* create */
	if (req->nr_create_urr) {
		if (urrs_grow(us, us->n + req->nr_create_urr))
			return -1;
		for (i = 0; i < req->nr_create_urr; i++)
			urrs_create(us, req->create_urr[i],
				    router->urr_static_pdr_link,
				    ARRAY_SIZE(router->urr_static_pdr_link));
	}

	/* update */
	for (i = 0; i < req->nr_update_urr; i++) {
		int ret = urrs_update(us, req->update_urr[i]);
		if (ret > 0) {
			changed |= ret;
			bpf_action = UPF_TTC_CMD_UPDATE;
		}
	}

	/* rebuild linked_by bitmaps if URRs changed */
	if (req->nr_create_urr || req->nr_remove_urr || req->nr_update_urr)
		urrs_build_linked_by(us);

	if (!us->ttc_n)
		return 0;

	/* update cached TTC command, only re-merge changed fields */
	tc = &us->ttc[0];
	tc->cmd = bpf_action;
	if (bpf_action == UPF_TTC_CMD_UPDATE) {
		urrs_merge_flags(us, tc);
		if (changed & URR_CHG_VOLUME_THRESHOLD) {
			urrs_merge_volume_threshold(us, tc,
						    router->urr_merge_threshold_pct);
		}
		if (changed & URR_CHG_VOLUME_QUOTA)
			urrs_merge_volume_quota(us, tc);
		if (changed & (URR_CHG_TIME_THRESHOLD | URR_CHG_TIME_QUOTA |
			       URR_CHG_TIME_PERIODIC | URR_CHG_INACTIVITY |
			       URR_CHG_QUOTA_HOLDTIME))
			urrs_merge_time(us, tc);
	}
	pfcp_bpf_ttc_ctl(s, tc);

	return 0;
}

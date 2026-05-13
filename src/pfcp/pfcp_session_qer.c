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

#include <stdint.h>
#include <string.h>
#include "utils.h"
#include "mempool.h"
#include "pfcp_ie.h"
#include "pfcp_session.h"
#include "pfcp_bpf.h"
#include "pfcp_msg.h"


int
qers_find_by_qer_id(const struct qers *qs, uint32_t qer_id)
{
	int i;

	for (i = 0; i < qs->n; i++)
		if (qs->q[i].qer_id == qer_id)
			return i;
	return -1;
}

static inline int
qers_grow(struct pfcp_session *s, int new_msize)
{
	struct qers *qs = &s->qers;

	if (new_msize <= qs->msize)
		return 0;

	qs->q = mpool_zrealloc(&s->mp, qs->q,
			       new_msize * sizeof(struct qer));
	if (qs->q == NULL)
		return -1;
	qs->msize = new_msize;

	return 0;
}


/*
 * Token bucket rate conversion.
 *
 * MBR is in kbps. BPF time base is ns >> 24 (~16.7 ms resolution).
 * Tokens are stored as bytes << 8 (fractional precision).
 *
 * rate (bytes<<8 per ns>>24) = kbps * 125 * 256 * (1<<24) / 1e9
 *                            ≈ kbps * 537
 *
 * Burst in bytes: kbps * avg_window_ms / 8000, stored << 8.
 * Default averaging window: 1000 ms per 3GPP TS 29.244.
 */
static void
qers_update_bpf(struct pfcp_session *s, const struct qer *q,
		uint32_t bpf_idx, bool is_update)
{
	const uint64_t rate_factor = 537;
	const uint32_t default_avg_window = 1000;
	struct upf_mbr *qr;
	uint32_t avg_window;

	qr = pfcp_bpf_mbr_data(s, bpf_idx);
	if (qr == NULL)
		return;

	avg_window = q->averaging_window ?: default_avg_window;

	if (q->ul_mbr) {
		qr->tb_ul_rate = q->ul_mbr * rate_factor;
		qr->tb_ul_burst = (q->ul_mbr * avg_window / 8) << 8;
	}
	if (q->dl_mbr) {
		qr->tb_dl_rate = q->dl_mbr * rate_factor;
		qr->tb_dl_burst = (q->dl_mbr * avg_window / 8) << 8;
	}

	if (is_update) {
		/* preserve current tokens, cap to new burst */
		qr->tb_ul_tokens = min(qr->tb_ul_tokens, qr->tb_ul_burst);
		qr->tb_dl_tokens = min(qr->tb_dl_tokens, qr->tb_dl_burst);
	} else {
		qr->tb_ul_tokens = qr->tb_ul_burst;
		qr->tb_dl_tokens = qr->tb_dl_burst;
	}
}


/********************************************************************/
/* parse QER IEs */

static int
qers_create(struct qers *qs, struct pfcp_ie_create_qer *ie)
{
	int idx = qs->n;
	struct qer *q = &qs->q[idx];

	memset(q, 0, sizeof(*q));
	q->idx = idx;
	q->qer_id = ie->qer_id->value;

	if (ie->gate_status) {
		q->ul_gate = ie->gate_status->ul_gate;
		q->dl_gate = ie->gate_status->dl_gate;
	}

	if (ie->maximum_bitrate) {
		q->ul_mbr = ntohl(ie->maximum_bitrate->ul_mbr);
		q->dl_mbr = ntohl(ie->maximum_bitrate->dl_mbr);
	}

	if (ie->averaging_window)
		q->averaging_window = ntohl(ie->averaging_window->value);

	if (ie->qer_correlation_id)
		q->correlation_id =
			ntohl(ie->qer_correlation_id->qer_correlation_id);

	if (ie->qos_flow_identifier)
		q->qfi = ie->qos_flow_identifier->qfi;

	++qs->n;
	return idx;
}

static int
qers_update(struct qers *qs, struct pfcp_ie_update_qer *ie)
{
	struct qer *q;
	int idx;

	idx = qers_find_by_qer_id(qs, ie->qer_id->value);
	if (idx < 0)
		return 0;

	q = &qs->q[idx];

	if (ie->gate_status) {
		if (q->ul_gate != ie->gate_status->ul_gate ||
		    q->dl_gate != ie->gate_status->dl_gate)
			qs->action = PFCP_ACT_UPDATE;
		q->ul_gate = ie->gate_status->ul_gate;
		q->dl_gate = ie->gate_status->dl_gate;
	}

	if (ie->maximum_bitrate) {
		q->ul_mbr = ntohl(ie->maximum_bitrate->ul_mbr);
		q->dl_mbr = ntohl(ie->maximum_bitrate->dl_mbr);
		qs->action = PFCP_ACT_UPDATE;
	}

	if (ie->averaging_window) {
		q->averaging_window = ntohl(ie->averaging_window->value);
		qs->action = PFCP_ACT_UPDATE;
	}

	if (ie->qer_correlation_id)
		q->correlation_id =
			ntohl(ie->qer_correlation_id->qer_correlation_id);

	if (ie->qos_flow_identifier)
		q->qfi = ie->qos_flow_identifier->qfi;

	return 1;
}

static void
qers_remove(struct pfcp_session *s, uint32_t qer_id)
{
	struct qers *qs = &s->qers;
	int idx;

	idx = qers_find_by_qer_id(qs, qer_id);
	if (idx < 0)
		return;

	/* release BPF entry before overwriting */
	if (qs->q[idx].bpf_idx)
		pfcp_bpf_release_mbr_idx(s, qs->q[idx].bpf_idx);

	qs->n--;
	if (idx == qs->n)
		return;

	qs->q[idx] = qs->q[qs->n];
	qs->q[idx].idx = idx;
}


/********************************************************************/
/* handle Session Establishment/Modification requests */


static int
_qer_sync_bpf(struct pfcp_session *s, struct qer *q)
{
	if (!q->ul_mbr && !q->dl_mbr) {
		if (q->bpf_idx) {
			pfcp_bpf_release_mbr_idx(s, q->bpf_idx);
			q->bpf_idx = 0;
		}

	} else if (q->bpf_idx) {
		qers_update_bpf(s, q, q->bpf_idx, true);

	} else {
		q->bpf_idx = pfcp_bpf_alloc_mbr_idx(s);
		if (!q->bpf_idx)
			return -1;
		qers_update_bpf(s, q, q->bpf_idx, false);
	}

	return 0;
}

void
qers_release(struct pfcp_session *s)
{
	struct qers *qs = &s->qers;
	int i;

	for (i = 0; i < qs->n; i++) {
		if (qs->q[i].bpf_idx) {
			pfcp_bpf_release_mbr_idx(s, qs->q[i].bpf_idx);
			qs->q[i].bpf_idx = 0;
		}
	}
	if (qs->ambr_qer_bpf_idx) {
		pfcp_bpf_release_mbr_idx(s, qs->ambr_qer_bpf_idx);
		qs->ambr_qer_bpf_idx = 0;
	}
	qs->ambr_qer_idx = -1;
}


int
qers_on_create(struct pfcp_session *s,
	       struct pfcp_session_establishment_request *req)
{
	struct qers *qs = &s->qers;
	int i;

	if (qers_grow(s, req->nr_create_qer))
		return -1;
	for (i = 0; i < req->nr_create_qer; i++)
		qers_create(qs, req->create_qer[i]);

	return 0;
}

int
qers_after_create(struct pfcp_session *s)
{
	struct qers *qs = &s->qers;
	uint8_t qer_refcnt[qs->n];
	struct pdr *p;
	int pdr_n = 0;
	int i, k;

	/* detect presence of session-ambr qer */
	memset(qer_refcnt, 0, sizeof(qer_refcnt));
	list_for_each_entry(p, &s->pdr_list, next) {
		for (k = 0; k < p->qer_n; k++)
			qer_refcnt[p->qer[k]]++;
		++pdr_n;
	}
	if (!pdr_n || !qs->n)
		return 0;

	qs->ambr_qer_idx = -1;
	for (i = 0; i < qs->n; i++) {
		if ((!qs->q[i].dl_mbr && !qs->q[i].ul_mbr) || qs->q[i].qfi)
			continue;
		if (qs->q[i].correlation_id)
			qs->ambr_qer_idx = i;
		else if (qer_refcnt[i] == pdr_n && qs->ambr_qer_idx < 0)
			qs->ambr_qer_idx = i;
	}

	/* manage session ambr bpf qer entry */
	if (qs->ambr_qer_idx >= 0 && !qs->ambr_qer_bpf_idx) {
		qs->ambr_qer_bpf_idx = pfcp_bpf_alloc_mbr_idx(s);
		if (!qs->ambr_qer_bpf_idx)
			return -1;
		qers_update_bpf(s, &qs->q[qs->ambr_qer_idx],
				qs->ambr_qer_bpf_idx, false);

	} else if (qs->ambr_qer_idx >= 0) {
		qers_update_bpf(s, &qs->q[qs->ambr_qer_idx],
				qs->ambr_qer_bpf_idx, true);

	} else if (qs->ambr_qer_bpf_idx) {
		pfcp_bpf_release_mbr_idx(s, qs->ambr_qer_bpf_idx);
		qs->ambr_qer_bpf_idx = 0;
	}

	/* sync per-flow QER BPF entries */
	for (i = 0; i < qs->n; i++) {
		if (i != qs->ambr_qer_idx && _qer_sync_bpf(s, &qs->q[i]))
			return -1;
	}

	return 0;
}

int
qers_on_modify(struct pfcp_session *s,
	       struct pfcp_session_modification_request *req)
{
	struct qers *qs = &s->qers;
	int i;

	qs->action = req->nr_create_qer || req->nr_remove_qer;

	for (i = 0; i < req->nr_remove_qer; i++)
		qers_remove(s, req->remove_qer[i]->qer_id->value);

	if (qers_grow(s, qs->n + req->nr_create_qer))
		return -1;
	for (i = 0; i < req->nr_create_qer; i++)
		qers_create(qs, req->create_qer[i]);

	for (i = 0; i < req->nr_update_qer; i++)
		qers_update(qs, req->update_qer[i]);

	return 0;
}

int
qers_after_modify(struct pfcp_session *s,
		  struct pfcp_session_modification_request *req,
		  int pdr_changed)
{
	if (!pdr_changed && !req->nr_remove_qer &&
	    !req->nr_create_qer && !req->nr_update_qer)
		return 0;

	return qers_after_create(s);
}

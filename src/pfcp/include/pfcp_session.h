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

#include "logger.h"
#include "gtp_apn.h"
#include "gtp_conn.h"
#include "pfcp_msg.h"
#include "pfcp_metrics.h"
#include "gtp_bpf_capture.h"
#include "bpf/lib/upf-def.h"
#include "mempool.h"

/* Default values */
#define PFCP_MAX_NR_ELEM	5
#define PFCP_STR_MAX_LEN	32

/* Hash table */
#define PFCP_SESSION_HASHTAB_BITS  20
#define PFCP_SESSION_HASHTAB_SIZE  (1 << PFCP_SESSION_HASHTAB_BITS)
#define PFCP_SESSION_HASHTAB_MASK  (PFCP_SESSION_HASHTAB_SIZE - 1)

/* Session flags */
enum pfcp_session_flags {
	PFCP_SESSION_FL_UE_IPV4,
	PFCP_SESSION_FL_UE_IPV6,
	PFCP_SESSION_FL_HPLMN,
	PFCP_SESSION_FL_ROAMING_IN,
	PFCP_SESSION_FL_ROAMING_OUT,
};

/* Capture flags */
#define PFCP_SESSION_CAPTURE_FL_DATA	0x0100
#define PFCP_SESSION_CAPTURE_FL_PFCP	0x0200

/* Session Actions */
enum {
	PFCP_ACTION_DELETE_SESSION = 1,
};

/* Session components */
struct f_seid {
	uint64_t		id;
	sockaddr_t		addr;
};

#define UE_IPV4	(1 << 0)
#define UE_IPV6	(1 << 1)
#define UE_CHV4	(1 << 2)
#define UE_CHV6	(1 << 3)
struct ue_ip_address {
	uint8_t			flags;
	struct in_addr		v4;
	struct in6_addr		v6;
	struct ip_pool		*pool_v4;
	struct ip_pool		*pool_v6;
};

struct traffic_endpoint {
	uint8_t			action;
	uint8_t			id;
	uint8_t			choose_id;
	uint8_t			interface_type;
	struct ue_ip_address	ue_ip;
	struct pfcp_teid	*teid;

	struct list_head	next;
};

struct far {
	uint8_t			action;
	uint32_t		id;

	uint8_t			dst_interface_type;
	uint8_t			dst_interface;
	uint8_t			tos_tclass;
	uint8_t			tos_mask;
	uint32_t		outer_header_teid;
	struct in_addr		outer_header_ip4;
	struct in6_addr		outer_header_ip6;

	struct traffic_endpoint	*dst_te;

	uint16_t		flags;

	struct list_head	next;
};

struct qer {
	uint32_t		idx;		/* index in qers arrays */
	uint32_t		qer_id;		/* ie.qer_id */
	uint8_t			ul_gate;	/* 0=open, 1=closed */
	uint8_t			dl_gate;
	uint32_t		ul_mbr;		/* kbps */
	uint32_t		dl_mbr;		/* kbps */
	uint32_t		averaging_window; /* ms */
	uint32_t		correlation_id;
	uint8_t			qfi;
	uint32_t		bpf_idx;	/* upf_mbr map index, 0=unused */
};

struct qers {
	int			n;
	int			msize;
	struct qer		*q;
	uint8_t			action;

	/* aggregated mbr (session-wide) */
	int			ambr_qer_idx;
	uint32_t		ambr_qer_bpf_idx;
};

struct urr_volume {
	uint64_t			to;
	uint64_t			ul;
	uint64_t			dl;
};

struct urr_time {
	uint32_t			threshold;
	uint32_t			quota;
	uint32_t			periodic;
	uint32_t			inactivity_detection;
	uint32_t			quota_holdtime;
};

struct urr {
	uint32_t			idx;		/* index in urrs arrays */
	uint32_t			urr_id;		/* ie.urr_id */
	uint32_t			ttc_idx;	/* index in bpf map */
	uint32_t			seqn;
	bool				queried;
	bool				reported;
	bool				auto_attach;
	bool				quota_blocked;	/* zero quota from CP */
	int				linked_urr_n;
	uint32_t			*linked_urr_id;
	uint32_t			linked_by;	/* bit i = urr[i] links to me */

	union pfcp_measurement_method	measurement_method;
	union pfcp_measurement_information measurement_info;
	union pfcp_reporting_triggers	triggers;

	uint32_t			start_time;
	uint32_t			end_time;
	uint32_t			pkt_first_time;
	uint32_t			pkt_last_time;
	int				duration;
	int				last_report_duration;
	struct pfcp_metrics_pkt		ul;
	struct pfcp_metrics_pkt		dl;
	struct pfcp_metrics_pkt		last_report_ul;
	struct pfcp_metrics_pkt		last_report_dl;
};

struct urrs {
	int				n;	/* number of active URRs */
	int				msize;	/* allocated capacity */
	struct urr			*u;
	struct urr_volume		*vol_threshold;
	struct urr_volume		*vol_next;	/* next trigger point */
	struct urr_volume		*vol_quota;
	struct urr_time			*time;

	/* bpf's ttc mapping */
	int				ttc_n;
	int				ttc_msize;
	struct pfcp_ttc_cmd		*ttc;

	/* misc. */
	uint8_t				cmd_cur_id;
	uint32_t			query_ref;
};

struct pdr {
	uint8_t			action;
	uint16_t		id;		/* network order */
	uint32_t		precedence;

	/* F-TEID in PDI */
	uint8_t			src_interface;
	uint8_t			choose_id;
	struct pfcp_teid	*teid;
	struct ue_ip_address	ue_ip;

	/* F-TEID in traffic-endpoint when using
	 * PDI Optimization */
	struct traffic_endpoint *te;

	struct far		*far;

	int			*qer;
	int			qer_n;
	int			qer_msize;

	int			*urr;
	int			urr_n;
	int			urr_msize;

	struct pfcp_fwd_rule	*fwd_rule;
	char			predefined_rule[PFCP_STR_MAX_LEN];

	uint16_t		flags;

	struct list_head	next;
};

#define PFCP_ACT_NONE		0
#define PFCP_ACT_CREATE		1
#define PFCP_ACT_UPDATE		2
#define PFCP_ACT_DELETE		3
struct pfcp_fwd_rule {
	uint8_t			action;
	struct upf_fwd_rule	rule;
};

/* PFCP User Equipement */
struct pfcp_ue {
	struct gtp_conn		c;
	struct list_head	pfcp_sessions;	/* pdn sessions */
	struct gtp_capture_entry capture;
	bool			persistent_capture;
};

/* PFCP session */
struct pfcp_session {
	struct mpool		mp;

	uint64_t		seid;
	struct f_seid		remote_seid;

	struct list_head	pdr_list;
	struct list_head	far_list;
	struct list_head	te_list;

	/* qer handling */
	struct qers		qers;

	struct ue_ip_address	ue_ip;
	struct thread		*ue_ip_ra_timer;
	int			ue_ip_ra_cnt;
	int			teid_cnt;

	struct pfcp_ue		*ue;
	struct pfcp_router	*router;	/* Server used */
	struct gtp_apn		*apn;
	struct gtp_cdr		*cdr;

	int			cpu;		/* xdp pinned cpu */
	uint8_t			action;

	/* Expiration handling */
	char			tmp_str[64];
	struct tm		creation_time;
	struct tm		deletion_time;

	/* I/O MUX */
	struct thread		*timer;

	/* packets capture */
	struct gtp_capture_entry sig_cap;
	struct gtp_capture_entry data_cap;

	/* urr handling */
	struct urrs		urrs;
	struct list_head	urr_cmd_pending_list;
	struct pkt_buffer	*pending_pbuff;
	sockaddr_t		pending_addr;

	/* indexing */
	struct list_head	next;
	struct hlist_node	hlist;

	struct log_ctx		log;
	unsigned long		flags;
};

/* Prototypes */
struct gtp_range_partition *gtp_resolve_rp(struct gtp_apn *apn, struct pfcp_router *router, int type);
struct pfcp_ue *pfcp_ue_alloc(uint64_t imsi, uint64_t imei, uint64_t msisdn);
void pfcp_ue_release_all_sessions(struct pfcp_ue *ue);
int pfcp_sessions_count_read(void);
int pfcp_sessions_cpu_count(int cpu);
sockaddr_t *pfcp_session_get_addr_by_interface(struct pfcp_router *r,
					       uint8_t interface);
struct pfcp_session *pfcp_session_get(uint64_t id);
struct pfcp_session *pfcp_session_alloc(struct pfcp_ue *ue,
					struct gtp_apn *apn,
					struct pfcp_router *r);

int pfcp_session_alloc_ue_ip(struct pfcp_session *s, sa_family_t af);
int pfcp_session_release_ue_ip(struct pfcp_session *s);
int pfcp_session_release_teid(struct pfcp_session *s);
void pfcp_session_release(struct pfcp_session *s);
int pfcp_sessions_free(struct pfcp_ue *ue);
int pfcp_sessions_init(void);
int pfcp_sessions_destroy(void);

/* pfcp_session_ctx.c */
int pfcp_session_create(struct pfcp_session *s,
			struct pfcp_session_establishment_request *req,
			sockaddr_t *addr);
int pfcp_session_modify(struct pfcp_session *s,
			struct pfcp_session_modification_request *req);
int pfcp_session_delete(struct pfcp_session *s);
int pfcp_session_update_fwd_rules(struct pfcp_session *s);
int pfcp_session_put_created_pdr(struct pkt_buffer *pbuff,
				 struct pfcp_session *s);
int pfcp_session_put_created_traffic_endpoint(struct pkt_buffer *pbuff,
					      struct pfcp_session *s);

/* pfcp_session_urr.c */
int urrs_find_by_urr_id(const struct urrs *us, uint32_t urr_id);
int urrs_grow(struct pfcp_session *s, int new_msize);
int urrs_save_metrics(struct urrs *us, const struct upf_ttc_report_data *rd,
		       uint32_t mono2ntptime_off);
void urrs_report_triggered(struct pfcp_session *s,
			   const struct upf_ttc_report_data *urd);
int urrs_put_modification_reports(struct urrs *us,  struct pkt_buffer *pbuff);
int urrs_put_deletion_reports(struct urrs *us, struct pkt_buffer *pbuff);
int urrs_on_create(struct pfcp_session *s,
		   struct pfcp_session_establishment_request *req);
int urrs_on_modify(struct pfcp_session *s,
		   struct pfcp_session_modification_request *req);

/* pfcp_session_qer.c */
int qers_find_by_qer_id(const struct qers *qs, uint32_t qer_id);
int qers_on_create(struct pfcp_session *s,
		   struct pfcp_session_establishment_request *req);
int qers_after_create(struct pfcp_session *s);
int qers_on_modify(struct pfcp_session *s,
		   struct pfcp_session_modification_request *req);
int qers_after_modify(struct pfcp_session *s,
		      struct pfcp_session_modification_request *req,
		      int pdr_changed);
void qers_release(struct pfcp_session *s);

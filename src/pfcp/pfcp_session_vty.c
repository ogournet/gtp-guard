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
#include "utils.h"
#include "addr.h"
#include "command.h"
#include "table.h"
#include "pfcp_router.h"
#include "pfcp_session.h"
#include "pfcp_teid.h"
#include "pfcp_utils.h"
#include "pfcp_bpf.h"


/*
 *	VTY Command
 */
static void
_pfcp_session_urr_vty(struct vty *vty, struct urrs *us, int i)
{
	const struct urr *u = &us->u[i];
	const union pfcp_measurement_method *mm = &u->measurement_method;
	const union pfcp_reporting_triggers *tr = &u->triggers;
	char mmb[64];
	int k = 0;

	vty_out(vty, " . URR[%d] urr_id:%d seqn:%d\n",
		u->idx, ntohl(u->urr_id), u->seqn);

	if (mm->durat)
		k += scnprintf(mmb + k, sizeof(mmb) - k, "duration,");
	if (mm->volum)
		k += scnprintf(mmb + k, sizeof(mmb) - k, "volume,");
	if (mm->event)
		k += scnprintf(mmb + k, sizeof(mmb) - k, "event,");
	mmb[k ? k - 1 : 0] = 0;
	if (mm->measurement_method)
		vty_out(vty, "     measure : %s\n", mmb);

	if (tr->triggers)
		vty_out(vty, "     triggers:");
	vty_out(vty, "%s", VTY_NEWLINE);

	if (tr->perio)
		vty_out(vty, "      - PERIO period:%ds\n",
			us->time[i].periodic);
	if (tr->volth) {
		vty_out(vty, "      - VOLTH");
		if (us->vol_threshold[i].to)
			vty_out(vty, " total:%ld",
				us->vol_threshold[i].to);
		if (us->vol_threshold[i].ul)
			vty_out(vty, " ul:%ld",
				us->vol_threshold[i].ul);
		if (us->vol_threshold[i].dl)
			vty_out(vty, " dl:%ld",
				us->vol_threshold[i].dl);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (tr->volqu) {
		vty_out(vty, "      - VOLQU");
		if (us->vol_quota[i].to)
			vty_out(vty, " total:%ld",
				us->vol_quota[i].to);
		if (us->vol_quota[i].ul)
			vty_out(vty, " ul:%ld",
				us->vol_quota[i].ul);
		if (us->vol_quota[i].dl)
			vty_out(vty, " dl:%ld",
				us->vol_quota[i].dl);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (tr->timth)
		vty_out(vty, "      - TIMTH threshold:%ds\n",
			us->time[i].threshold);
	if (tr->timqu)
		vty_out(vty, "      - TIMQU quota:%ds\n",
			us->time[i].quota);
	if (tr->quhti)
		vty_out(vty, "      - QUHTI holdtime:%ds\n",
			us->time[i].quota_holdtime);
	if (tr->start)
		vty_out(vty, "      - START\n");
	if (tr->stopt)
		vty_out(vty, "      - STOPT\n");
	if (tr->droth)
		vty_out(vty, "      - DROTH\n");
	if (tr->liusa)
		vty_out(vty, "      - LIUSA\n");
	if (tr->envcl)
		vty_out(vty, "      - ENVCL\n");
	if (tr->macar)
		vty_out(vty, "      - MACAR\n");
	if (tr->eveth)
		vty_out(vty, "      - EVETH\n");
	if (tr->evequ)
		vty_out(vty, "      - EVEQU\n");
	if (tr->ipmjl)
		vty_out(vty, "      - IPMJL\n");
	if (tr->quvti)
		vty_out(vty, "      - QUVTI\n");

	/* metrics */
	if (mm->volum)
		vty_out(vty, "     volume  :\n"
			"       ul: packets:%ld bytes:%ld\n"
			"       dl: packets:%ld bytes:%ld\n",
			u->ul.count, u->ul.bytes,
			u->dl.count, u->dl.bytes);
	if (mm->durat && u->duration >= 0)
		vty_out(vty, "     duration:%ds\n",
			u->duration);
}

static void
_pfcp_session_ttc_vty(struct vty *vty, const struct upf_ttc_cmd *c,
		      int idx)
{
	vty_out(vty, " . TTC[%d] bpf_idx:%d flags:0x%02x\n",
		idx, c->ttc_idx, c->flags);

	if (c->total_th || c->ul_th || c->dl_th) {
		vty_out(vty, "     vol-threshold");
		if (c->total_th)
			vty_out(vty, " total:%lld", c->total_th);
		if (c->ul_th)
			vty_out(vty, " ul:%lld", c->ul_th);
		if (c->dl_th)
			vty_out(vty, " dl:%lld", c->dl_th);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (c->total_qu || c->ul_qu || c->dl_qu) {
		vty_out(vty, "     vol-quota");
		if (c->total_qu)
			vty_out(vty, " total:%lld", c->total_qu);
		if (c->ul_qu)
			vty_out(vty, " ul:%lld", c->ul_qu);
		if (c->dl_qu)
			vty_out(vty, " dl:%lld", c->dl_qu);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	if (c->time_th)
		vty_out(vty, "     time-threshold:%ds\n", c->time_th);
	if (c->time_qu)
		vty_out(vty, "     time-quota:%ds\n", c->time_qu);
	if (c->time_periodic)
		vty_out(vty, "     periodic:%ds\n", c->time_periodic);
	if (c->time_inactivity)
		vty_out(vty, "     quota-holdtime:%ds\n",
			c->time_inactivity);
	if (c->inactivity_det_time)
		vty_out(vty, "     inactivity-det:%ds\n",
			c->inactivity_det_time);
}

static void
_pfcp_session_qer_vty(struct vty *vty, const struct qer *q)
{
	vty_out(vty, " . QER[%d] qer_id:%d", q->idx, ntohl(q->qer_id));
	if (q->qfi)
		vty_out(vty, " qfi:%d", q->qfi);
	if (q->correlation_id)
		vty_out(vty, " correlation_id:%d", q->correlation_id);
	vty_out(vty, "%s", VTY_NEWLINE);

	vty_out(vty, "     gate    : ul:%s dl:%s\n",
		q->ul_gate ? "CLOSED" : "OPEN",
		q->dl_gate ? "CLOSED" : "OPEN");

	if (q->ul_mbr || q->dl_mbr) {
		vty_out(vty, "     mbr     :");
		if (q->ul_mbr)
			vty_out(vty, " ul:%d kbps", q->ul_mbr);
		if (q->dl_mbr)
			vty_out(vty, " dl:%d kbps", q->dl_mbr);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (q->averaging_window)
		vty_out(vty, "     avg-wnd : %d ms\n",
			q->averaging_window);
}

static void
_pfcp_session_pdr_vty(struct vty *vty, struct pfcp_session *s,
		      bool details)
{
	struct gtp_bpf_prog *prg = s->router->bpf_prog;
	struct upf_fwd_rule *u;
	struct qers *qs;
	struct urrs *us;
	struct pdr *p;
	struct pfcp_teid *t;
	int j;

	list_for_each_entry(p, &s->pdr_list, next) {
		if (p->te)
			vty_out(vty, " . Traffic-Endpoint:%d "
				"3GPP-Interface-Type:%s\n", p->te->id,
				pfcp_3GPP_interface2str(p->te->interface_type));

		if (!p->fwd_rule)
			continue;
		u = &p->fwd_rule->rule;
		t = p->teid ?: (p->te ? p->te->teid : NULL);

		if (u->flags & UPF_FWD_FL_EGRESS && t) {
			vty_out(vty, "   [uplink] local-teid:0x%.8x"
				     " local-gtpu:'%s'\n"
				   , t->id
				   , ip4_str(t->ipv4.s_addr));
			pfcp_bpf_teid_vty(vty, prg, UPF_FWD_FL_EGRESS, &s->ue_ip, t);
		}

		if (u->flags & UPF_FWD_FL_INGRESS) {
			vty_out(vty, "   [downlink] remote-teid:0x%.8x"
				     " remote-gtpu:'%s'\n"
				   , u->gtpu_remote_teid
				   , ip4_str(u->gtpu_remote_addr));
			pfcp_bpf_teid_vty(vty, prg, UPF_FWD_FL_INGRESS, &s->ue_ip, t);
		}

		if (details && p->qer_n) {
			qs = &s->qers;
			vty_out(vty, "            ref-qer:");
			for (j = 0; j < p->qer_n; j++) {
				struct qer *rq = &qs->q[p->qer[j]];
				vty_out(vty, " %d", ntohl(rq->qer_id));
				if (rq->bpf_idx)
					vty_out(vty, "(bpf:%d)", rq->bpf_idx);
			}
			vty_out(vty, "%s", VTY_NEWLINE);
		}

		if (details && p->urr_n) {
			us = &s->urrs;
			vty_out(vty, "            ref-urr:");
			for (j = 0; j < p->urr_n; j++)
				vty_out(vty, " %d", ntohl(us->u[p->urr[j]].urr_id));
			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}
}

int
pfcp_session_vty(struct vty *vty, struct gtp_conn *c, void *arg)
{
	struct pfcp_ue *pue = (struct pfcp_ue *)c;
	struct pfcp_session *s;
	struct ue_ip_address *ue;
	time_t timeout = 0;
	struct tm *t;
	bool details = arg != NULL;
	int i;

	/* Walk the line */
	list_for_each_entry(s, &pue->pfcp_sessions, next) {
		if (s->timer) {
			timeout = s->timer->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);

		}

		t = &s->creation_time;
		vty_out(vty, " imsi:%ld seid:0x%lx remote-seid:0x%lx apn:%s"
			     " creation:%.2d/%.2d/%.2d-%.2d:%.2d:%.2d expire:%s\n"
			   , c->imsi, s->seid, be64toh(s->remote_seid.id), s->apn->name
			   , t->tm_mday, t->tm_mon+1, t->tm_year+1900
			   , t->tm_hour, t->tm_min, t->tm_sec
			   , s->timer ? s->tmp_str : "never");

		ue = &s->ue_ip;
		if (ue->flags & UE_IPV4)
			vty_out(vty, " . UE IPv4: %s\n",
				ip4_str(ue->v4.s_addr));
		if (ue->flags & UE_IPV6)
			vty_out(vty, " . UE IPv6: %s\n",
				ip6_str(&ue->v6));

		_pfcp_session_pdr_vty(vty, s, details);

		if (details) {
			struct qers *qs = &s->qers;
			struct urrs *us = &s->urrs;

			for (i = 0; i < qs->n; i++)
				_pfcp_session_qer_vty(vty, &qs->q[i]);
			if (qs->ambr_qer_idx >= 0)
				vty_out(vty, " . AMBR: qer_id:%d bpf:%d\n",
					ntohl(qs->q[qs->ambr_qer_idx].qer_id),
					qs->ambr_qer_bpf_idx);

			for (i = 0; i < us->n; i++)
				_pfcp_session_urr_vty(vty, us, i);
			for (i = 0; i < us->ttc_n; i++)
				_pfcp_session_ttc_vty(vty, &us->ttc[i].tc, i);
		}
	}
	return 0;
}

int
pfcp_session_summary_vty(struct vty *vty, struct gtp_conn *c, void *arg)
{
	struct pfcp_ue *ue = (struct pfcp_ue *)c;
	struct list_head *l = &ue->pfcp_sessions;
	struct table *tbl = arg;
	struct pfcp_session *s;
	time_t timeout = 0;
	struct gtp_apn *apn = NULL;

	if (!tbl)
		return -1;

	/* Walk the line */
	list_for_each_entry(s, l, next) {
		if (s->timer) {
			timeout = s->timer->sands.tv_sec - time_now.tv_sec;
			snprintf(s->tmp_str, 63, "%ld secs", timeout);
		}

		if (!apn) {
			table_add_row_fmt(tbl, "%ld|%s|seid:0x%lx #teid:%.2d expiration:%s"
					     , c->imsi, s->apn->name, s->seid, s->teid_cnt
					     , s->timer ? s->tmp_str : "never");
			apn = s->apn;
			continue;
		}

		table_add_row_fmt(tbl, "%s|%s|seid:0x%lx #teid:%.2d expiration:%s"
				     , "", (apn == s->apn) ? "" : s->apn->name
				     , s->seid, s->teid_cnt
				     , s->timer ? s->tmp_str : "never");
		apn = s->apn;
	}

	return 0;
}

DEFUN(show_pfcp_session,
      show_pfcp_session_cmd,
      "show pfcp session [IMSI DETAILS]",
      SHOW_STR
      "PFCP related informations\n"
      "PFCP Session tracking\n"
      "IMSI to look for (none for all)\n")
{
	struct table *tbl;
	uint64_t imsi;

	if (argc) {
		imsi = strtoull(argv[0], NULL, 10);
		gtp_conn_vty(vty, pfcp_session_vty, imsi,
			     argc > 1 ? (void *)1 : NULL);
		return CMD_SUCCESS;
	}

	tbl = table_init(3, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "IMSI", "APN", "PFCP Sessions Informations");
	table_set_column_align(tbl, ALIGN_RIGHT, ALIGN_RIGHT, ALIGN_LEFT);

	gtp_conn_vty(vty, pfcp_session_summary_vty, 0, tbl);

	table_vty_out(tbl, vty);
	table_destroy(tbl);

	return CMD_SUCCESS;
}

DEFUN(clear_pfcp_session,
      clear_pfcp_session_cmd,
      "clear pfcp session IMSI",
      "Clear PFCP related\n"
      "PFCP session\n"
      "PFCP Session\n"
      "IMSI\n")
{
	struct gtp_conn *c;
	uint64_t imsi = 0;

	imsi = strtoull(argv[0], NULL, 10);
	c = gtp_conn_get_by_imsi(imsi);
	if (!c) {
		vty_out(vty, "%% unknown imsi:%ld\n", imsi);
		return CMD_WARNING;
	}

	pfcp_ue_release_all_sessions((struct pfcp_ue *)c);
	return CMD_SUCCESS;
}


/* Capture */
DEFUN(capture_start_pfcp,
      capture_start_pfcp_cmd,
      "capture start pfcp (seid|imsi|imei|msisdn) USER "
      "[ name CAPENTRY ] "
      "[ side (input|output|access|core|all) ] "
      "[ caplen <32-10000> ] "
      "[ sigonly ] "
      "[ dataonly ] "
      "[ permanent ]",
      "Capture menu\n"
      "Start capture\n"
      "Capture pfcp protocol submenu\n"
      "Capture by SEID\n"
      "Capture by IMSI\n"
      "Capture by IMEI\n"
      "Capture by MSISDN\n"
      "Capture this user\n"
      "Capture file entry name\n"
      "File entry name\n"
      "Capture side (default: input)\n"
      "Capture on input (xdp rx)\n"
      "Capture on output (xdp tx/pass/redirect)\n"
      "Capture on acces side (encap in gtp-u)\n"
      "Capture on core side (plain l3)\n"
      "Capture on both input and output\n"
      "Capture packet max length\n"
      "Value\n"
      "Capture pfcp signalisation only\n"
      "Capture userplan data only\n"
      "Permanent capture (start a new trace on each new session)\n")
{
	struct pfcp_session *s;
	struct gtp_conn *c = NULL;
	struct pfcp_ue *ue;
	uint16_t cap_fl, traf_fl;
	char capname[64];
	int cap_len = 0;
	bool persist = false;
	uint64_t v = atoll(argv[1]);
	int i;

	snprintf(capname, sizeof (capname), "%ld", v);
	cap_fl = GTP_CAPTURE_FL_INPUT;
	traf_fl = PFCP_SESSION_CAPTURE_FL_PFCP | PFCP_SESSION_CAPTURE_FL_DATA;

	/* parse optional parameters */
	for (i = 2; i < argc; i += 2) {
		if (!strcmp(argv[i], "name") && i + 1 < argc) {
			snprintf(capname, sizeof (capname), "%s", argv[i + 1]);
		} else if (!strcmp(argv[i], "side") && i + 1 < argc) {
			if (!strcmp(argv[i + 1], "input"))
				cap_fl = GTP_CAPTURE_FL_INPUT;
			else if (!strcmp(argv[i + 1], "output"))
				cap_fl = GTP_CAPTURE_FL_OUTPUT;
			else if (!strcmp(argv[i + 1], "core"))
				cap_fl = GTP_CAPTURE_FL_CORE;
			else if (!strcmp(argv[i + 1], "access"))
				cap_fl = GTP_CAPTURE_FL_ACCESS;
			else if (!strcmp(argv[i + 1], "all"))
				cap_fl = GTP_CAPTURE_FL_DIRECTION_MASK;
		} else if (!strcmp(argv[i], "caplen") && i + 1 < argc)
			VTY_GET_INTEGER_RANGE("caplen", cap_len, argv[i + 1],
					      32, 10000);
		else if (!strcmp(argv[i], "dataonly"))
			traf_fl = PFCP_SESSION_CAPTURE_FL_DATA;
		else if (!strcmp(argv[i], "sigonly"))
			traf_fl = PFCP_SESSION_CAPTURE_FL_PFCP;
		else if (!strcmp(argv[i], "persist"))
			persist = !strcmp(argv[i + 1], "1");
		else {
			vty_out(vty, "%% Incomplete command\n");
			return CMD_WARNING;
		}
	}

	/* get user to trace */
	if (!strcmp(argv[0], "imsi"))
		c = gtp_conn_get_by_imsi(v);
	else if (!strcmp(argv[0], "imei"))
		c = gtp_conn_get_by_imei(v);
	else if (!strcmp(argv[0], "msisdn"))
		c = gtp_conn_get_by_msisdn(v);
	else if (!strcmp(argv[0], "seid")) {
		s = pfcp_session_get(v);
		c = s ? (s->ue ? &s->ue->c : NULL) : NULL;
	}
	if (c == NULL) {
		if (persist && !strcmp(argv[0], "imsi")) {
			ue = pfcp_ue_alloc(v, 0, 0);
			if (ue == NULL)
				return CMD_WARNING;
			vty_out(vty, "user imsi=%s doesn't exist yet, will start "
				"capture when it will attach\n", argv[1]);
		} else {
			vty_out(vty, "%% Cannot find user '%s' by %s\n", argv[1], argv[0]);
			return CMD_WARNING;
		}
	} else {
		ue = (struct pfcp_ue *)c;
	}

	if (persist && !ue->persistent_capture) {
		ue->persistent_capture = true;
		gtp_conn_refinc(&ue->c);
	}

	ue->capture.flags = cap_fl | traf_fl;
	ue->capture.cap_len = cap_len;
	list_for_each_entry(s, &ue->pfcp_sessions, next) {
		if (traf_fl & PFCP_SESSION_CAPTURE_FL_DATA) {
			s->data_cap.flags = cap_fl | traf_fl;
			s->data_cap.cap_len = cap_len;
			if (gtp_capture_start(&s->data_cap, s->router->bpf_prog, capname))
				vty_out(vty, "%% Error starting pfcp gtp-u trace\n");
			pfcp_session_update_fwd_rules(s);
		} else {
			gtp_capture_stop(&s->data_cap);
			pfcp_session_update_fwd_rules(s);
		}

		if (traf_fl & PFCP_SESSION_CAPTURE_FL_PFCP) {
			/* on signaling path, we always want full packets and both path */
			s->sig_cap.flags = GTP_CAPTURE_FL_INPUT |
				GTP_CAPTURE_FL_OUTPUT | traf_fl;
			s->sig_cap.cap_len = ~0;
			if (gtp_capture_start(&s->sig_cap, s->router->bpf_prog, capname))
				vty_out(vty, "%% Error starting pfcp trace\n");
		} else {
			gtp_capture_stop(&s->sig_cap);
		}
	}

	return CMD_SUCCESS;
}

DEFUN(capture_stop_pfcp,
      capture_stop_pfcp_cmd,
      "capture stop pfcp (imsi|imei|msisdn) USER",
      "Capture menu\n"
      "Stop capture\n"
      "Capture pfcp protocol submenu\n"
      "Interface name\n")
{
	struct pfcp_session *s;
	struct gtp_conn *c = NULL;
	struct pfcp_ue *ue;
	uint64_t v = atoll(argv[1]);

	if (!strcmp(argv[0], "imsi"))
		c = gtp_conn_get_by_imsi(v);
	else if (!strcmp(argv[0], "imei"))
		c = gtp_conn_get_by_imei(v);
	else if (!strcmp(argv[0], "msisdn"))
		c = gtp_conn_get_by_msisdn(v);

	if (c == NULL) {
		vty_out(vty, "%% Cannot find user '%s' by %s\n", argv[1], argv[0]);
		return CMD_WARNING;
	}

	ue = (struct pfcp_ue *)c;
	memset(&ue->capture, 0x00, sizeof (ue->capture));
	if (ue->persistent_capture) {
		gtp_conn_refdec(&ue->c);
		ue->persistent_capture = false;
	}
	list_for_each_entry(s, &ue->pfcp_sessions, next) {
		gtp_capture_stop(&s->sig_cap);
		gtp_capture_stop(&s->data_cap);
		pfcp_session_update_fwd_rules(s);
	}

	return CMD_SUCCESS;
}


/*
 *	VTY init
 */
int
cmd_ext_pfcp_session_install(void)
{
	install_element(ENABLE_NODE, &capture_start_pfcp_cmd);
	install_element(ENABLE_NODE, &capture_stop_pfcp_cmd);

	/* Install show commands */
	install_element(VIEW_NODE, &show_pfcp_session_cmd);
	install_element(ENABLE_NODE, &show_pfcp_session_cmd);
	install_element(ENABLE_NODE, &clear_pfcp_session_cmd);

	return 0;
}

static struct cmd_ext cmd_ext_pfcp_session = {
	.install = cmd_ext_pfcp_session_install,
};

static void __attribute__((constructor))
pfcp_session_vty_init(void)
{
	cmd_ext_register(&cmd_ext_pfcp_session);
}

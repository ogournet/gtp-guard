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
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <errno.h>

#include "gtp.h"
#include "gtp_utils.h"
#include "gtp_bpf_capture.h"
#include "pfcp.h"
#include "pfcp_router.h"
#include "pfcp_assoc.h"
#include "pfcp_session.h"
#include "pfcp_session_report.h"
#include "pfcp_msg.h"
#include "pfcp_proto_dump.h"
#include "pfcp_utils.h"
#include "gtp_conn.h"
#include "gtp_apn.h"
#include "inet_utils.h"
#include "pkt_buffer.h"
#include "bitops.h"
#include "logger.h"


/*
 *	PFCP Protocol helpers
 */

/* Heartbeat */
static int
pfcp_heartbeat_request(struct pfcp_msg *msg, struct pfcp_server *srv,
		       sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	int err;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_HEARTBEAT_RESPONSE;

	/* Append mandatory IE */
	err = pfcp_ie_put_recovery_ts(pbuff, ctx->recovery_ts);
	if (err) {
		log_message(LOG_INFO, "%s(): Cant append recovery_ts IE"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}


/* pfd management */
static int
pfcp_pfd_management_request(struct pfcp_msg *msg, struct pfcp_server *srv,
			    sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	int err;

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_PFD_MANAGEMENT_RESPONSE;

	/* Append IEs */
	err = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
				      PFCP_CAUSE_REQUEST_ACCEPTED);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}


/* Association setup */
static int
pfcp_assoc_setup_request(struct pfcp_msg *msg, struct pfcp_server *srv,
			 sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	struct pfcp_assoc *assoc;
	struct pfcp_association_setup_request *req;
	uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
	int err;

	req = msg->association_setup_request;

	/* 3GPP.TS.29.244 6.2.6.2.2 : Already exist ? */
	assoc = pfcp_assoc_get_by_ie(req->node_id);
	if (assoc) {
		if (!req->session_retention_info) {
			/* TODO: release all related Sessions */
		}

		assoc->recovery_ts = req->recovery_time_stamp->ts;
	} else {
		assoc = pfcp_assoc_alloc(req->node_id, req->recovery_time_stamp);
		if (!assoc) {
			cause = PFCP_CAUSE_REQUEST_REJECTED;
		}
	}

	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_ASSOCIATION_SETUP_RESPONSE;

	/* Append IEs */
	err = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len, cause);
	err = (err) ? : pfcp_ie_put_recovery_ts(pbuff, ctx->recovery_ts);
	err = (err) ? : pfcp_ie_put_up_function_features(pbuff, ctx->supported_features);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
pfcp_assoc_setup_response(struct pfcp_msg *msg, struct pfcp_server *srv,
			  sockaddr_t *addr)
{
	struct pfcp_association_setup_response *rsp;
	struct pfcp_assoc *assoc;
	char assoc_str[GTP_NAME_MAX_LEN];

	rsp = msg->association_setup_response;

	if (rsp->cause->value != PFCP_CAUSE_REQUEST_ACCEPTED) {
		log_message(LOG_INFO, "%s(): remote PFCP peer:'%s' rejection (%s)"
				    , __FUNCTION__
				    , sa_str_ip(addr)
				    , pfcp_cause2str(rsp->cause->value));
		return -1;
	}

	/* Already exit... ignore... */
	assoc = pfcp_assoc_get_by_ie(rsp->node_id);
	if (assoc)
		return -1;

	/* Create this brand new one ! */
	assoc = pfcp_assoc_alloc(rsp->node_id, rsp->recovery_time_stamp);
	log_message(LOG_INFO, "%s(): %s Creating PFCP association:'%s'"
			    , __FUNCTION__
			    , (assoc) ? "Success" : "Error"
			    , pfcp_assoc_stringify(assoc, assoc_str, GTP_NAME_MAX_LEN));

	return -1;
}

void
pfcp_assoc_setup_request_send(struct thread *t)
{
	struct pfcp_router *ctx = THREAD_ARG(t);
	struct pfcp_server *srv = &ctx->s;
	struct pfcp_peer_list *plist = ctx->peer_list;
	struct pkt_buffer *pbuff;
	struct pfcp_hdr *pfcph;
	struct pkt *p;
	int err = 0, i;

	if (srv->ctx == NULL)
		return;

	p = __pkt_queue_get(&srv->pkt_q);
	if (!p) {
		log_message(LOG_INFO, "%s(): Error getting pkt from queue for server %s"
				    , __FUNCTION__
				    , sa_str(&srv->s.addr));
		return;
	}

	/* Prepare pkt */
	pbuff = p->pbuff;
	pfcph = (struct pfcp_hdr *) pbuff->head;
	pfcph->version = 1;
	pfcph->type = PFCP_ASSOCIATION_SETUP_REQUEST;
	pfcph->sqn_only = htonl(1 << 8);
	pfcp_msg_reset_hlen(pbuff);

	err = pfcp_ie_put_node_id(pbuff, ctx->node_id, ctx->node_id_len);
	err = (err) ? : pfcp_ie_put_recovery_ts(pbuff, ctx->recovery_ts);
	err = (err) ? : pfcp_ie_put_up_function_features(pbuff, ctx->supported_features);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		goto end;
	}

	/* Broadcast pkt to peer list */
	for (i = 0; i < plist->nr_addr; i++)
		inet_server_snd(&ctx->s.s, ctx->s.s.fd, pbuff, &plist->addr[i]);

end:
	__pkt_queue_put(&srv->pkt_q, p);
}


/* Session Establishment */
static struct gtp_apn *
pfcp_session_get_apn(struct pfcp_ie_apn_dnn *apn_dnn)
{
	struct gtp_apn *apn;
	char apn_str[64];
	int err;

	if (!apn_dnn)
		return NULL;

	err = pfcp_ie_decode_apn_dnn_ni(apn_dnn, apn_str, sizeof(apn_str) - 1);
	if (err) {
		log_message(LOG_INFO, "%s(): malformed IE APN-DNN... rejecting..."
				    , __FUNCTION__);
		return NULL;
	}

	apn = gtp_apn_get(apn_str);
	if (!apn) {
		log_message(LOG_INFO, "%s(): Unknown Access-Point-Name:'%s'. rejecting..."
				    , __FUNCTION__, apn_str);
		return NULL;
	}

	return apn;
}

static int
pfcp_session_establishment_request(struct pfcp_msg *msg, struct pfcp_server *srv,
				   sockaddr_t *addr)
{
	struct pkt_buffer *rcv_pbuff = srv->s.pbuff;
	struct pkt_buffer *pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *)rcv_pbuff->head;
	struct pfcp_router *ctx = srv->ctx;
	struct pfcp_assoc *assoc;
	struct pfcp_session *s;
	struct pfcp_ue *ue;
	struct gtp_apn *apn = NULL;
	struct pfcp_session_establishment_request *req;
	uint8_t cause = PFCP_CAUSE_REQUEST_ACCEPTED;
	uint64_t imsi, imei, msisdn;
	int ret;

	req = msg->session_establishment_request;

	if (!pfcph->s) {
		cause = PFCP_CAUSE_MANDATORY_IE_MISSING;
		pfcph->s = 1;
		pfcph->seid = 0;
		goto err;
	}

	assoc = pfcp_assoc_get_by_ie(req->node_id);
	if (!assoc) {
		cause = PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION;
		goto err;
	}

	/* APN selection */
	if (__test_bit(PFCP_ROUTER_FL_STRICT_APN, &ctx->flags))
		apn = pfcp_session_get_apn(req->apn_dnn);
	if (!apn) {
		log_message(LOG_INFO, "%s(): No APN selected... rejecting..."
				    , __FUNCTION__);
		cause = PFCP_CAUSE_REQUEST_REJECTED;
		goto err;
	}

	/* User infos */
	if (!req->user_id) {
		log_message(LOG_INFO, "%s(): IE User-ID not present... rejecting..."
				    , __FUNCTION__);
		cause = PFCP_CAUSE_REQUEST_REJECTED;
		goto err;
	}

	ret = pfcp_ie_decode_user_id(req->user_id, &imsi, &imei, &msisdn);
	if (ret) {
		log_message(LOG_INFO, "%s(): malformed IE User-ID... rejecting..."
				    , __FUNCTION__);
		cause = PFCP_CAUSE_REQUEST_REJECTED;
		goto err;
	}

	ue = (struct pfcp_ue *)gtp_conn_get_by_imsi(imsi);
	if (ue == NULL) {
		ue = pfcp_ue_alloc(imsi, imei, msisdn);
		if (ue == NULL) {
			cause = PFCP_CAUSE_REQUEST_REJECTED;
			goto err;
		}
	}

	/* Create new session */
	s = pfcp_session_alloc(ue, apn, ctx);
	if (!s) {
		log_message(LOG_INFO, "%s(): Unable to create new session... rejecting..."
				    , __FUNCTION__);
		cause = PFCP_CAUSE_REQUEST_REJECTED;
		goto err;
	}

	gtp_capture_data(&s->sig_cap, rcv_pbuff->head, pkt_buffer_len(rcv_pbuff),
			 addr, &srv->s.addr, GTP_CAPTURE_FL_INPUT);

	ret = pfcp_session_create(s, req, addr);
	if (ret) {
		if (errno == ENOSPC) {
			cause = PFCP_CAUSE_ALL_DYNAMIC_ADDRESS_ARE_OCCUPIED;
		} else {
			log_message(LOG_INFO, "%s(): malformed IE Create-PDR... rejecting..."
				    , __FUNCTION__);
			cause = PFCP_CAUSE_REQUEST_REJECTED;
		}
		pfcp_session_delete(s);
		goto err;
	}

 err:
	/* Alloc and copy header to response buffer */
	pbuff = pkt_buffer_alloc(DEFAULT_PKT_BUFFER_SIZE);
	if (pbuff == NULL)
		return -1;
	memcpy(pbuff->head, rcv_pbuff->head, pfcp_msg_hlen(rcv_pbuff));
	pfcp_msg_reset_hlen(pbuff);
	pfcph = (struct pfcp_hdr *)pbuff->head;
	pfcph->type = PFCP_SESSION_ESTABLISHMENT_RESPONSE;

	/* Append IEs */
	ret = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len, cause);
	if (cause != PFCP_CAUSE_REQUEST_ACCEPTED)
		goto reply_now;

	ret = (ret) ? : pfcp_ie_put_f_seid(pbuff, htobe64(s->seid), &srv->s.addr);
	ret = (ret) ? : pfcp_session_put_created_pdr(pbuff, s);
	ret = (ret) ? : pfcp_session_put_created_traffic_endpoint(pbuff, s);
	if (ret) {
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
		pfcp_session_delete(s);
		pfcp_msg_reset_hlen(pbuff);
		ret = pfcp_ie_put_error_cause(pbuff, ctx->node_id, ctx->node_id_len,
					      PFCP_CAUSE_SYSTEM_FAILURE);
		goto reply_now;
	}

	/* Update PFCP Header */
	pfcph->seid = s->remote_seid.id;

	/* Some urr commands are still pending, delay reply */
	if (!list_empty(&s->urr_cmd_pending_list)) {
		s->pending_addr = *addr;
		s->pending_pbuff = pbuff;
		return PFCP_ROUTER_DELAYED;
	}

 reply_now:
	pkt_buffer_free(srv->s.pbuff);
	srv->s.pbuff = pbuff;
	if (s != NULL)
		gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
				 addr, &srv->s.addr, GTP_CAPTURE_FL_OUTPUT);
	return ret;
}

/* Session modification */
static int
pfcp_session_modification_request(struct pfcp_msg *msg, struct pfcp_server *srv,
				  sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_session *s;
	uint8_t cause = PFCP_CAUSE_REQUEST_REJECTED;
	int ret;

	/* Retrieve pfcp session */
	if (!pfcph->s) {
		cause = PFCP_CAUSE_MANDATORY_IE_MISSING;
		pfcph->s = 1;
		pfcph->seid = 0;
		goto reply_now;
	}
	s = pfcp_session_get(be64toh(pfcph->seid));
	if (!s) {
		log_message(LOG_INFO, "%s(): Unknown Session-ID:0x%" PRIx64
				    , __FUNCTION__, be64toh(pfcph->seid));
		cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
		pfcph->seid = 0;
		goto reply_now;
	}
	gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
			 addr, &srv->s.addr, GTP_CAPTURE_FL_INPUT);
	pfcph->seid = s->remote_seid.id;

	/* Handle modification message */
	if (msg->session_modification_request == NULL)
		goto reply_now;
	ret = pfcp_session_modify(s, msg->session_modification_request);
	if (ret) {
		log_message(LOG_INFO, "%s(): malformed Modification request...."
				    , __FUNCTION__);
		goto reply_now;
	}

	/* Some urr commands are still pending, delay reply */
	if (!list_empty(&s->urr_cmd_pending_list)) {
		s->pending_addr = *addr;
		s->pending_pbuff = pbuff;
		srv->s.pbuff = NULL;
		return PFCP_ROUTER_DELAYED;
	}

	cause = PFCP_CAUSE_REQUEST_ACCEPTED;

 reply_now:
	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_SESSION_MODIFICATION_RESPONSE;

	/* Append Cause IE */
	ret = pfcp_ie_put_cause(pbuff, cause);
	if (ret)
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
	if (s != NULL)
		gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
				 addr, &srv->s.addr, GTP_CAPTURE_FL_OUTPUT);

	return ret;
}

/* Session deletion */
static int
pfcp_session_deletion_request(struct pfcp_msg *msg, struct pfcp_server *srv,
			      sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_session *s;
	uint8_t cause = PFCP_CAUSE_REQUEST_REJECTED;
	int ret;

	/* Retrieve pfcp session */
	if (!pfcph->s) {
		cause = PFCP_CAUSE_MANDATORY_IE_MISSING;
		pfcph->s = 1;
		pfcph->seid = 0;
		goto reply_now;
	}
	s = pfcp_session_get(be64toh(pfcph->seid));
	if (!s) {
		log_message(LOG_INFO, "%s(): Unknown Session-ID:0x%" PRIx64
				    , __FUNCTION__, be64toh(pfcph->seid));
		cause = PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
		pfcph->seid = 0;
		goto reply_now;
	}
	gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
			 addr, &srv->s.addr, GTP_CAPTURE_FL_INPUT);
	pfcph->seid = s->remote_seid.id;

	/* Delete URRs, and generate the last report */
	if (s->bpf_urr_idx) {
		struct upf_urr_cmd_req *uc = pfcp_bpf_urr_alloc_cmd(s);
		uc->urr_idx = s->bpf_urr_idx;
		uc->ctl_fl = UPF_FL_CTL_DELETE;
		pfcp_bpf_urr_ctl(s, uc);

		s->pending_addr = *addr;
		s->pending_pbuff = srv->s.pbuff;
		srv->s.pbuff = NULL;
		return PFCP_ROUTER_DELAYED;
	}

	cause = PFCP_CAUSE_REQUEST_ACCEPTED;

 reply_now:
	/* Recycle header and reset length */
	pfcp_msg_reset_hlen(pbuff);
	pfcph->type = PFCP_SESSION_DELETION_RESPONSE;

	/* Append Cause IE */
	ret = pfcp_ie_put_cause(pbuff, cause);
	if (ret)
		log_message(LOG_INFO, "%s(): Error while Appending IEs"
				    , __FUNCTION__);
	if (s != NULL)
		gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
				 addr, &srv->s.addr, GTP_CAPTURE_FL_OUTPUT);

	return ret;
}

/* Session Report Response */
static int
pfcp_session_report_response(struct pfcp_msg *msg, struct pfcp_server *srv,
			      sockaddr_t *addr)
{
	struct pfcp_session_report_response *rsp = msg->session_report_response;
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_session *s = NULL;

	if (rsp->cause->value != PFCP_CAUSE_REQUEST_ACCEPTED)
		log_message(LOG_INFO, "%s(): remote PFCP peer:'%s' rejection (%s)"
				    , __FUNCTION__
				    , sa_str_ip(addr)
				    , pfcp_cause2str(rsp->cause->value));

	if (pfcph->s)
		s = pfcp_session_get(be64toh(pfcph->seid));
	if (s != NULL)
		gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
				 addr, &srv->s.addr, GTP_CAPTURE_FL_INPUT);

	return -1;
}


/*
 *	PFCP FSM
 */
static const struct {
	int (*hdl) (struct pfcp_msg *, struct pfcp_server *, sockaddr_t *);
} pfcp_msg_hdl[1 << 8] = {
	/* PFCP Node related */
	[PFCP_HEARTBEAT_REQUEST]		= { pfcp_heartbeat_request },
	[PFCP_PFD_MANAGEMENT_REQUEST]		= { pfcp_pfd_management_request },
	[PFCP_ASSOCIATION_SETUP_REQUEST]	= { pfcp_assoc_setup_request },
	[PFCP_ASSOCIATION_SETUP_RESPONSE]	= { pfcp_assoc_setup_response },
	[PFCP_ASSOCIATION_UPDATE_REQUEST]	= { NULL },
	[PFCP_ASSOCIATION_RELEASE_REQUEST]	= { NULL },
	[PFCP_NODE_REPORT_REQUEST]		= { NULL },
	[PFCP_SESSION_SET_DELETION_REQUEST]	= { NULL },
	[PFCP_SESSION_SET_MODIFICATION_REQUEST]	= { NULL },

	/* PFCP Session related */
	[PFCP_SESSION_ESTABLISHMENT_REQUEST]	= { pfcp_session_establishment_request },
	[PFCP_SESSION_MODIFICATION_REQUEST]	= { pfcp_session_modification_request },
	[PFCP_SESSION_DELETION_REQUEST]		= { pfcp_session_deletion_request },
	[PFCP_SESSION_REPORT_REQUEST]		= { NULL },
	[PFCP_SESSION_REPORT_RESPONSE]		= { pfcp_session_report_response },
};

int
pfcp_proto_hdl(struct pfcp_server *srv, sockaddr_t *addr)
{
	struct pfcp_router *c = srv->ctx;
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct pfcp_hdr *pfcph = (struct pfcp_hdr *) pbuff->head;
	struct pfcp_msg *msg = srv->msg;
	int err;

	err = pfcp_msg_parse(msg, srv->s.pbuff);
	if (err) {
		log_message(LOG_INFO, "%s(): Error while parsing [%s] Request"
				    , __FUNCTION__
				    , pfcp_msgtype2str(pfcph->type));
		err = -1;
		goto end;
	}

	if (__test_bit(PFCP_DEBUG_FL_INGRESS_MSG, &c->debug))
		pfcp_proto_dump(srv, msg, addr, PFCP_DIR_INGRESS);

	if (!*(pfcp_msg_hdl[pfcph->type].hdl)) {
		pfcp_metrics_rx_notsup(&srv->msg_metrics, pfcph->type);
		err = -1;
		goto end;
	}

	pfcp_metrics_rx(&srv->msg_metrics, pfcph->type);
	err = (*(pfcp_msg_hdl[pfcph->type].hdl)) (msg, srv, addr);

	if (!err && __test_bit(PFCP_DEBUG_FL_EGRESS_MSG, &c->debug))
		pfcp_proto_dump(srv, NULL, addr, PFCP_DIR_EGRESS);

end:
	return err;
}


/*
 *	GTP-U Message handle
 */
int
gtpu_send_end_marker(struct gtp_server *srv, struct far *f)
{
	struct gtpuhdr *gtph = (struct gtpuhdr *)srv->s.pbuff->head;
	sockaddr_t addr_to;
	int gtph_len = GTPU_HLEN_SHORT;

	gtph->flags = GTPU_FL_V1 | GTPU_FL_PT;
	gtph->type = GTPU_TYPE_END_MARKER;
	gtph->length = 0;
	gtph->teid = f->outer_header_teid;

	if (f->dst_interface_type == PFCP_3GPP_INTERFACE_N3 ||
	    f->dst_interface_type == PFCP_3GPP_INTERFACE_N9) {
		gtph_len += 8;
		gtph->length = htons(8);
		gtph->flags |= GTPU_FL_E;
		gtph->seqnum = 0;
		gtph->npdu_num = 0;
		gtph->exthdr_type = GTPU_ETYPE_PDU_SESSION_CONTAINER;
		gtph->exthdr[0] = 1;
		gtph->exthdr[1] = 0;
		gtph->exthdr[2] = 0;
		gtph->exthdr[3] = GTPU_ETYPE_NONE;
	}

	pkt_buffer_set_end_pointer(srv->s.pbuff, gtph_len);
	pkt_buffer_set_data_pointer(srv->s.pbuff, gtph_len);

	sa_from_ip4_port(&addr_to, f->outer_header_ip4.s_addr, GTP_U_PORT);

	return inet_server_snd(&srv->s, srv->s.fd, srv->s.pbuff, &addr_to);
}

static int
gtpu_build_ra(struct gtp_server *srv, struct pfcp_session *s, uint32_t teid,
	      sockaddr_t *addr_to, const struct in6_addr *dst_addr,
	      bool add_gtp_exthdr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct gtpuhdr *gtph;
	struct ip6_hdr *ip6h;
	struct icmp6_hdr *icmp6;
	struct nd_router_advert *nd_ra;
	struct nd_opt_prefix_info *nd_pi;
	int pl_len, gtph_len = GTPU_HLEN_SHORT;

	if (pbuff == NULL)
		pbuff = srv->s.pbuff = pkt_buffer_alloc(DEFAULT_PKT_BUFFER_SIZE);

	pl_len = sizeof (*nd_ra) + sizeof (*nd_pi);

	gtph = (struct gtpuhdr *)pbuff->head;
	gtph->flags = GTPU_FL_V1 | GTPU_FL_PT;
	gtph->type = GTPU_TYPE_TPDU;
	gtph->teid = teid;
	if (add_gtp_exthdr) {
		gtph->flags |= GTPU_FL_E;
		gtph->length = htons(8 + sizeof (*ip6h) + pl_len);
		gtph->seqnum = 0;
		gtph->npdu_num = 0;
		gtph->exthdr_type = GTPU_ETYPE_PDU_SESSION_CONTAINER;
		gtph->exthdr[0] = 1;
		gtph->exthdr[1] = 0;
		gtph->exthdr[2] = 0;
		gtph->exthdr[3] = GTPU_ETYPE_NONE;
		gtph_len += 8;
	} else {
		gtph->length = htons(sizeof (*ip6h) + pl_len);
	}

	ip6h = (void *)gtph + gtph_len;
	if (dst_addr != NULL) {
		memmove(ip6h->ip6_dst.s6_addr, dst_addr, sizeof (*dst_addr));
	} else {
		ip6h->ip6_dst.s6_addr32[0] = __constant_htonl(0xff020000);
		ip6h->ip6_dst.s6_addr32[1] = 0;
		ip6h->ip6_dst.s6_addr32[2] = 0;
		ip6h->ip6_dst.s6_addr32[3] = __constant_htonl(0x00000001);
	}
	ip6h->ip6_flow = 0;
	ip6h->ip6_vfc = 0x60;
	ip6h->ip6_plen = htons(pl_len);
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	ip6h->ip6_hlim = 255;
	ip6h->ip6_src.s6_addr32[0] = __constant_htonl(0xfe800000);
	ip6h->ip6_src.s6_addr32[1] = 0;
	ip6h->ip6_src.s6_addr32[2] = 0;
	ip6h->ip6_src.s6_addr32[3] = __constant_htonl(0x00000001);

	nd_ra = (struct nd_router_advert *)(ip6h + 1);
	icmp6 = &nd_ra->nd_ra_hdr;
	icmp6->icmp6_type = ND_ROUTER_ADVERT;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_data8[0] = 255;
	icmp6->icmp6_data8[1] = 0;
	icmp6->icmp6_data16[1] = __constant_htons(64800);
	nd_ra->nd_ra_reachable = 0;
	nd_ra->nd_ra_retransmit = 0;
	nd_pi = (struct nd_opt_prefix_info *)(nd_ra + 1);
	nd_pi->nd_opt_pi_type = 3;
	nd_pi->nd_opt_pi_len = 4;
	nd_pi->nd_opt_pi_prefix_len = 64;
	nd_pi->nd_opt_pi_flags_reserved = 0x40;
	nd_pi->nd_opt_pi_valid_time = ~0;
	nd_pi->nd_opt_pi_preferred_time = ~0;
	nd_pi->nd_opt_pi_reserved2 = 0;
	nd_pi->nd_opt_pi_prefix = s->ue_ip.v6;

	/* compute icmpv6 checksum */
	uint16_t csum = ipv6_pshdr_csum(ip6h);
	csum = in_csum((uint16_t*)icmp6, pl_len, ~csum);
	icmp6->icmp6_cksum = csum;

	pl_len += sizeof (*ip6h) + gtph_len;
	pkt_buffer_set_end_pointer(pbuff, pl_len);
	pkt_buffer_set_data_pointer(pbuff, pl_len);

	gtp_capture_data(&s->sig_cap, pbuff->head, pkt_buffer_len(pbuff),
			 addr_to, &srv->s.addr, GTP_CAPTURE_FL_OUTPUT);

	return inet_server_snd(&srv->s, srv->s.fd, pbuff, addr_to);
}

int
gtpu_send_router_advert(struct gtp_server *srv, struct pfcp_session *s, struct far *f)
{
	sockaddr_t addr_to;

	sa_from_ip4_port(&addr_to, f->outer_header_ip4.s_addr, GTP_U_PORT);
	return gtpu_build_ra(srv, s, f->outer_header_teid, &addr_to, NULL,
			     f->dst_interface_type == PFCP_3GPP_INTERFACE_N3 ||
			     f->dst_interface_type == PFCP_3GPP_INTERFACE_N9);
}


static int
gtpu_echo_request_hdl(struct gtp_server *srv, sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct gtpuhdr *h = (struct gtpuhdr *)pbuff->head;
	struct gtp1_ie_recovery *rec;

	/* 3GPP.TS.129.060 7.2.2 : IE Recovery is mandatory in response message */
	h->type = GTPU_TYPE_ECHO_RSP;
	h->length = htons(ntohs(h->length) + sizeof(*rec));
	pkt_buffer_set_end_pointer(srv->s.pbuff, gtpu_get_header_len(pbuff));
	pkt_buffer_set_data_pointer(srv->s.pbuff, gtpu_get_header_len(pbuff));

	gtp1_ie_add_tail(srv->s.pbuff, sizeof(*rec));
	rec = (struct gtp1_ie_recovery *) srv->s.pbuff->data;
	rec->type = GTP1_IE_RECOVERY_TYPE;
	rec->recovery = 0;
	pkt_buffer_put_data(srv->s.pbuff, sizeof(*rec));
	return 1;
}

static int
gtpu_error_indication_hdl(struct gtp_server *s, sockaddr_t *addr)
{
	return 0;
}

static int
gtpu_end_marker_hdl(struct gtp_server *s, sockaddr_t *addr)
{
	/* TODO: Release related TEID */
	return 0;
}

static int
gtpu_data_hdl(struct gtp_server *srv, sockaddr_t *addr)
{
	struct pkt_buffer *pbuff = srv->s.pbuff;
	struct gtpuhdr *gtph;
	struct ip6_hdr *ip6h;
	struct icmp6_hdr *icmp6;
	struct pfcp_session *s = NULL;
	struct far *f;
	struct pdr *p;
	uint32_t teid;
	int hlen;

	hlen = gtpu_get_header_len(pbuff);
	if (hlen < 0)
		return 0;

	/* check it is a router solicitation */
	gtph = (struct gtpuhdr *)pbuff->head;
	ip6h = (void *)gtph + hlen;
	icmp6 = (struct icmp6_hdr *)(ip6h + 1);
	if ((uint8_t *)icmp6 + 1 > pbuff->tail ||
	    (gtph->flags & 0xf0) != 0x30 ||
	    ip6h->ip6_nxt != IPPROTO_ICMPV6 ||
	    icmp6->icmp6_type != ND_ROUTER_SOLICIT)
		return 0;

	/* use bpf 'user_egress' map to lookup seid, then retrieve
	 * pfcp_session. pfcp_teid doesn't have index we wish for */
	struct upf_egress_key ek = {
		.gtpu_local_teid = gtph->teid,
		.gtpu_local_addr = sa_ip4(&srv->s.addr),
	};
	uint64_t seid = pfcp_bpf_lookup_seid(srv->ctx, &ek);
	if (seid)
		s = pfcp_session_get(seid);
	if (s == NULL || !(s->ue_ip.flags & UE_IPV6))
		return 0;

	/* now walk far in session's pdr, to find someone matching
	 * remote addr. if addr match, then we have the remote teid! */
	teid = 0;
	list_for_each_entry(p, &s->pdr_list, next) {
		f = p->far;
		if (f == NULL)
			continue;
		if (f->outer_header_ip4.s_addr &&
		    f->outer_header_ip4.s_addr == sa_ip4(addr)) {
			teid = f->outer_header_teid;
			break;
		}
	}
	if (!teid)
		return 0;

	/* build and send RA */
	sa_set_port(addr, GTP_U_PORT);
	gtpu_build_ra(srv, s, teid, addr, &ip6h->ip6_src, gtph->flags & GTPU_FL_E);

	return 0;
}


static const struct {
	int (*hdl) (struct gtp_server *, sockaddr_t *);
} gtpu_msg_hdl[1 << 8] = {
	[GTPU_TYPE_ECHO_REQ]			= { gtpu_echo_request_hdl },
	[GTPU_TYPE_ERROR_IND]			= { gtpu_error_indication_hdl },
	[GTPU_TYPE_END_MARKER]			= { gtpu_end_marker_hdl	},
	[GTPU_TYPE_TPDU]			= { gtpu_data_hdl },
};

int
pfcp_gtpu_hdl(struct gtp_server *srv, sockaddr_t *addr)
{
	struct gtpuhdr *gtph = (struct gtpuhdr *) srv->s.pbuff->head;
	ssize_t len;

	len = gtpu_get_header_len(srv->s.pbuff);
	if (len < 0)
		return -1;

	if (*(gtpu_msg_hdl[gtph->type].hdl)) {
		gtp_metrics_rx(&srv->msg_metrics, gtph->type);

		return (*(gtpu_msg_hdl[gtph->type].hdl)) (srv, addr);
	}

	/* Not supported */
	log_message(LOG_INFO, "%s(): GTP-U/path-mgt msg_type:0x%.2x from %s not supported..."
			    , __FUNCTION__
			    , gtph->type
			    , sa_str(addr));

	gtp_metrics_rx_notsup(&srv->msg_metrics, gtph->type);
	return -1;
}




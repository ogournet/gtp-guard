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

#include "pfcp_server.h"
#include "pfcp.h"
#include "inet_server.h"
#include "inet_utils.h"
#include "logger.h"
#include "bitops.h"
#include "pkt_buffer.h"


/* Extern data */
extern struct thread_master *master;


static int
pfcp_server_rcv(struct inet_server *srv, ssize_t nbytes, const sockaddr_t *remote)
{
	struct pfcp_server *s = container_of(srv, struct pfcp_server, s);
	struct pkt_buffer *pbuff = srv->pbuff;

	gtp_capture_data(&s->capture, pbuff->head, nbytes,
			 remote, &srv->addr, GTP_CAPTURE_FL_INPUT);

	pfcp_metrics_pkt_update(&s->rx_metrics, nbytes);
	return 0;
}

static int
pfcp_server_snd(struct inet_server *srv, struct pkt_buffer *pbuff, ssize_t nbytes,
		const sockaddr_t *remote)
{
	struct pfcp_server *s = container_of(srv, struct pfcp_server, s);
	struct pfcp_hdr *h = (struct pfcp_hdr *) pbuff->head;

	gtp_capture_data(&s->capture, pbuff->head, pkt_buffer_len(pbuff),
			 remote, &srv->addr, GTP_CAPTURE_FL_OUTPUT);

	pfcp_metrics_pkt_update(&s->tx_metrics, nbytes);
	pfcp_metrics_tx(&s->msg_metrics, h->type);
	return 0;
}


int
pfcp_server_init(struct pfcp_server *s, void *ctx,
		 int (*init) (struct inet_server *),
		 int (*process) (struct inet_server *, sockaddr_t *))
{
	struct inet_server *srv = &s->s;
	sockaddr_t *addr = &srv->addr;
	int err;

	/* Init pfcp server */
	s->ctx = ctx;
	s->msg = pfcp_msg_alloc(PFCP_MSG_MEM_ZEROCOPY);
	if (!s->msg) {
		log_message(LOG_INFO, "%s(): Error allocating PFCP msg for %s"
				    , __FUNCTION__
				    , sa_str(addr));
		return -1;
	}

	/* Init inet server */
	srv->ctx = s;
	srv->init = init;
	srv->process = process;
	srv->snd = pfcp_server_snd;
	srv->rcv = pfcp_server_rcv;

	/* Create UDP Listener */
	err = inet_server_init(srv, SOCK_DGRAM);
	if (err) {
		log_message(LOG_INFO, "%s(): Error creating PFCP listener on %s"
				    , __FUNCTION__
				    , sa_str(addr));
		pfcp_msg_free(s->msg);
		s->msg = NULL;
		return -1;
	}

	/* So far so good */
	pkt_queue_init(&s->pkt_q, DEFAULT_PKT_QUEUE_SIZE);
	inet_server_start(srv, master);
	return 0;
}

int
pfcp_server_destroy(struct pfcp_server *s)
{
	pfcp_msg_free(s->msg);
	pkt_queue_destroy(&s->pkt_q);
	return inet_server_destroy(&s->s);
}

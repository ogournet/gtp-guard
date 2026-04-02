/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        The main goal of gtp-guard is to provide robust and secure
 *              extensions to GTP protocol (GPRS Tunneling Protocol). GTP is
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

#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <linux/perf_event.h>
#include <libbpf.h>

#include "xpcapng.h"
#include "utils.h"
#include "command.h"
#include "table.h"
#include "config.h"
#include "gtp_interface.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_capture.h"
#include "bpf/lib/capture-def.h"


#define PERF_BUFFER_PAGES		128

/* set max number of running captures per bpf program */
#define CAPTURE_BPF_MAX_ENTRY		8


struct capture_perf_buf_cpu
{
	struct thread			*t;
	struct perf_buffer		*pb;
	int				cpu;
};


/* per bpf-program */
struct gtp_bpf_capture_ctx
{
	struct list_head		list;
	struct gtp_bpf_prog		*p;

	struct gtp_capture_entry	*ae[CAPTURE_BPF_MAX_ENTRY];
	int				ae_n;

	/* perf buffer to send packet data to userspace */
	struct bpf_map			*perf_map;
	struct perf_buffer		*pb;
	struct capture_perf_buf_cpu	*apbc;
	uint64_t			missed_events;
	uint32_t			last_missed_events;

	/* trace program */
	struct capture_bpf_entry	prg_entry;
	struct bpf_map			*cfg_map;
	struct bpf_map			*iface_map;
	struct bpf_object		*tr_obj;
	struct bpf_link			*fentry_lnk;
	struct bpf_link			*fexit_lnk;
};

/* capture_file. may be referenced by 0 to many capture_entry */
struct gtp_capture_file
{
	char				name[32];
	char				filename[64];
	struct gtp_bpf_prog		*p;
	struct xpcapng_dumper		*pcapng;
	int				refcnt;
	bool				running;
	bool				persist;
	uint16_t			snaplen;

	uint32_t			pkt_max;
	uint32_t			duration;	/* in seconds */
	uint32_t			pkt_count;
	time_t				until;
	uint64_t			*cpu_packet_id;
	int				cpu_packet_id_n;

	struct list_head		list;
};


/* Extern data */
extern struct thread_master *master;

/* config and local data */
static char cfg_pcap_path[256];
static int cfg_wakeup_events;
static uint16_t cfg_capture_snaplen = GTP_CAPTURE_DEFAULT_SNAPLEN;
static uint64_t epoch_delta;
static struct thread *flush_ev;
static LIST_HEAD(cfile_list);		/* opened pcap files */
static LIST_HEAD(bcc_list);		/* running bpf-prog */


/********************************************************************/
/* perf_buffer */

struct perf_sample_raw
{
	struct perf_event_header header;
	uint64_t time;
	uint32_t size;
	struct capture_metadata md;
	unsigned char packet[];
};

struct perf_sample_lost
{
	struct perf_event_header header;
	uint64_t id;
	uint64_t lost;
};

static enum bpf_perf_event_ret
capture_handle_perf_event(void *ctx, int cpu, struct perf_event_header *event)
{
	struct gtp_bpf_capture_ctx *bcc = ctx;
	struct gtp_capture_entry *ce;
	struct gtp_capture_file *cf;
	struct perf_sample_lost *lost;
	struct perf_sample_raw *e;
	uint64_t ts;

	if (event->type == PERF_RECORD_LOST) {
		lost = container_of(event, struct perf_sample_lost, header);
		bcc->missed_events += lost->lost;
		bcc->last_missed_events += lost->lost;
		return LIBBPF_PERF_EVENT_CONT;
	}

	if (event->type != PERF_RECORD_SAMPLE)
		return LIBBPF_PERF_EVENT_CONT;

	e = container_of(event, struct perf_sample_raw, header);
	if (e->header.size < sizeof(struct perf_sample_raw) ||
	    e->size < (sizeof (struct capture_metadata) + e->md.cap_len))
		return LIBBPF_PERF_EVENT_CONT;

	ce = bcc->ae[e->md.entry_id - 1];
	if (ce == NULL || ce->cf == NULL || !ce->cf->running)
		return LIBBPF_PERF_EVENT_CONT;
	cf = ce->cf;

	ts = e->time + epoch_delta;

	struct xpcapng_epb_options_s options = {};
	int64_t  action = e->md.action;
	uint32_t queue = e->md.rx_queue;

	options.flags = e->md.flags & BPF_CAPTURE_EFL_INPUT ?
		PCAPNG_EPB_FLAG_INBOUND : PCAPNG_EPB_FLAG_OUTBOUND;
	options.dropcount = bcc->last_missed_events;
	options.packetid = &cf->cpu_packet_id[cpu];
	options.queue = &queue;
	options.xdp_verdict = action == -1 ? NULL : &action;

	int if_idx = 0;
	/* XXX: set if_idx to xpcapng_add_interface index */

	xpcapng_dump_enhanced_pkt(cf->pcapng, if_idx, e->packet,
				  min(cf->snaplen, e->md.pkt_len),
				  e->md.cap_len, ts, &options);
	bcc->last_missed_events = 0;

	cf->pkt_count++;
	if ((cf->pkt_max && cf->pkt_count >= cf->pkt_max) ||
	    (cf->until && ts / NSEC_PER_SEC > cf->until)) {
		printf("stopping capture, pkt: %d/%d, expired:%s (ref:%d)\n",
		       cf->pkt_count, cf->pkt_max,
		       cf->until && ts / NSEC_PER_SEC > cf->until ? "yes" : "no",
		       cf->refcnt);
		cf->running = false;
	}

	return LIBBPF_PERF_EVENT_CONT;
}

static void
capture_perf_consume(struct capture_perf_buf_cpu *pbc)
{
	int ret;

	ret = perf_buffer__consume_buffer(pbc->pb, pbc->cpu);
	if (ret && errno != EAGAIN)
		fprintf(stderr, "perf consume buffer: %m\n");
}

/* callback called by thread, when there is something to read on perf buffer's fd.
 * libbpf will handle data and then will call handle_event. */
static void
capture_perf_io_read(struct thread *t)
{
	struct capture_perf_buf_cpu *pbc = THREAD_ARG(t);

	capture_perf_consume(pbc);
	pbc->t = thread_add_read(master, capture_perf_io_read, pbc,
				 THREAD_FD(t), TIMER_NEVER, 0);
}


/********************************************************************/
/* capture_file */

static int
capture_file_start(struct gtp_capture_file *cf, struct gtp_bpf_prog *p)
{
	struct gtp_interface *iface;
	char pathname[400];
	char ifname[200];

	if (cf->running)
		return 0;
	if (cf->p != NULL && cf->p != p)
		return -1;
	cf->p = p;
	cf->snaplen = cfg_capture_snaplen;

	/* set filename from name, if not set */
	if (!*cf->filename)
		snprintf(cf->filename, sizeof (cf->filename), "%s", cf->name);
	snprintf(pathname, sizeof (pathname), "%s/%s.pcap",
		 cfg_pcap_path, cf->filename);

	/* open pcap */
	cf->pcapng = xpcapng_dump_open(pathname, NULL, NULL, NULL,
				       VERSION_STRING);
	if (cf->pcapng == NULL) {
		syslog(LOG_ERR, "Can't open PcapNG file for writing!");
		return -1;
	}

	/* XXX: dynamically register to bpf prog's ifaces */
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		snprintf(ifname, sizeof (ifname), "%s:%s",
			 p->name, iface->ifname);
		if (xpcapng_dump_add_interface(cf->pcapng,
					       cfg_capture_snaplen,
					       ifname, NULL, NULL,
					       0, 9, NULL) < 0) {
			syslog(LOG_ERR, "Can't add %s interface to PcapNG file!",
				ifname);
			xpcapng_dump_close(cf->pcapng);
			cf->pcapng = NULL;
			return -1;
		}
	}

	cf->pkt_count = 0;
	if (cf->duration)
		cf->until = time(NULL) + cf->duration;
	else
		cf->until = 0;
	cf->running = true;
	printf("%s.pcap: capture file started\n", cf->filename);

	return 0;
}

static void
capture_file_stop(struct gtp_capture_file *cf)
{
	struct gtp_bpf_capture_ctx *bcc;
	int i;

	if (!cf->running)
		return;

	xpcapng_dump_close(cf->pcapng);
	printf("%s.pcap: capture file closed, wrote %d packets\n",
	       cf->filename, cf->pkt_count);
	cf->running = false;

	/* force capture_stop() on each linked gtp_capture_entry */
	list_for_each_entry(bcc, &bcc_list, list) {
		for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++) {
			if (bcc->ae[i] != NULL && bcc->ae[i]->cf == cf)
				gtp_capture_stop(bcc->ae[i]);

		}
	}
	cf->p = NULL;
}

static struct gtp_capture_file *
capture_file_get(const char *name, bool alloc)
{
	struct gtp_capture_file *cf;

	list_for_each_entry(cf, &cfile_list, list) {
		if (!strcmp(cf->name, name)) {
			cf->refcnt++;
			return cf;
		}
	}
	if (!alloc)
		return NULL;

	cf = calloc(1, sizeof (*cf));
	if (cf == NULL)
		return NULL;
	snprintf(cf->name, sizeof (cf->name), "%s", name);
	cf->refcnt = 1;
	cf->cpu_packet_id_n = libbpf_num_possible_cpus();
	cf->cpu_packet_id = calloc(cf->cpu_packet_id_n + 1,
				   sizeof (*cf->cpu_packet_id));
	if (cf->cpu_packet_id == NULL) {
		free(cf);
		return NULL;
	}
	list_add_tail(&cf->list, &cfile_list);

	return cf;
}

static void
capture_file_put(struct gtp_capture_file *cf)
{
	if (cf->refcnt && --cf->refcnt)
		return;
	capture_file_stop(cf);
	if (!cf->persist) {
		list_del(&cf->list);
		free(cf->cpu_packet_id);
		free(cf);
	}
}


static void
capture_timer_flush(struct thread *thread)
{
	struct gtp_bpf_capture_ctx *bcc;
	struct gtp_capture_file *cf;
	int i;

	list_for_each_entry(cf, &cfile_list, list) {
		if (cf->until && time(NULL) > cf->until)
			capture_file_stop(cf);
		if (cf->running)
			xpcapng_dump_flush(cf->pcapng);
	}

	list_for_each_entry(bcc, &bcc_list, list) {
		for (i = 0; i < perf_buffer__buffer_cnt(bcc->pb); i++)
			capture_perf_consume(&bcc->apbc[i]);
	}

	flush_ev = thread_add_timer(master, capture_timer_flush, NULL, TIMER_HZ);
}


/********************************************************************/
/* capture on bpf-prog and gtp interface */

static int
capture_add_trace_func(struct gtp_bpf_capture_ctx *bcc)
{
	struct bpf_program *fentry_prg, *fexit_prg, *xprg;
	struct gtp_bpf_prog *p = bcc->p;
	struct bpf_map *map;
	char path[512];
	char *d;
	int ret;

	if (bcc->tr_obj != NULL)
		return 0;

	/* retrieve directory from bpf-prog path */
	d = strrchr(p->path, '/');
	if (d == NULL)
		return -1;
	*d = 0;
	snprintf(path, sizeof (path), "%s/capture_trace.bpf", p->path);
	*d = '/';

	/* open our special trace bpf program */
	bcc->tr_obj = bpf_object__open_file(path, NULL);
	if (bcc->tr_obj == NULL) {
		syslog(LOG_NOTICE, "%s: cannot open: %m", path);
		return 0;
	}

	/* locate the fentry and fexit functions */
	fentry_prg = bpf_object__find_program_by_name(bcc->tr_obj, "entry_trace");
	if (!fentry_prg) {
		syslog(LOG_ERR, "Can't find XDP trace fentry function!");
		goto err;
	}
	fexit_prg = bpf_object__find_program_by_name(bcc->tr_obj, "exit_trace");
	if (!fexit_prg) {
		syslog(LOG_ERR, "Can't find XDP trace fexit function!");
		goto err;
	}
	bpf_program__set_expected_attach_type(fentry_prg, BPF_TRACE_FENTRY);
	bpf_program__set_expected_attach_type(fexit_prg, BPF_TRACE_FEXIT);

	/* attach to the running xdp program */
	ret = gtp_bpf_lookup_program(p->obj_run, &xprg, BPF_XDP, p->name,
				     p->xdp_progname, "");
	if (ret < 0 || xprg == NULL) {
		syslog(LOG_INFO, "Can't find program in running bfp %s!", p->name);
		goto err;
	}
	bpf_program__set_attach_target(fentry_prg, bpf_program__fd(xprg),
				       bpf_program__name(xprg));
	bpf_program__set_attach_target(fexit_prg, bpf_program__fd(xprg),
				       bpf_program__name(xprg));

	/* config map */
	bcc->iface_map = bpf_object__find_map_by_name(bcc->tr_obj,
						      "capture_iface_entries");
	bcc->cfg_map = bpf_object__find_map_by_name(bcc->tr_obj,
						    "capture_prog_entry");
	if (bcc->iface_map == NULL || bcc->cfg_map == NULL)
		goto err;

	/* reuse perf map from running program, if it exists */
	map = bpf_object__find_map_by_name(bcc->tr_obj, "capture_perf_map");
	if (bcc->perf_map == NULL)
		bcc->perf_map = map;
	else
		bpf_map__reuse_fd(map, bpf_map__fd(bcc->perf_map));

	/* load obj */
	ret = bpf_object__load(bcc->tr_obj);
	if (ret) {
		syslog(LOG_ERR, "%s: cannot load: %m", p->path);
		goto err;
	}

	bcc->fentry_lnk = bpf_program__attach_trace(fentry_prg);
	if (bcc->fentry_lnk == NULL) {
		syslog(LOG_ERR, "%s: cannot attach: %m", p->path);
		goto err;
	}
	bcc->fexit_lnk = bpf_program__attach_trace(fexit_prg);
	if (bcc->fexit_lnk == NULL) {
		syslog(LOG_ERR, "%s: cannot attach: %m", p->path);
		goto err;
	}

	return 0;

 err:
	bpf_object__close(bcc->tr_obj);
	bcc->tr_obj = NULL;
	return -1;
}


static void
_trace_map_prg_entry_update(struct gtp_bpf_capture_ctx *bcc)
{
	uint32_t idx = 0;
	int ret;

	ret = bpf_map__update_elem(bcc->cfg_map, &idx, sizeof (idx),
				   &bcc->prg_entry, sizeof (bcc->prg_entry), 0);
	if (ret)
		printf("update map{capture_cfg}: %m\n");
}

int
gtp_capture_start_all(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
		      const char *name)
{
	struct gtp_bpf_capture_ctx *bcc;

	e->flags |= GTP_CAPTURE_FL_USE_TRACEFUNC;
	if (gtp_capture_start(e, p, name) < 0)
		return -1;

	bcc = e->bcc;
	bcc->prg_entry.flags |= e->flags & GTP_CAPTURE_FL_DIRECTION_MASK;
	bcc->prg_entry.entry_id = e->entry_id;
	bcc->prg_entry.cap_len = e->cap_len;
	_trace_map_prg_entry_update(bcc);

	return 0;
}

int
gtp_capture_start_iface(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
			const char *name, int iface)
{
	struct gtp_bpf_capture_ctx *bcc;
	struct capture_bpf_entry be;
	int ret;

	e->flags |= GTP_CAPTURE_FL_USE_TRACEFUNC;
	if (gtp_capture_start(e, p, name) < 0)
		return -1;

	bcc = e->bcc;
	be.flags = e->flags & GTP_CAPTURE_FL_DIRECTION_MASK;
	be.entry_id = e->entry_id;
	be.cap_len = e->cap_len;
	ret = bpf_map__update_elem(bcc->iface_map, &iface, sizeof (iface),
				   &be, sizeof (be), 0);
	if (ret)
		printf("update map{capture_iface}: %m\n");

	if (!(bcc->prg_entry.flags & BPF_CAPTURE_EFL_BY_IFACE)) {
		bcc->prg_entry.flags |= BPF_CAPTURE_EFL_BY_IFACE;
		_trace_map_prg_entry_update(bcc);
	}

	printf("%s: capture started on ifindex %d\n", e->cf->filename, iface);

	return 0;
}



/********************************************************************/
/* capture api */

/* capture packet from userspace */
void
gtp_capture_pkt(struct gtp_capture_entry *e, const void *data, size_t len,
		uint16_t flags)
{
	struct gtp_capture_file *cf = e->cf;
	struct xpcapng_epb_options_s options = {};
	struct timespec ts;
	uint64_t ns;
	uint32_t caplen;

	if (!cf->running)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);
	ns = ts.tv_sec + ts.tv_nsec * NSEC_PER_SEC ;
	caplen = min(e->cap_len, cf->snaplen);
	++cf->cpu_packet_id[cf->cpu_packet_id_n];

	options.flags = flags & GTP_CAPTURE_FL_INPUT ?
		PCAPNG_EPB_FLAG_INBOUND : PCAPNG_EPB_FLAG_OUTBOUND;
	options.dropcount = 0;
	options.packetid = &cf->cpu_packet_id[cf->cpu_packet_id_n];

	int if_idx = 0;
	/* XXX: set if_idx to xpcapng_add_interface index */

	xpcapng_dump_enhanced_pkt(cf->pcapng, if_idx, data,
				  len, caplen, ns, &options);

	cf->pkt_count++;
	if ((cf->pkt_max && cf->pkt_count >= cf->pkt_max) ||
	    (cf->until && ns / NSEC_PER_SEC > cf->until)) {
		printf("stopping capture, pkt: %d/%d, expired:%s (ref:%d)\n",
		       cf->pkt_count, cf->pkt_max,
		       cf->until && ns / NSEC_PER_SEC > cf->until ? "yes" : "no",
		       cf->refcnt);
		cf->running = false;
	}
}

int
gtp_capture_start(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
		  const char *name)
{
	struct gtp_bpf_capture_ctx *tmp_bcc, *bcc = NULL;
	struct capture_perf_buf_cpu *pbc;
	struct gtp_capture_file *cf;
	int i;

	/* already started */
	if (e->bcc != NULL)
		return 0;
	e->entry_id = 0;
	e->cf = NULL;
	e->cap_len = e->cap_len ?: cfg_capture_snaplen;

	/* no specified direction */
	if (!(e->flags & 0x000f)) {
		errno = EINVAL;
		return -1;
	}
	if (!(e->flags & GTP_CAPTURE_FL_SIDE_MASK))
		e->flags |= GTP_CAPTURE_FL_SIDE_MASK;
	if (!(e->flags & GTP_CAPTURE_FL_DIRECTION_MASK))
		e->flags |= GTP_CAPTURE_FL_DIRECTION_MASK;

	/* bpf program must be running */
	if (p->obj_run == NULL)
		return -1;

	/* get or create context associated to bpf program */
	list_for_each_entry(tmp_bcc, &bcc_list, list) {
		if (tmp_bcc->p == p) {
			bcc = tmp_bcc;
			break;
		}
	}
	if (bcc == NULL) {
		bcc = calloc(1, sizeof (*bcc));
		bcc->p = p;
		bcc->perf_map = bpf_object__find_map_by_name(p->obj_run,
							     "capture_perf_map");
		list_add(&bcc->list, &bcc_list);

	} else if (bcc->ae_n == CAPTURE_BPF_MAX_ENTRY) {
		 /* max running capture */
		return -1;
	}
	e->bcc = bcc;

	/* link entry and capture file */
	cf = capture_file_get(name, true);
	if (cf == NULL || capture_file_start(cf, p) < 0)
		goto err;
	e->cf = cf;

	/* link entry and bpf-program capture context */
	for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++)
		if (bcc->ae[i] == NULL)
			break;
	bcc->ae[i] = e;
	e->entry_id = i + 1;
	e->flags |= GTP_CAPTURE_FL_NEED_BPF_UPDATE;
	++bcc->ae_n;

	/* add fentry/fexit trace */
	if (e->flags & GTP_CAPTURE_FL_USE_TRACEFUNC)
		if (capture_add_trace_func(bcc))
			goto err;

	/* perf buffer already created */
	if (bcc->pb != NULL)
		goto opened;

	if (bcc->perf_map == NULL) {
		printf("cannot find bpf map 'capture_perf_map'\n");
		goto err;
	}

	/* create perf buffer */
	struct perf_event_attr perf_attr = {
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.wakeup_events = cfg_wakeup_events,
	};
	bcc->pb = perf_buffer__new_raw(bpf_map__fd(bcc->perf_map),
				       PERF_BUFFER_PAGES,
				       &perf_attr, capture_handle_perf_event,
				       bcc, NULL);
	if (bcc->pb == NULL) {
		fprintf(stderr, "Failed to open perf buffer: %m\n");
		goto err;
	}

	/* there is one perf buffer per cpu, each have its own fd */
	bcc->apbc = calloc(perf_buffer__buffer_cnt(bcc->pb), sizeof (*bcc->apbc));
	for (i = 0; i < perf_buffer__buffer_cnt(bcc->pb); i++) {
		pbc = &bcc->apbc[i];
		pbc->t = thread_add_read(master, capture_perf_io_read, pbc,
					 perf_buffer__buffer_fd(bcc->pb, i),
					 TIMER_NEVER, 0);
		pbc->pb = bcc->pb;
		pbc->cpu = i;
	}

 opened:
	if (e->opened_cb != NULL)
		e->opened_cb(e->cb_ud, e);

	return 0;

 err:
	gtp_capture_stop(e);
	return -1;
}

void
gtp_capture_stop(struct gtp_capture_entry *e)
{
	struct gtp_bpf_capture_ctx *bcc = e->bcc;
	struct gtp_capture_file *cf;
	int i;

	if (bcc == NULL)
		return;

	if (e->cf != NULL) {
		cf = e->cf;
		e->cf = NULL;
		capture_file_put(cf);
	}
	if (e->entry_id) {
		bcc->ae[e->entry_id - 1] = NULL;
		--bcc->ae_n;
		e->flags |= GTP_CAPTURE_FL_NEED_BPF_UPDATE;
		if (e->closed_cb != NULL)
			e->closed_cb(e->cb_ud, e);
	}
	e->bcc = NULL;

	if (bcc->ae_n)
		return;

	if (bcc->fentry_lnk)
		bpf_link__destroy(bcc->fentry_lnk);
	if (bcc->fexit_lnk)
		bpf_link__destroy(bcc->fexit_lnk);
	if (bcc->tr_obj != NULL)
		bpf_object__close(bcc->tr_obj);

	if (bcc->pb != NULL) {
		for (i = 0; i < perf_buffer__buffer_cnt(bcc->pb); i++)
			thread_del(bcc->apbc[i].t);
		free(bcc->apbc);
		perf_buffer__free(bcc->pb);
	}
	list_del(&bcc->list);
	free(bcc);
}

int
gtp_capture_init(void)
{
	struct timespec ts;
	uint64_t epoch, uptime;

	snprintf(cfg_pcap_path, sizeof (cfg_pcap_path), "/tmp");
	cfg_wakeup_events = 64;

	/* get delta from monotonic to realtime to add in each packet-pcap */
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		printf("ERROR: Failed to get CLOCK_MONOTONIC time: %m\n");
		return -errno;
	}
	epoch = time(NULL) * 1000000000ULL;
	uptime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	epoch_delta = epoch - uptime;

	flush_ev = thread_add_timer(master, capture_timer_flush,
				    NULL, TIMER_HZ);

	return 0;
}

void
gtp_capture_release(void)
{
	struct gtp_bpf_capture_ctx *bcc, *bcc_tmp;
	struct gtp_capture_file *cf, *cf_tmp;
	struct gtp_capture_entry e = {};

	thread_del(flush_ev);

	/* force bpf-prog context release */
	list_for_each_entry_safe(bcc, bcc_tmp, &bcc_list, list) {
		bcc->ae_n = 0;
		e.bcc = bcc;
		gtp_capture_stop(&e);
	}

	list_for_each_entry_safe(cf, cf_tmp, &cfile_list, list) {
		capture_file_stop(cf);
		free(cf->cpu_packet_id);
		free(cf);
	}
}


/********************************************************************/
/* Vty */

DEFUN(capture_file_set,
      capture_file_set_cmd,
      "capture file NAME set [TIME MAXPKT FILENAME]",
      "Capture menu\n"
      "Capture file submenu\n"
      "Capture file entry name\n"
      "Add a new capture\n"
      "Delete existing capture\n"
      "Update existing capture\n"
      "Time in second before stopping capture (default: 0, unlimited)\n"
      "Packets to write before stopping capture (default: 0, unlimited)\n"
      "Pcap filename to write into\n")
{
	struct gtp_capture_file *cf;

	cf = capture_file_get(argv[0], true);
	if (cf == NULL) {
		vty_out(vty, "%% cannot get capture file %s\n", argv[0]);
		return CMD_WARNING;
	}

	if (argc > 2)
		cf->duration = atoi(argv[1]);
	if (argc > 3)
		cf->pkt_max = atoi(argv[2]);
	if (argc > 4)
		snprintf(cf->filename, sizeof (cf->filename), "%s", argv[3]);

	cf->persist = true;
	capture_file_put(cf);

	return CMD_SUCCESS;
}

DEFUN(capture_file_del,
      capture_file_del_cmd,
      "capture file NAME del",
      "Capture menu\n"
      "Capture file submenu\n"
      "Capture file entry name\n"
      "Delete existing capture\n")
{
	struct gtp_capture_file *cf;

	cf = capture_file_get(argv[0], false);
	if (cf == NULL) {
		vty_out(vty, "%% Cannot get capture file %s\n", argv[0]);
		return CMD_WARNING;
	}

	cf->refcnt = 1;
	capture_file_stop(cf);
	cf->persist = false;
	capture_file_put(cf);

	return CMD_SUCCESS;
}

DEFUN(capture_file_show,
      capture_file_show_cmd,
      "capture file NAME show",
      "Capture menu\n"
      "Capture file submenu\n"
      "Capture file entry name\n"
      "Show capture\n")
{
	struct gtp_capture_file *cf;
	struct gtp_bpf_capture_ctx *bcc;
	char pathname[400];
	int i;

	cf = capture_file_get(argv[0], false);
	if (cf == NULL) {
		vty_out(vty, "%% Cannot get capture file %s\n", argv[0]);
		return CMD_WARNING;
	}

	vty_out(vty, "name         : %s\n", cf->name);
	if (*cf->filename) {
		if (strcmp(cf->name, cf->filename))
			vty_out(vty, "filename     : %s\n", cf->filename);
		snprintf(pathname, sizeof (pathname), "%s/%s.pcap",
			 cfg_pcap_path, cf->filename);
		vty_out(vty, "pathname     : %s\n", pathname);
	}
	vty_out(vty, "status       : %s\n", cf->running ? "running" : "closed");
	if (cf->running) {
		vty_out(vty, "packet count : %d / %d\n",
			cf->pkt_count, cf->pkt_max);
		if (cf->until) {
			vty_out(vty, "remaining  : %ld seconds\n",
				cf->until - time(NULL));
		}
	}
	if (cf->refcnt == 1)
		goto out;

	vty_out(vty, "referenced by %d capture entries:\n", cf->refcnt - 1);
	list_for_each_entry(bcc, &bcc_list, list) {
		for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++) {
			if (bcc->ae[i] != NULL && bcc->ae[i]->cf == cf)
				vty_out(vty, "  - %s:%d\n",
					bcc->p->name, i);
		}
	}

 out:
	capture_file_put(cf);
	return CMD_SUCCESS;
}



DEFUN(capture_set_record_path,
      capture_set_record_path_cmd,
      "capture set record-path PATH",
      "Capture menu\n")
{
	snprintf(cfg_pcap_path, sizeof (cfg_pcap_path), argv[0]);

	return CMD_SUCCESS;
}

DEFUN(capture_set_snaplen,
      capture_set_snaplen_cmd,
      "capture set snaplen <32-65535>",
      "Capture menu\n")
{
	VTY_GET_INTEGER_RANGE("Capture length", cfg_capture_snaplen, argv[0], 32, 65535);

	return CMD_SUCCESS;
}

DEFUN(capture_set_wakeup_events,
      capture_set_wakeup_events_cmd,
      "capture set wakeup-events <1-128>",
      "Capture menu\n")
{
	VTY_GET_INTEGER_RANGE("Wakeup events", cfg_wakeup_events, argv[0], 1, 128);

	return CMD_SUCCESS;
}


DEFUN(capture_show,
      capture_show_cmd,
      "show capture",
      "show\n"
      "capture\n")
{
	struct gtp_capture_file *cf;
	struct gtp_bpf_capture_ctx *bcc;
	int i;

	list_for_each_entry(bcc, &bcc_list, list) {
		vty_out(vty, "bpf-prog %s:\n", bcc->p->name);
		for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++) {
			if (bcc->ae[i] == NULL)
				continue;
			cf = bcc->ae[i]->cf;
			vty_out(vty, " - %d %s\n",
				i, cf ? cf->filename : "<closed>");
		}
	}

	return CMD_SUCCESS;
}


DEFUN(capture_show_file,
      capture_show_file_cmd,
      "show capture file",
      "show\n"
      "capture\n"
      "name\n")
{
	struct gtp_capture_file *cf;
	struct table *tbl;

	tbl = table_init(6, STYLE_SINGLE_LINE_ROUNDED);
	table_set_column(tbl, "Name", "Filename", "Refcnt",
			 "Time", "Packets", "Interface");
	table_set_header_align(tbl, ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER,
			       ALIGN_CENTER, ALIGN_CENTER, ALIGN_CENTER);

	list_for_each_entry(cf, &cfile_list, list) {
		table_add_row_fmt(tbl, "%s|%s|%d|%ld|%d/%d|%s",
				  cf->name, cf->filename, cf->refcnt,
				  cf->until, cf->pkt_count, cf->pkt_max,
				  "itf");
	}

	table_vty_out(tbl, vty);
	table_destroy(tbl);

	return CMD_SUCCESS;
}


static int
cmd_ext_capture_install(void)
{
	install_element(ENABLE_NODE, &capture_file_set_cmd);
	install_element(ENABLE_NODE, &capture_file_del_cmd);
	install_element(ENABLE_NODE, &capture_file_show_cmd);
	install_element(ENABLE_NODE, &capture_set_record_path_cmd);
	install_element(ENABLE_NODE, &capture_set_snaplen_cmd);
	install_element(ENABLE_NODE, &capture_set_wakeup_events_cmd);
	install_element(ENABLE_NODE, &capture_show_cmd);
	install_element(ENABLE_NODE, &capture_show_file_cmd);

	return 0;
}

static struct cmd_ext cmd_ext_capture = {
	.install = cmd_ext_capture_install,
};

static void __attribute__((constructor))
gtp_bpf_capture_init(void)
{
	cmd_ext_register(&cmd_ext_capture);
}

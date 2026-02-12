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
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/pcap.h>
#include <pcap/dlt.h>
#include <linux/perf_event.h>
#include <libbpf.h>

#include "utils.h"
#include "command.h"
#include "table.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_capture.h"
#include "bpf/lib/capture-def.h"


#define PERF_BUFFER_PAGES		16

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
	struct gtp_capture_ctx		*cc;
	struct gtp_bpf_prog		*p;

	struct gtp_capture_entry	*ae[CAPTURE_BPF_MAX_ENTRY];
	int				ae_n;

	/* perf buffer to send packet data to userspace */
	struct bpf_map			*perf_map;
	struct perf_buffer		*pb;
	struct capture_perf_buf_cpu	*apbc;
	uint64_t			missed_events;

	/* trace program */
	struct capture_trace_cfg	cfg;
	struct bpf_map			*cfg_map;
	struct bpf_map			*iface_map;
	struct bpf_object		*tr_obj;
};

/* capture_file. may be referenced by 0 to many capture_entry */
struct gtp_capture_file
{
	char				name[32];
	char				filename[64];
	pcap_t				*pcap;
	pcap_dumper_t			*pdump;
	int				refcnt;
	bool				running;

	uint32_t			pkt_count;
	uint32_t			pkt_max;
	time_t				until;

	struct list_head		list;
};

struct gtp_capture_ctx
{
	/* config */
	char				pcap_path[256];
	uint64_t			epoch_delta;

	/* opened pcap files */
	struct list_head		cfile_list;
	struct thread			*flush_ev;

	/* running bpf-program */
	struct list_head		bcc_list;
};


/* Extern data */
extern struct thread_master *master;

/* locals */
static struct gtp_capture_ctx *cc;


static struct gtp_capture_file *
capture_file_get(const char *name, bool alloc)
{
	struct gtp_capture_file *cf;

	list_for_each_entry(cf, &cc->cfile_list, list) {
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
	list_add_tail(&cf->list, &cc->cfile_list);
	cf->refcnt = 1;

	return cf;
}

static int
capture_file_open(struct gtp_capture_file *cf)
{
	char pathname[400];

	if (!*cf->filename)
		snprintf(cf->filename, sizeof (cf->filename), "%s", cf->name);
	snprintf(pathname, sizeof (pathname), "%s/%s.pcap",
		 cc->pcap_path, cf->filename);

	/* open pcap */
	cf->pcap = pcap_open_dead(DLT_EN10MB, 65535);
	if (cf->pcap == NULL) {
		printf("could not open dead\n");
		return -1;
	}
	cf->pdump = pcap_dump_open(cf->pcap, pathname);
	if (cf->pdump == NULL) {
		printf("%s\n", pcap_geterr(cf->pcap));
		pcap_close(cf->pcap);
		cf->pcap = NULL;
		return -1;
	}
	cf->running = true;

	return 0;
}

static void
capture_file_put(struct gtp_capture_file *cf)
{
	if (--cf->refcnt)
		return;
	if (cf->pdump) {
		pcap_dump_close(cf->pdump);
		pcap_close(cf->pcap);
	}
	printf("%s.pcap: capture file closed, wrote %d packets\n",
	       cf->filename, cf->pkt_count);
	list_del(&cf->list);
	free(cf);
}


static void
capture_timer_flush(struct thread *thread)
{
	struct gtp_capture_ctx *cc = THREAD_ARG(thread);
	struct gtp_capture_file *cf;

	list_for_each_entry(cf, &cc->cfile_list, list) {
		if (cf->until && time(NULL) > cf->until)
			cf->running = false;
		pcap_dump_flush(cf->pdump);
	}

	cc->flush_ev = thread_add_timer(master, capture_timer_flush, cc, TIMER_HZ);
}

#if 0
static struct gtp_bpf_capture_ctx *
capture_ctx_get_by_bpf_prog(struct gtp_bpf_prog	*p)
{
	struct gtp_bpf_capture_ctx *bcc;

	list_for_each_entry(bcc, &cc->bcc_list, list)
		if (bcc->p == p)
			return bcc;
	return NULL;
}
#endif


static int
capture_add_trace_func(struct gtp_bpf_capture_ctx *bcc)
{
	struct bpf_program *fentry_prg, *fexit_prg, *xprg;
	struct bpf_link *fentry_lnk, *fexit_lnk;
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
	bcc->iface_map = bpf_object__find_map_by_name(bcc->tr_obj, "capture_iface");
	bcc->cfg_map = bpf_object__find_map_by_name(bcc->tr_obj, "capture_cfg");
	if (bcc->iface_map == NULL || bcc->cfg_map == NULL)
		return 1;

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
		return -1;
	}

	fentry_lnk = bpf_program__attach_trace(fentry_prg);
	if (fentry_lnk == NULL) {
		syslog(LOG_ERR, "%s: cannot attach: %m", p->path);
		return -1;
	}
	fexit_lnk = bpf_program__attach_trace(fexit_prg);
	if (fexit_lnk == NULL) {
		syslog(LOG_ERR, "%s: cannot attach: %m", p->path);
		return -1;
	}

	return 0;

 err:
	bpf_object__close(bcc->tr_obj);
	bcc->tr_obj = NULL;
	return -1;
}


struct perf_sample_raw
{
	struct perf_event_header header;
	uint64_t time;
	uint32_t size;
	struct capture_metadata metadata;
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
	struct pcap_pkthdr h;
	uint64_t ts;

	if (event->type == PERF_RECORD_LOST) {
		lost = container_of(event, struct perf_sample_lost, header);
		bcc->missed_events += lost->lost;
		return LIBBPF_PERF_EVENT_CONT;
	}

	if (event->type != PERF_RECORD_SAMPLE)
		return LIBBPF_PERF_EVENT_CONT;

	e = container_of(event, struct perf_sample_raw, header);
	if (e->header.size < sizeof(struct perf_sample_raw) ||
	    e->size < (sizeof (struct capture_metadata) + e->metadata.cap_len))
		return LIBBPF_PERF_EVENT_CONT;

	ce = bcc->ae[e->metadata.entry_id - 1];
	if (ce == NULL || ce->cf == NULL || !ce->cf->running)
		return LIBBPF_PERF_EVENT_CONT;
	cf = ce->cf;

	ts = e->time + cc->epoch_delta;
	memset(&h, 0x00, sizeof (h));
	h.ts.tv_sec = ts / 1000000000ULL;
	h.ts.tv_usec = ts % 1000000000ULL / 1000;
	h.caplen = e->metadata.cap_len;
	h.len = e->metadata.pkt_len;

	pcap_dump((u_char *)cf->pdump, &h, e->packet);

	cf->pkt_count++;
	if ((cf->pkt_max && cf->pkt_count >= cf->pkt_max) ||
	    (cf->until && h.ts.tv_sec > cf->until)) {
		printf("stopping capture, pkt: %d/%d, expired:%s (ref:%d)\n",
		       cf->pkt_count, cf->pkt_max,
		       cf->until && h.ts.tv_sec > cf->until ? "yes" : "no",
		       cf->refcnt);
		cf->running = false;
	}

	return LIBBPF_PERF_EVENT_CONT;
}


/* callback called by thread, when there is something to read on perf buffer's fd.
 * libbpf will handle data and then will call handle_event. */
static void
capture_perf_io_read(struct thread *t)
{
	struct capture_perf_buf_cpu *pbc = THREAD_ARG(t);
	int ret;

	ret = perf_buffer__consume_buffer(pbc->pb, pbc->cpu);
	if (ret)
		fprintf(stderr, "perf comsume buffer: %m\n");

	pbc->t = thread_add_read(master, capture_perf_io_read, pbc,
				 THREAD_FD(t), TIMER_NEVER, 0);
}


int
gtp_capture_start(struct gtp_capture_entry *e, struct gtp_bpf_prog *p,
		  const char *name)
{
	struct gtp_bpf_capture_ctx *tmp_bcc, *bcc = NULL;
	struct capture_perf_buf_cpu *pbc;
	struct gtp_capture_file *cf;
	int fd, i;

	/* already started */
	if (e->bcc != NULL)
		return 0;
	e->entry_id = 0;
	e->cf = NULL;

	/* bpf program must be running */
	if (p->obj_run == NULL)
		return -1;

	/* get or create context associated to bpf program */
	list_for_each_entry(tmp_bcc, &cc->bcc_list, list) {
		if (tmp_bcc->p == p) {
			bcc = tmp_bcc;
			break;
		}
	}
	if (bcc == NULL) {
		bcc = calloc(1, sizeof (*bcc));
		bcc->cc = cc;
		bcc->p = p;
		bcc->perf_map = bpf_object__find_map_by_name(p->obj_run,
							     "capture_perf_map");
		list_add(&bcc->list, &cc->bcc_list);

	} else if (bcc->ae_n == CAPTURE_BPF_MAX_ENTRY) {
		 /* max running capture */
		return -1;
	}
	e->bcc = bcc;

	/* link entry and capture file */
	cf = capture_file_get(name, true);
	if (cf == NULL || capture_file_open(cf) < 0)
		goto err;
	e->cf = cf;

	/* link entry and bpf-program capture context */
	for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++)
		if (bcc->ae[i] == NULL)
			break;
	bcc->ae[i] = e;
	e->entry_id = i + 1;
	++bcc->ae_n;

	/* add fentry/fexit trace */
	if (e->flags & GTP_CAPTURE_FL_USE_TRACEFUNC)
		if (capture_add_trace_func(bcc))
			goto err;

	if (bcc->perf_map == NULL) {
		printf("cannot find bpf map 'capture_perf_map'\n");
		goto err;
	}

	/* create perf buffer */
	struct perf_event_attr perf_attr = {
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.sample_period = 1,
		.wakeup_events = 1,	/* XXX: set to more (64,128), with poll mode */
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
		fd = perf_buffer__buffer_fd(bcc->pb, i);
		pbc = &bcc->apbc[i];
		pbc->t = thread_add_read(master, capture_perf_io_read, pbc,
					 fd, TIMER_NEVER, 0);
		pbc->pb = bcc->pb;
		pbc->cpu = i;
	}


	return 0;

 err:
	gtp_capture_stop(e);
	return -1;
}

void
gtp_capture_stop(struct gtp_capture_entry *e)
{
	struct gtp_bpf_capture_ctx *bcc = e->bcc;
	int i;

	if (bcc == NULL)
		return;

	if (e->cf != NULL) {
		capture_file_put(e->cf);
		e->cf = NULL;
	}
	if (e->entry_id) {
		bcc->ae[e->entry_id - 1] = NULL;
		--bcc->ae_n;
	}
	e->bcc = NULL;

	if (bcc->ae_n)
		return;

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

static void
_trace_cfg_update(struct gtp_bpf_capture_ctx *bcc)
{
	uint32_t idx = 0;
	int ret;

	ret = bpf_map__update_elem(bcc->cfg_map, &idx, sizeof (idx),
				   &bcc->cfg, sizeof (bcc->cfg), 0);
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
	bcc->cfg.flags |= e->flags & GTP_CAPTURE_FL_DIRECTION_MASK;
	bcc->cfg.entry_id = e->entry_id;
	bcc->cfg.cap_len = e->cap_len ? e->cap_len : GTP_CAPTURE_DEFAULT_CAPLEN;
	_trace_cfg_update(bcc);

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
	be.cap_len = e->cap_len ? e->cap_len : GTP_CAPTURE_DEFAULT_CAPLEN;
	ret = bpf_map__update_elem(bcc->iface_map, &iface, sizeof (iface),
				   &be, sizeof (be), 0);
	if (ret)
		printf("update map{capture_iface}: %m\n");

	if (!(bcc->cfg.flags & BPF_CAPTURE_CFG_FL_BY_IFACE)) {
		bcc->cfg.flags |= BPF_CAPTURE_CFG_FL_BY_IFACE;
		_trace_cfg_update(bcc);
	}

	return 0;
}


int
gtp_capture_init(void)
{
	struct timespec ts;
	uint64_t epoch, uptime;

	if (cc != NULL)
		return 0;

	cc = calloc(1, sizeof (*cc));
	if (cc == NULL)
		return -1;
	snprintf(cc->pcap_path, sizeof (cc->pcap_path), "/tmp");

	/* get delta from monotonic to realtime to add in each packet-pcap */
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		printf("ERROR: Failed to get CLOCK_MONOTONIC time: %m\n");
		return -errno;
	}
	epoch = time(NULL) * 1000000000ULL;
	uptime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	cc->epoch_delta = epoch - uptime;

	INIT_LIST_HEAD(&cc->cfile_list);
	cc->flush_ev = thread_add_timer(master, capture_timer_flush, cc, TIMER_HZ);

	INIT_LIST_HEAD(&cc->bcc_list);

	return 0;
}

void
gtp_capture_release(void)
{
	thread_del(cc->flush_ev);
	free(cc);
	cc = NULL;
}


/* Vty */
DEFUN(capture_manage,
      capture_manage_cmd,
      "capture file NAME (add|del|update) [TIME MAXPKT FILENAME]",
      "Capture packets in pcap\n"
      "Add a new capture\n"
      "Delete existing capture\n"
      "Show current captures\n"
      "Time in second before stopping capture (default: 0, unlimited)\n"
      "Packets to write before stopping capture (default: 0, unlimited)\n"
      "Capture on both xdp ingress and egress side\n"
      "Capture on both xdp side, write in 2 differents pcap\n"
      "Capture on xdp ingress side\n"
      "Capture on xdp egress side\n"
      "Pcap filename to write into\n")
{
	struct gtp_capture_file *cf;
	bool add = !strcmp(argv[0], "add");

	cf = capture_file_get(argv[1], add);
	if (cf == NULL) {
		vty_out(vty, "%% cannot get capture file %s\n", argv[1]);
		return CMD_WARNING;
	}

	if (argc > 3)
		cf->until = time(NULL) + atoi(argv[2]);
	if (argc > 4)
		cf->pkt_max = atoi(argv[3]);
	if (argc > 5)
		snprintf(cf->filename, sizeof (cf->filename), "%s", argv[4]);

	return CMD_SUCCESS;
}


DEFUN(capture_set_cfg,
      capture_set_cfg_cmd,
      "capture set record-path PATH",
      "Capture menu\n")
{
	snprintf(cc->pcap_path, sizeof (cc->pcap_path), argv[0]);

	return CMD_SUCCESS;
}


DEFUN(capture_show,
      capture_show_cmd,
      "show capture [NAME]",
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

	list_for_each_entry(cf, &cc->cfile_list, list) {
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
	install_element(ENABLE_NODE, &capture_manage_cmd);
	install_element(ENABLE_NODE, &capture_set_cfg_cmd);
	install_element(ENABLE_NODE, &capture_show_cmd);

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

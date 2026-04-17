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
#include <time.h>
#include <assert.h>
#include <sys/types.h>
#include <dirent.h>
#include <linux/perf_event.h>
#include <libbpf.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "xpcapng.h"
#include "utils.h"
#include "logger.h"
#include "inet_utils.h"
#include "command.h"
#include "config.h"
#include "gtp_interface.h"
#include "gtp_bpf_prog.h"
#include "gtp_bpf_capture.h"
#include "bpf/lib/capture-def.h"


#define PERF_BUFFER_PAGES		256

/* set max number of running captures per bpf program */
#define CAPTURE_BPF_MAX_ENTRY		8

/* max number of interfaces in pcap file */
#define CAPTURE_BPF_MAX_INTERFACE	100


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
	bool				is_tpl;

	/* capturing items */
	struct gtp_capture_entry	*ae[CAPTURE_BPF_MAX_ENTRY];
	int				ae_n;

	/* perf buffer to send packet data to userspace */
	struct bpf_map			*perf_map;
	struct perf_buffer		*pb;
	struct capture_perf_buf_cpu	*apbc;
	struct thread			*flush_ev;
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
	struct thread			*flush_ev;
	int				refcnt;
	bool				running;
	bool				persist;

	uint32_t			pkt_max;
	uint32_t			duration;	/* in seconds */
	uint32_t			pkt_count;
	time_t				until;
	uint64_t			*cpu_packet_id;
	int				cpu_packet_id_n;
	uint64_t			*if2itfidx;
	uint32_t			if2itfidx_mask;

	struct list_head		list;
};


/* Extern data */
extern struct thread_master *master;

/* config and local data */
static char cfg_pcap_path[256];
static int cfg_rotate_file = 5;
static int cfg_wakeup_events = 64;
static uint16_t cfg_capture_snaplen = GTP_CAPTURE_DEFAULT_SNAPLEN;
static uint64_t epoch_delta;
static LIST_HEAD(cfile_list);		/* opened pcap files */
static LIST_HEAD(bcc_list);		/* running bpf-prog */

/* local forward declaration */
static struct gtp_bpf_capture_ctx *_alloc_bpf_ctx(struct gtp_bpf_prog *p, bool);


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
capture_perf_event(void *ctx, int cpu, struct perf_event_header *event)
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

	int itf_idx;
	uint32_t idx = e->md.ifindex & cf->if2itfidx_mask;
	while (cf->if2itfidx[idx] && (cf->if2itfidx[idx] >> 32) != e->md.ifindex)
		idx = (idx + 1) & cf->if2itfidx_mask;
	itf_idx = cf->if2itfidx[idx] ? cf->if2itfidx[idx] & 0xffffffff : 0;

	struct iovec pkt_iov = {
		.iov_base = e->packet,
		.iov_len = min(e->md.cap_len, e->md.pkt_len)
	};
	xpcapng_dump_enhanced_pkt(cf->pcapng, itf_idx, &pkt_iov, 1,
				  e->md.pkt_len, e->md.cap_len, ts, &options);
	bcc->last_missed_events = 0;

	cf->pkt_count++;
	if ((cf->pkt_max && cf->pkt_count >= cf->pkt_max) ||
	    (cf->until && ts / NSEC_PER_SEC > cf->until)) {
		log_message(LOG_DEBUG, "stopping capture, pkt: %d/%d, expired:%s (ref:%d)",
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
		log_message(LOG_ERR, "%s: perf consume buffer: %m", __func__);
}

/* callback called by thread, when there is something to read on perf buffer's fd.
 * libbpf will handle data and then will call capture_perf_event() */
static void
capture_perf_io_read(struct thread *t)
{
	struct capture_perf_buf_cpu *pbc = THREAD_ARG(t);

	capture_perf_consume(pbc);
	pbc->t = thread_add_read(master, capture_perf_io_read, pbc,
				 THREAD_FD(t), TIMER_NEVER, 0);
}

static void
capture_perf_flush(struct thread *th)
{
	struct gtp_bpf_capture_ctx *bcc = THREAD_ARG(th);
	int i;

	for (i = 0; i < perf_buffer__buffer_cnt(bcc->pb); i++)
		capture_perf_consume(&bcc->apbc[i]);
	bcc->flush_ev = thread_add_timer(master, capture_perf_flush, bcc, TIMER_HZ);
}


/********************************************************************/
/* capture_file */

static void capture_file_flush(struct thread *th);


static int _filter(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

/* keep 'cfg_rotate_file' latest capture file, unlink olders */
static void
capture_file_rotate(struct gtp_capture_file *cf)
{
	char pathname[600];
	struct dirent *entry;
	char **fnlist = NULL;
	int fnlist_msize = cfg_rotate_file;
	int fnlist_n = 0;
	int flen, i, n;
	DIR *d;

	d = opendir(cfg_pcap_path);
	if (d == NULL)
		return;

	flen = strlen(cf->filename);
	cf->filename[flen] = '-';
	while ((entry = readdir(d)) != NULL) {
		if (strncmp(entry->d_name, cf->filename, flen + 1))
			continue;

		if (fnlist == NULL || fnlist_n == fnlist_msize) {
			fnlist_msize *= 2;
			fnlist = realloc(fnlist, fnlist_msize * sizeof (char *));
			if (fnlist == NULL)
				goto err;
		}
		fnlist[fnlist_n] = strdup(entry->d_name);
		if (fnlist[fnlist_n] == NULL)
			goto err;
		fnlist_n++;
	}

	qsort(fnlist, fnlist_n, sizeof (char *), _filter);

	n = max(0, fnlist_n - cfg_rotate_file + 1);
	for (i = 0; i < n; i++) {
		snprintf(pathname, sizeof (pathname), "%s/%s",
			 cfg_pcap_path, fnlist[i]);
		unlink(pathname);
	}

 err:
	cf->filename[flen] = 0;
	for (i = 0; i < fnlist_n; i++)
		free(fnlist[i]);
	free(fnlist);
	closedir(d);
}

static int
capture_file_start(struct gtp_capture_file *cf, struct gtp_bpf_prog *p)
{
	struct gtp_interface *iface;
	char pathname[600];
	char linkname[400];
	char ifname[200];
	struct tm date;
	time_t now;
	uint32_t k;

	if (cf->running)
		return 0;
	if (cf->p != NULL && cf->p != p)
		return -1;
	cf->p = p;

	/* set filename from name, if not set */
	if (!*cf->filename)
		snprintf(cf->filename, sizeof (cf->filename), "%s", cf->name);

	if (!cfg_rotate_file) {
		snprintf(pathname, sizeof (pathname), "%s/%s.pcap",
			 cfg_pcap_path, cf->filename);
	} else {
		/* filename with creation date */
		now = time(NULL);
		strftime(ifname, sizeof(ifname), "%y%m%d_%H%M%S",
			 localtime_r(&now, &date));
		snprintf(pathname, sizeof (pathname), "%s/%s-%s.pcap",
			 cfg_pcap_path, cf->filename, ifname);

		/* symlink to it */
		snprintf(linkname, sizeof (linkname), "%s/%s.pcap",
			 cfg_pcap_path, cf->filename);
		unlink(linkname);
		if (symlink(pathname, linkname) < 0)
			log_message(LOG_INFO, "symlink{%s}: %m", linkname);

		/* remove file after nth element */
		capture_file_rotate(cf);
	}

	/* open pcap */
	cf->pcapng = xpcapng_dump_open(pathname, NULL, NULL, NULL,
				       VERSION_STRING);
	if (cf->pcapng == NULL) {
		log_message(LOG_ERR, "Can't open PcapNG file for writing!");
		return -1;
	}

	/* interfaces are written in pcap file header. once written, it won't
	 * be modified. if a new interface is added to bpf_prog, then add it
	 * to special interface 'undefined' */
	snprintf(ifname, sizeof (ifname), "_undefined");
	if (xpcapng_dump_add_interface(cf->pcapng, cfg_capture_snaplen,
				       ifname, NULL, NULL, 0, 9, NULL) < 0) {
		log_message(LOG_ERR, "Can't add %s interface to PcapNG file!", ifname);
		goto err;
	}

	/* use this interface for all packets sent from userspace. do not limit
	 * capture size */
	snprintf(ifname, sizeof (ifname), "_protocol");
	if (xpcapng_dump_add_interface(cf->pcapng, ~0, ifname, NULL, NULL,
				       0, 9, NULL) < 0) {
		log_message(LOG_ERR, "Can't add %s interface to PcapNG file!", ifname);
		goto err;
	}

	/* add all current bpf_prog's interfaces */
	k = 2;
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		if (k >= CAPTURE_BPF_MAX_INTERFACE)
			break;
		snprintf(ifname, sizeof (ifname), "%s:%s",
			 p->name, iface->ifname);
		if (xpcapng_dump_add_interface(cf->pcapng,
					       cfg_capture_snaplen,
					       ifname, NULL, NULL,
					       0, 9, NULL) < 0) {
			log_message(LOG_ERR, "Can't add %s interface to PcapNG file!",
				    ifname);
			goto err;
		}
		uint32_t idx = iface->ifindex & cf->if2itfidx_mask;
		while (cf->if2itfidx[idx])
			idx = (idx + 1) & cf->if2itfidx_mask;
		cf->if2itfidx[idx] = ((uint64_t)iface->ifindex << 32ULL) | k++;
	}

	cf->pkt_count = 0;
	if (cf->duration)
		cf->until = time(NULL) + cf->duration;
	else
		cf->until = 0;

	cf->flush_ev = thread_add_timer(master, capture_file_flush, cf, TIMER_HZ);
	cf->running = true;
	log_message(LOG_DEBUG, "%s.pcap: capture file started", cf->filename);

	return 0;

 err:
	xpcapng_dump_close(cf->pcapng);
	cf->pcapng = NULL;
	return -1;
}

static void
capture_file_stop(struct gtp_capture_file *cf)
{
	struct gtp_bpf_capture_ctx *bcc;
	int i;

	if (!cf->running)
		return;

	/* force capture_stop() on each linked gtp_capture_entry */
	list_for_each_entry(bcc, &bcc_list, list) {
		for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++) {
			if (bcc->ae[i] != NULL && bcc->ae[i]->cf == cf)
				gtp_capture_stop(bcc->ae[i]);

		}
	}

	xpcapng_dump_close(cf->pcapng);
	thread_del(cf->flush_ev);
	cf->running = false;
	cf->p = NULL;
	log_message(LOG_DEBUG, "%s.pcap: capture file closed, wrote %d packets",
	       cf->filename, cf->pkt_count);
}

static struct gtp_capture_file *
capture_file_get(const char *name, bool alloc)
{
	struct gtp_capture_file *cf;
	uint32_t n;

	list_for_each_entry(cf, &cfile_list, list)
		if (!strcmp(cf->name, name))
			return cf;

	if (!alloc)
		return NULL;
	cf = calloc(1, sizeof (*cf));
	if (cf == NULL)
		return NULL;
	snprintf(cf->name, sizeof (cf->name), "%s", name);
	cf->cpu_packet_id_n = libbpf_num_possible_cpus();
	cf->cpu_packet_id = calloc(cf->cpu_packet_id_n + 1,
				   sizeof (*cf->cpu_packet_id));
	n = next_power_of_2(CAPTURE_BPF_MAX_INTERFACE + 4);
	cf->if2itfidx = calloc(n, sizeof (uint64_t));
	cf->if2itfidx_mask = n - 1;
	if (cf->cpu_packet_id == NULL || cf->if2itfidx == NULL) {
		free(cf->cpu_packet_id);
		free(cf);
		return NULL;
	}
	list_add_tail(&cf->list, &cfile_list);

	return cf;
}

static void
capture_file_destroy(struct gtp_capture_file *cf)
{
	capture_file_stop(cf);
	assert(cf->refcnt == 0);
	list_del(&cf->list);
	free(cf->if2itfidx);
	free(cf->cpu_packet_id);
	free(cf);
}

static struct gtp_capture_file *
capture_file_refinc(struct gtp_capture_file *cf)
{
	++cf->refcnt;
	return cf;
}

static void
capture_file_refdec(struct gtp_capture_file *cf)
{
	if (!--cf->refcnt) {
		if (cf->persist)
			capture_file_stop(cf);
		else
			capture_file_destroy(cf);
	}
}

static void
capture_file_flush(struct thread *th)
{
	struct gtp_capture_file *cf = THREAD_ARG(th);

	xpcapng_dump_flush(cf->pcapng);
	if (cf->until && time(NULL) > cf->until)
		capture_file_stop(cf);
	else
		cf->flush_ev = thread_add_timer(master, capture_file_flush,
						cf, TIMER_HZ);
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
		log_message(LOG_NOTICE, "%s: cannot open: %m", path);
		return 0;
	}

	/* locate the fentry and fexit functions */
	fentry_prg = bpf_object__find_program_by_name(bcc->tr_obj, "entry_trace");
	if (!fentry_prg) {
		log_message(LOG_ERR, "Can't find XDP trace fentry function!");
		goto err;
	}
	fexit_prg = bpf_object__find_program_by_name(bcc->tr_obj, "exit_trace");
	if (!fexit_prg) {
		log_message(LOG_ERR, "Can't find XDP trace fexit function!");
		goto err;
	}
	bpf_program__set_expected_attach_type(fentry_prg, BPF_TRACE_FENTRY);
	bpf_program__set_expected_attach_type(fexit_prg, BPF_TRACE_FEXIT);

	/* attach to the running xdp program */
	ret = gtp_bpf_lookup_program(p->obj_run, &xprg, BPF_XDP, p->name,
				     p->xdp_progname, "");
	if (ret < 0 || xprg == NULL) {
		log_message(LOG_INFO, "Can't find program in running bfp %s!",
			    p->name);
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
	if (bcc->perf_map == NULL) {
		if (map == NULL) {
			log_message(LOG_ERR, "cannot find perf_map");
			goto err;
		}
		if (bpf_map__set_max_entries(map, libbpf_num_possible_cpus())) {
			log_message(LOG_ERR, "cannot set perf max_entries: %m");
			goto err;
		}
		bcc->perf_map = map;
	} else {
		bpf_map__reuse_fd(map, bpf_map__fd(bcc->perf_map));
	}

	/* load obj */
	ret = bpf_object__load(bcc->tr_obj);
	if (ret) {
		log_message(LOG_ERR, "%s: cannot load: %m", p->path);
		goto err;
	}

	bcc->fentry_lnk = bpf_program__attach_trace(fentry_prg);
	if (bcc->fentry_lnk == NULL) {
		log_message(LOG_ERR, "%s: cannot attach: %m", p->path);
		goto err;
	}
	bcc->fexit_lnk = bpf_program__attach_trace(fexit_prg);
	if (bcc->fexit_lnk == NULL) {
		log_message(LOG_ERR, "%s: cannot attach: %m", p->path);
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
		log_message(LOG_INFO, "update map{capture_cfg}: %m");
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
		log_message(LOG_INFO, "update map{capture_iface}: %m");

	if (!(bcc->prg_entry.flags & BPF_CAPTURE_EFL_BY_IFACE)) {
		bcc->prg_entry.flags |= BPF_CAPTURE_EFL_BY_IFACE;
		_trace_map_prg_entry_update(bcc);
	}

	log_message(LOG_DEBUG, "%s: capture started on ifindex %d",
		    e->cf->filename, iface);

	return 0;
}


/********************************************************************/
/* capture packet from userspace */


static int
_build_fake_l2l3_hdr(uint8_t *buffer, size_t buflen, size_t payload_len,
		     const sockaddr_t *remote_addr, const sockaddr_t *local_addr,
		     uint16_t flags)
{
	struct ethhdr *eth;
	struct iphdr *iph;
	struct udphdr *udph;
	size_t total_len = sizeof(*eth) + sizeof(*iph) + sizeof(*udph);
	uint8_t *macaddr;

	if (buflen < total_len)
		return -1;

	if (remote_addr->family != AF_INET || local_addr->family != AF_INET)
		return -1;

	/* Ethernet header */
	eth = (struct ethhdr *)buffer;
	macaddr = flags & GTP_CAPTURE_FL_INPUT ? eth->h_dest : eth->h_source;
	macaddr[0] = 0;
	macaddr[1] = 0x24;
	macaddr[2] = 0xd4;
	macaddr[3] = 0;
	macaddr[4] = 0;
	macaddr[5] = 1;
	macaddr = flags & GTP_CAPTURE_FL_INPUT ? eth->h_source : eth->h_dest;
	macaddr[0] = 0xEC;
	macaddr[1] = 0x0D;
	macaddr[2] = 0x9d;
	macaddr[3] = 0;
	macaddr[4] = 0;
	macaddr[5] = 2;
	eth->h_proto = htons(ETH_P_IP);

	/* IP header */
	iph = (struct iphdr *)(eth + 1);
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(*iph) + sizeof(*udph) + payload_len);
	iph->id = htons(0x6666);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;
	if (flags & GTP_CAPTURE_FL_INPUT) {
		iph->saddr = sa_ip4(remote_addr);
		iph->daddr = sa_ip4(local_addr);
	} else {
		iph->daddr = sa_ip4(remote_addr);
		iph->saddr = sa_ip4(local_addr);
	}
	iph->check = in_csum((uint16_t *) iph, sizeof(*iph), 0);

	/* UDP header */
	udph = (struct udphdr *)(iph + 1);
	if (flags & GTP_CAPTURE_FL_INPUT) {
		udph->source = sa_portn(remote_addr);
		udph->dest = sa_portn(local_addr);
	} else {
		udph->dest = sa_portn(remote_addr);
		udph->source = sa_portn(local_addr);
	}
	udph->len = htons(sizeof(*udph) + payload_len);
	udph->check = 0;

	return total_len;
}

static void
_capture_userspace_pkt(struct gtp_capture_entry *e, uint32_t pktlen,
		       const struct iovec *pkt_iov, int iovcnt, uint16_t flags)
{
	struct gtp_capture_file *cf = e->cf;
	struct xpcapng_epb_options_s options = {};
	struct timespec ts;
	uint64_t ns;

	clock_gettime(CLOCK_REALTIME, &ts);
	ns = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
	++cf->cpu_packet_id[cf->cpu_packet_id_n];

	options.flags = flags & GTP_CAPTURE_FL_INPUT ?
		PCAPNG_EPB_FLAG_INBOUND : PCAPNG_EPB_FLAG_OUTBOUND;
	options.dropcount = 0;
	options.packetid = &cf->cpu_packet_id[cf->cpu_packet_id_n];

	xpcapng_dump_enhanced_pkt(cf->pcapng, 1, pkt_iov, iovcnt,
				  pktlen, min(pktlen, e->cap_len),
				  ns, &options);

	cf->pkt_count++;
	if ((cf->pkt_max && cf->pkt_count >= cf->pkt_max) ||
	    (cf->until && ns / NSEC_PER_SEC > cf->until)) {
		log_message(LOG_DEBUG, "stopping capture, pkt: %d/%d, expired:%s (ref:%d)",
			    cf->pkt_count, cf->pkt_max,
			    cf->until && ns / NSEC_PER_SEC > cf->until ? "yes" : "no",
			    cf->refcnt);
		cf->running = false;
	}
}


/********************************************************************/
/* capture api */

void
gtp_capture_pkt(struct gtp_capture_entry *e, const uint8_t *data, size_t len,
		uint16_t flags)
{
	struct iovec pkt_iov[1];

	if (e->cf == NULL || !e->flags || !e->cf->running)
		return;

	pkt_iov[0].iov_base = (void *)data;
	pkt_iov[0].iov_len = len;

	_capture_userspace_pkt(e, len, pkt_iov, 1, flags);

}

void
gtp_capture_data(struct gtp_capture_entry *e, const uint8_t *data, size_t len,
		 const sockaddr_t *remote_addr, const sockaddr_t *local_addr,
		 uint16_t flags)
{
	struct iovec pkt_iov[2];
	uint8_t buf[100];
	int n;

	if (e->cf == NULL || !e->flags || !e->cf->running)
		return;

	n = _build_fake_l2l3_hdr(buf, sizeof(buf), len,
				 remote_addr, local_addr, flags);
	if (n < 0)
		return;

	pkt_iov[0].iov_base = buf;
	pkt_iov[0].iov_len = n;
	pkt_iov[1].iov_base = (void *)data;
	pkt_iov[1].iov_len = len;

	_capture_userspace_pkt(e, len + n, pkt_iov, 2, flags);
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
		bcc = _alloc_bpf_ctx(p, false);
		if (bcc == NULL)
			return -1;
	}

	/* max running capture */
	if (bcc->ae_n == CAPTURE_BPF_MAX_ENTRY)
		return -1;

	/* link entry and capture file */
	cf = capture_file_get(name, true);
	if (cf == NULL || capture_file_start(cf, p) < 0)
		goto err;
	e->cf = capture_file_refinc(cf);

	/* link entry and bpf-program capture context */
	for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++)
		if (bcc->ae[i] == NULL)
			break;
	bcc->ae[i] = e;
	e->entry_id = i + 1;
	e->flags |= GTP_CAPTURE_FL_NEED_BPF_UPDATE;
	++bcc->ae_n;
	e->bcc = bcc;

	/* add fentry/fexit trace */
	if (e->flags & GTP_CAPTURE_FL_USE_TRACEFUNC)
		if (capture_add_trace_func(bcc))
			goto err;

	/* perf buffer already created */
	if (bcc->pb != NULL)
		goto opened;

	/* create perf buffer */
	struct perf_event_attr perf_attr = {
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.wakeup_events = cfg_wakeup_events,
	};
	bcc->pb = perf_buffer__new_raw(bpf_map__fd(bcc->perf_map),
				       PERF_BUFFER_PAGES,
				       &perf_attr, capture_perf_event,
				       bcc, NULL);
	if (bcc->pb == NULL) {
		log_message(LOG_INFO, "Failed to open perf buffer: %m");
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
	bcc->flush_ev = thread_add_timer(master, capture_perf_flush, bcc, TIMER_HZ);
	bcc->missed_events = 0;
	bcc->last_missed_events = 0;

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
		capture_file_refdec(cf);
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
		bcc->pb = NULL;
	}
	thread_del(bcc->flush_ev);
	if (!bcc->is_tpl) {
		list_del(&bcc->list);
		free(bcc);
	}
}

void
gtp_capture_get_info(struct gtp_capture_entry *e, const char **out_capname)
{
	if (e->cf == NULL) {
		*out_capname = NULL;
		return;
	}
	*out_capname = e->cf->name;
}

/********************************************************************/
/* eBPF template */


static struct gtp_bpf_capture_ctx *
_alloc_bpf_ctx(struct gtp_bpf_prog *p, bool is_tpl)
{
	struct gtp_bpf_capture_ctx *bcc;
	struct timespec ts;
	uint64_t epoch, uptime;
	static int init_once = 0;

	/* get delta from monotonic to realtime to add in each packet-pcap */
	if (init_once == 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
			log_message(LOG_ERR, "Failed to get CLOCK_MONOTONIC time: %m");
			return NULL;
		}
		epoch = time(NULL) * 1000000000ULL;
		uptime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
		epoch_delta = epoch - uptime;

		init_once = 1;
	}

	bcc = calloc(1, sizeof (*bcc));
	if (bcc == NULL)
		return NULL;
	bcc->p = p;
	bcc->is_tpl = is_tpl;
	list_add(&bcc->list, &bcc_list);

	return bcc;
}


static void *
gtp_bpf_capture_alloc(struct gtp_bpf_prog *p)
{
	return _alloc_bpf_ctx(p, true);
}

static void
gtp_bpf_capture_release(struct gtp_bpf_prog *p, void *udata)
{
	struct gtp_bpf_capture_ctx *bcc = udata;

	list_del(&bcc->list);
	free(bcc);
}

static int
gtp_bpf_capture_prepare(struct gtp_bpf_prog *p, void *udata)
{
	struct bpf_map *map;

	map = gtp_bpf_prog_load_map(p->obj_load, "capture_perf_map");
	if (map == NULL)
		return -1;
	if (bpf_map__set_max_entries(map, libbpf_num_possible_cpus())) {
		log_message(LOG_ERR, "cannot set perf max_entries: %m");
		return -1;
	}

	return 0;
}

static int
gtp_bpf_capture_loaded(struct gtp_bpf_prog *p, void *udata, bool reload)
{
	struct gtp_bpf_capture_ctx *bcc = udata;

	bcc->perf_map = gtp_bpf_prog_load_map(p->obj_load, "capture_perf_map");
	if (bcc->perf_map == NULL)
		return -1;

	return 0;
}

static void
gtp_bpf_capture_vty(struct gtp_bpf_prog *p, void *udata, struct vty *vty,
		    int argc, const char **argv)
{
	struct gtp_bpf_capture_ctx *bcc = udata;
	struct gtp_capture_entry *e;
	int i;

	vty_out(vty, "capture on bpf-prog '%s': ", p->name);
	if (bcc->pb == NULL) {
		vty_out(vty, "currently not in use\n");
		return;
	}
	vty_out(vty, "capture entries %d/%d\n",
		bcc->ae_n, CAPTURE_BPF_MAX_ENTRY);

	for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++) {
		e = bcc->ae[i];
		if (e == NULL)
			continue;
		vty_out(vty, "  [%d] flags:0x%04x caplen:%d pcap:%s\n",
			i, e->flags, e->cap_len, e->cf ? e->cf->name : "<no pcap>");
	}
	vty_out(vty, "perf missed events : %ld\n",
		bcc->missed_events);
}

static struct gtp_bpf_prog_tpl gtp_bpf_capture_module = {
	.name = "capture",
	.description = "PcapNG capture handler",
	.alloc = gtp_bpf_capture_alloc,
	.release = gtp_bpf_capture_release,
	.prepare = gtp_bpf_capture_prepare,
	.loaded = gtp_bpf_capture_loaded,
	.vty_out = gtp_bpf_capture_vty,
};



/********************************************************************/
/* Vty */


DEFUN(capture_file_set,
      capture_file_set_cmd,
      "capture file set NAME [TIME MAXPKT FILENAME]",
      "Capture menu\n"
      "Capture file configuration\n"
      "Capture file entry name\n"
      "Add/Update a capture\n"
      "Time in second before stopping capture (default: 0, unlimited)\n"
      "Packets to write before stopping capture (default: 0, unlimited)\n"
      "Pcap filename to write into\n")
{
	struct gtp_capture_file *cf;

	cf = capture_file_get(argv[0], true);
	if (cf == NULL) {
		vty_out(vty, "%% Cannot get capture file %s\n", argv[0]);
		return CMD_WARNING;
	}
	cf->persist = true;

	if (argc > 1)
		cf->duration = atoi(argv[1]);
	if (argc > 2)
		cf->pkt_max = atoi(argv[2]);
	if (argc > 3)
		snprintf(cf->filename, sizeof (cf->filename), "%s", argv[3]);


	return CMD_SUCCESS;
}

DEFUN(capture_file_del,
      capture_file_del_cmd,
      "capture file del NAME",
      "Capture menu\n"
      "Capture file configuration\n"
      "Capture file entry name\n"
      "Delete existing capture\n")
{
	struct gtp_capture_file *cf;

	cf = capture_file_get(argv[0], false);
	if (cf == NULL) {
		vty_out(vty, "%% Cannot get capture file %s\n", argv[0]);
		return CMD_WARNING;
	}
	capture_file_destroy(cf);

	return CMD_SUCCESS;
}

static void
_vty_show_cf(struct vty *vty, struct gtp_capture_file *cf)
{
	struct gtp_bpf_capture_ctx *bcc;
	char pathname[400];
	int i;

	vty_out(vty, "capture entry %s\n", cf->name);
	if (*cf->filename) {
		if (strcmp(cf->name, cf->filename))
			vty_out(vty, "filename         : %s\n", cf->filename);
		snprintf(pathname, sizeof (pathname), "%s/%s.pcap",
			 cfg_pcap_path, cf->filename);
		vty_out(vty, "pathname         : %s\n", pathname);
	}
	vty_out(vty, "  refcnt         : %d%s\n",
		cf->refcnt, cf->persist ? " (persist)" : "");
	vty_out(vty, "  status         : %s\n",
		cf->running ? "running" : "closed");
	if (!cf->running)
		return;

	assert(cf->pcapng != NULL);
	vty_out(vty, "  bpf-prog link  : %s\n", cf->p->name);
	if (cf->refcnt) {
		vty_out(vty, "  referenced from:");
		bool seen = false;
		list_for_each_entry(bcc, &bcc_list, list) {
			for (i = 0; i < CAPTURE_BPF_MAX_ENTRY; i++) {
				if (bcc->ae[i] != NULL && bcc->ae[i]->cf == cf) {
					if (!seen) {
						vty_out(vty, " [%d", i);
						seen = true;
					} else {
						vty_out(vty, ", %d", i);
					}
				}
			}
			if (seen) {
				vty_out(vty, "]\n");
				break;
			}
		}
		if (!seen)
			vty_out(vty, " <nowhere!>\n");
	}
	if (cf->pkt_max)
		vty_out(vty, "  packet count   : %d / %d\n",
			cf->pkt_count, cf->pkt_max);
	else
		vty_out(vty, "  packet count   : %d\n", cf->pkt_count);
	if (cf->duration) {
		vty_out(vty, "  duration       : %d seconds", cf->duration);
		if (cf->until)
			vty_out(vty, " (%ld seconds remaining)",
				cf->until - time(NULL));
		vty_out(vty, VTY_NEWLINE);
	}
	vty_out(vty, "  interface index:\n");
	for (i = 0; i < cf->if2itfidx_mask + 1; i++)
		if (cf->if2itfidx[i])
			vty_out(vty, "    [%d] if-index:%-3d  pcap-itf-idx:%-3d\n",
				i, (uint32_t)(cf->if2itfidx[i] >> 32ULL),
				(uint32_t)cf->if2itfidx[i]);
}

DEFUN(capture_file_show,
      capture_file_show_cmd,
      "capture file show [NAME]",
      "Capture menu\n"
      "Capture file configuration\n"
      SHOW_STR
      "Capture file entry name\n")
{
	struct gtp_capture_file *cf;

	if (argc == 0) {
		list_for_each_entry(cf, &cfile_list, list)
			_vty_show_cf(vty, cf);
		return CMD_SUCCESS;
	}

	cf = capture_file_get(argv[0], false);
	if (cf == NULL) {
		vty_out(vty, "%% Cannot get capture file %s\n", argv[0]);
		return CMD_WARNING;
	}
	_vty_show_cf(vty, cf);

	return CMD_SUCCESS;
}


DEFUN(capture_entry,
      capture_entry_cmd,
      "capture-config",
      "Configure capture module\n")
{
	vty->node = CAPTURE_NODE;
	return CMD_SUCCESS;
}

DEFUN(capture_set_record_path,
      capture_set_record_path_cmd,
      "record-path PATH",
      "set record-path\n")
{
	snprintf(cfg_pcap_path, sizeof (cfg_pcap_path), "%s", argv[0]);

	return CMD_SUCCESS;
}

DEFUN(capture_set_snaplen,
      capture_set_snaplen_cmd,
      "snaplen <32-65535>",
      "set snaplen\n")
{
	VTY_GET_INTEGER_RANGE("Capture length", cfg_capture_snaplen, argv[0], 32, 65535);

	return CMD_SUCCESS;
}

DEFUN(capture_set_rotate_file,
      capture_set_rotate_file_cmd,
      "rotate <0-100>",
      "set rotate file count (0: do not rotate)\n")
{
	VTY_GET_INTEGER_RANGE("Rotate file", cfg_rotate_file, argv[0], 0, 100);

	return CMD_SUCCESS;
}

DEFUN(capture_set_wakeup_events,
      capture_set_wakeup_events_cmd,
      "wakeup-events <1-128>",
      "set wakeup-events")
{
	VTY_GET_INTEGER_RANGE("Wakeup events", cfg_wakeup_events, argv[0], 1, 128);

	return CMD_SUCCESS;
}


static int
capture_config_write(struct vty *vty)
{
	vty_out(vty, "capture-config\n");
	vty_out(vty, " record-path %s\n", cfg_pcap_path);
	vty_out(vty, " snaplen %d\n", cfg_capture_snaplen);
	vty_out(vty, " rotate %d\n", cfg_rotate_file);
	vty_out(vty, " wakeup-events %d\n", cfg_wakeup_events);
	return CMD_SUCCESS;
}


static int
cmd_ext_capture_install(void)
{
	/* Config commands */
	install_element(CONFIG_NODE, &capture_entry_cmd);

	install_element(CAPTURE_NODE, &capture_set_record_path_cmd);
	install_element(CAPTURE_NODE, &capture_set_snaplen_cmd);
	install_element(CAPTURE_NODE, &capture_set_rotate_file_cmd);
	install_element(CAPTURE_NODE, &capture_set_wakeup_events_cmd);

	/* Action commands */
	install_element(ENABLE_NODE, &capture_file_set_cmd);
	install_element(ENABLE_NODE, &capture_file_del_cmd);
	install_element(ENABLE_NODE, &capture_file_show_cmd);

	return 0;
}

struct cmd_node capture_node = {
	.node = CAPTURE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(capture)# ",
	.config_write = capture_config_write,
};


static struct cmd_ext cmd_ext_capture = {
	.node = &capture_node,
	.install = cmd_ext_capture_install,
};



static void __attribute__((constructor))
gtp_bpf_capture_init(void)
{
	snprintf(cfg_pcap_path, sizeof (cfg_pcap_path), "/tmp");

	cmd_ext_register(&cmd_ext_capture);
	gtp_bpf_prog_tpl_register(&gtp_bpf_capture_module);
}

static void __attribute__((destructor))
gtp_bpf_capture_destroy(void)
{
	struct gtp_capture_file *cf, *cf_tmp;

	/* delete persistent capture file */
 	list_for_each_entry_safe(cf, cf_tmp, &cfile_list, list)
		capture_file_destroy(cf);
}

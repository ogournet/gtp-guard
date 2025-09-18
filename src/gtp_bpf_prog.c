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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <sys/inotify.h>
#include <errno.h>
#include <btf.h>
#include <linux/if_link.h>

#include "gtp_data.h"
#include "gtp_bpf.h"
#include "gtp_bpf_prog.h"
#include "gtp_interface.h"
#include "bitops.h"
#include "libbpf.h"
#include "bitops.h"
#include "logger.h"
#include "utils.h"
#include "memory.h"


/* Extern data */
extern struct data *daemon_data;
extern struct thread_master *master;

/* Local data */
static struct thread *inotify_th;

static void gtp_bpf_prog_watch(struct gtp_bpf_prog *p);


/*
 *	BPF Object variable update.
 *
 *  This only apply to global variables as present in .rodata section,
 *  without using generated skeleton from libbpf.
 *  They can be modified *only* before program is loaded into kernel.
 *  it should be the same for variables in .data or .bss sections.
 */


/*
 * split given buffer into array using delimiters, consecutive
 * delimiters occurence are merged
 * does *NOT* remove leading occurence of delimiter
 */
static void
split_line(char *buf, int *argc, char **argv, const char *delim,
	   int max_args)
{
	int scan;

	*argc = 1;
	argv[0] = buf;

	scan = 0;
	while (*buf) {
		if (!scan) {
			if (strchr(delim, *buf)) {
				*buf = 0;
				scan = 1;
			}
		} else {
			if (!strchr(delim, *buf)) {
				(*argc)++;
				argv[*argc - 1] = buf;
				scan = 0;

				if (*argc == max_args)
					return;
			}
		}
		buf++;
	}
}


static const struct btf_type *
_get_datasec_type(struct bpf_object *obj, const char *datasec_name, void **out_data)
{
	struct bpf_map *map;
	const char *name;

	name = datasec_name;
#if 0
	/* sometimes '.rodata' is called 'prgnam.rodata' ? */
	/* XXX: if it's the case, re-enable this code */
	bpf_object__for_each_map(map, obj) {
		if (strstr(bpf_map__name(map), datasec_name)) {
			name = bpf_map__name(map);
			break;
		}
	}
	if (!name) {
		log_message(LOG_INFO, "%s(): cant find DATASEC=%s !!!",
			    __FUNCTION__, datasec_name);
		errno = ENOENT;
		return NULL;
	}
#endif

	/* this open() subskeleton is only here to retrieve map's mmap address
	 * libbpf doesn't provide other way to get this address */
	struct bpf_map_skeleton ms[1] = { {
		.name = name,
		.map = &map,
		.mmaped = out_data,
	} };
	struct bpf_object_subskeleton ss = {
		.sz = sizeof (struct bpf_object_subskeleton),
		.obj = obj,
		.map_cnt = 1,
		.map_skel_sz = sizeof (struct bpf_map_skeleton),
		.maps = ms,
	};
	if (bpf_object__open_subskeleton(&ss) < 0) {
		log_message(LOG_INFO, "%s(): cant open subskeleton !!!", __FUNCTION__);
		errno = EINVAL;
		return NULL;
	}

	/* now use btf info to find this variable */
	struct btf *btf;
	const struct btf_type *sec;
	int sec_id;

	btf = bpf_object__btf(obj);
	if (btf == NULL) {
		log_message(LOG_INFO, "%s(): cant get BTF handler !!!", __FUNCTION__);
		errno = ENOENT;
		return NULL;
	}

	/* get secdata id */
	sec_id = btf__find_by_name(btf, datasec_name);
	if (sec_id < 0) {
		log_message(LOG_INFO, "%s(): cant get %s section !!!",
			    __FUNCTION__, datasec_name);
		errno = ENOENT;
		return NULL;
	}

	/* get the actual BTF type from the ID */
	sec = btf__type_by_id(btf, sec_id);
	if (sec == NULL) {
		log_message(LOG_INFO, "%s(): cant get BTF type from section ID !!!"
				    , __FUNCTION__);
		errno = ENOENT;
		return NULL;
	}

	return sec;
}


int
gtp_bpf_prog_obj_update_var(struct bpf_object *obj, const struct gtp_bpf_prog_var *consts)
{
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	void *rodata;
	int set = 0, to_be_set = 0;
	int i, j;

	sec = _get_datasec_type(obj, ".rodata", &rodata);
	if (sec == NULL)
		return -1;

	/* Get all secinfos, each of which will be a global variable */
	btf = bpf_object__btf(obj);
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);
		for (j = 0; consts[j].name != NULL; j++) {
			if (!strcmp(name, consts[j].name)) {
				if (secinfo[i].size != consts[j].size) {
					log_message(LOG_INFO, "%s(): '%s' var size mismatch"
						    " (btf:%d, userapp:%d)"
						    , __FUNCTION__, name,
						    secinfo[i].size, consts[j].size);
					errno = EINVAL;
					return -1;
				}
				memcpy(rodata + secinfo[i].offset,
				       consts[j].value, consts[j].size);
				++set;
				break;
			}
		}
		if (consts[j].name == NULL)
			to_be_set = j;
	}

	if (set < to_be_set - 1) {
		log_message(LOG_INFO, "%s(): not all .rodata var set (%d/%d) !!!"
				, __FUNCTION__, set, to_be_set);
	}

	return 0;
}

static int
gtp_bpf_prog_obj_get_mode_list(struct bpf_object *obj, char **out_buf, char **tpl_names)
{
	struct btf *btf;
	const struct btf_type *sec;
	struct btf_var_secinfo *secinfo;
	char *buf;
	void *data;
	int i, argc;

	sec = _get_datasec_type(obj, ".rodata", &data);
	if (sec == NULL)
		return -1;

	btf = bpf_object__btf(obj);
	secinfo = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++) {
		const struct btf_type *t = btf__type_by_id(btf, secinfo[i].type);
		const char *name = btf__name_by_offset(btf, t->name_off);
		if (!strcmp(name, "_mode") && secinfo[i].size > 0) {
			buf = MALLOC(secinfo[i].size);
			memcpy(buf, data + secinfo[i].offset, secinfo[i].size - 1);
			split_line(buf, &argc, tpl_names, ",;", BPF_PROG_TPL_MAX);
			if (argc)
				return argc;
			free(buf);
			return -1;
		}
	}

	log_message(LOG_INFO, "%s(): cannot find var '_mode' in DATASEC(mode) !!!",
		    __FUNCTION__);

	return -1;
}



/*
 *	BPF helpers
 */


int
gtp_bpf_prog_open(struct gtp_bpf_prog *p, bool reload)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	const struct gtp_bpf_prog_tpl *tpl;
	char *argv[BPF_PROG_TPL_MAX], *buf;
	bool mode_changed = false;
	int i = 0, n, ret = -1;
	const size_t log_buf_size = 1 << 22;

	if (p->load.obj)
		return 0;
	if (__test_bit(GTP_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags))
		return -1;

	if (!p->log_buf)
		p->log_buf = MALLOC(log_buf_size);

	/* libbpf buf triggers valgrind warnings, because valgrind is not yet
	   up to date... provide our own buf */
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
			    .kernel_log_buf = p->log_buf,
			    .kernel_log_size = log_buf_size,
			    .kernel_log_level = 0);

	/* Open eBPF file */
	p->load.obj = bpf_object__open_file(p->path, &opts);
	if (!p->load.obj) {
		libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "eBPF: error opening bpf file err:%d (%s)"
				    , errno, errmsg);
		return -1;
	}

	/* file exists, we can watch it */
	gtp_bpf_prog_watch(p);

	/* Get template mode(s), from const char *_mode */
	n = gtp_bpf_prog_obj_get_mode_list(p->load.obj, &buf, argv);
	if (n < 0)
		goto err;

	if (reload) {
		/* A program is running. Check that template list didn't changed */
		mode_changed = n != p->tpl_n;
		for (i = 0; i < n && !mode_changed; i++)
			mode_changed = gtp_bpf_prog_tpl_get(argv[i]) != p->tpl[i];
		if (mode_changed) {
			log_message(LOG_INFO, "%s(): bpf program mode list changed",
				    __FUNCTION__);
			ret = 1;
			goto err;
		}

	} else {
		/* Load template data */
		for (i = 0; i < n; i++) {
			tpl = gtp_bpf_prog_tpl_get(argv[i]);
			if (tpl == NULL) {
				log_message(LOG_INFO, "%s: bpf program refers to "
					    "unknown mode '%s'",
					    p->path, argv[i]);
				goto err;
			}
			if (tpl->udata_alloc_size)
				p->tpl_data[i] = MALLOC(tpl->udata_alloc_size);
			p->tpl[i] = tpl;
		}
		p->tpl_n = n;
	}

	free(buf);
	return 0;

 err:
	n = i;
	for (i = 0; !reload && i < n; i++)
		if (p->tpl[i]->udata_alloc_size)
			free(p->tpl_data[i]);
	bpf_object__close(p->load.obj);
	p->load.obj = NULL;
	free(buf);
	__set_bit(GTP_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
	return ret;
}


static inline int
_assign_program(struct gtp_bpf_prog *p, struct bpf_program *prg,
		const char *force_type, const char *prgname)
{
	enum bpf_attach_type atype;

	if (prg == NULL) {
		log_message(LOG_INFO, "%s: %s program '%s' not found in bpf file",
			    p->name, force_type, prgname);
		return -1;
	}

	atype = bpf_program__expected_attach_type(prg);
	switch (atype) {
	case BPF_TCX_INGRESS:
		if (*force_type && strcmp(force_type, "tc")) {
			log_message(LOG_INFO, "%s: wrong program '%s' type', "
				    "has:%s expect:tc", p->name, p->load.tc_progname,
				    libbpf_bpf_attach_type_str(atype));
			return -1;
		}
		if (p->load.tc == NULL) {
			p->load.tc = prg;
			log_message(LOG_DEBUG, "%s: tc program %s loaded, %ld instructions",
				    p->name, bpf_program__name(prg),
				    bpf_program__insn_cnt(prg));
		}
		return 0;

	case BPF_XDP:
		if (*force_type && strcmp(force_type, "xdp")) {
			log_message(LOG_INFO, "%s: wrong program '%s' type, "
				    "has:%s expect:xdp", p->name, p->load.xdp_progname,
				    libbpf_bpf_attach_type_str(atype));
			return -1;
		}
		if (p->load.xdp == NULL) {
			p->load.xdp = prg;
			log_message(LOG_DEBUG, "%s: xdp program %s loaded, %ld instructions",
				    p->name, bpf_program__name(prg),
				    bpf_program__insn_cnt(prg));
		}
		return 0;

	default:
		if (*force_type) {
			log_message(LOG_INFO, "%s: program type '%s' not supported",
				    p->name, libbpf_bpf_attach_type_str(atype));
			return -1;
		}
		return 0;
	}
}

static int
gtp_bpf_prog_load(struct gtp_bpf_prog *p, bool reloading)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct bpf_program *bpf_prg;
	int i, err;

	if (__test_bit(GTP_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags))
		return -1;

	log_message(LOG_INFO, "%s: %sloading program into kernel",
		    p->name, reloading ? "re-" : "");

	/* Open bpf file (if not done yet) */
	if (gtp_bpf_prog_open(p, reloading))
		return -1;

	for (i = 0; i < p->tpl_n; i++)
		if (p->tpl[i]->opened != NULL && p->tpl[i]->opened(p, p->tpl_data[i]))
			goto err;

	/* Finally load it (kernel runs verifier) */
	err = bpf_object__load(p->load.obj);
	if (err) {
		log_message(LOG_DEBUG, "--- FULL KERNEL BPF LOG ---\n");
		log_message(LOG_DEBUG, "%s", p->log_buf);
		log_message(LOG_DEBUG, "--- END FULL KERNEL BPF LOG ---\n");
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_ERR, "%s: error loading bpf_object err:%d (%s)",
			    p->name, err, errmsg);
		goto err;
	}

	if (!reloading) {
		for (i = 0; i < p->tpl_n; i++) {
			if (p->tpl[i]->loaded != NULL && p->tpl[i]->loaded(p, p->tpl_data[i]))
				goto err;
		}
	}

	/* Explicit program lookup */
	if (p->load.xdp_progname[0]) {
		bpf_prg = bpf_object__find_program_by_name(p->load.obj, p->load.xdp_progname);
		if (_assign_program(p, bpf_prg, "xdp", p->load.xdp_progname) < 0)
			goto err;
	}
	if (p->load.tc_progname[0]) {
		bpf_prg = bpf_object__find_program_by_name(p->load.obj, p->load.tc_progname);
		if (_assign_program(p, bpf_prg, "tc", p->load.tc_progname) < 0)
			goto err;
	}

	/* If progname is not specified, use first program the object contains */
	bpf_object__for_each_program(bpf_prg, p->load.obj) {
		_assign_program(p, bpf_prg, "", NULL);
	}

	/* Must have at least one loaded program */
	if (!p->load.tc && !p->load.xdp)
		goto err;

	return 0;

 err:
	if (!reloading)
		gtp_bpf_prog_unload(p);
	bpf_object__close(p->load.obj);
	p->load.obj = NULL;
	p->load.tc = NULL;
	p->load.xdp = NULL;
	__set_bit(GTP_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);
	return -1;
}

int
gtp_bpf_prog_attach(struct gtp_bpf_prog *p, struct gtp_interface *iface)
{
	int ifindex = iface->ifindex;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int i;

	if (!p->run.obj) {
		if (gtp_bpf_prog_load(p, false) < 0)
			return -1;
		p->run = p->load;
		p->load.obj = NULL;
		p->load.tc = NULL;
		p->load.xdp = NULL;
	}

	/* Attach XDP */
	if (p->run.xdp != NULL) {
		iface->bpf_xdp_lnk = bpf_program__attach_xdp(p->run.xdp, ifindex);
		if (!iface->bpf_xdp_lnk) {
			libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
			log_message(LOG_INFO,
				    "%s(): XDP: error attaching program:%s "
				    "to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(p->run.xdp)
				    , ifindex
				    , errno, errmsg);
			goto err;
		}
	}

	/* Attach TCX */
	if (p->run.tc != NULL) {
		DECLARE_LIBBPF_OPTS(bpf_tcx_opts, opts);
		iface->bpf_tc_lnk = bpf_program__attach_tcx(p->run.tc, ifindex, &opts);
		if (!iface->bpf_tc_lnk) {
			libbpf_strerror(errno, errmsg, GTP_XDP_STRERR_BUFSIZE);
			log_message(LOG_INFO,
				    "%s(): TCX: error attaching program:%s "
				    "to ifindex:%d err:%d (%s)"
				    , __FUNCTION__
				    , bpf_program__name(p->run.tc)
				    , ifindex
				    , errno, errmsg);
			goto err;
		}
	}

	/* After attaching program to interface */
	for (i = 0; i < p->tpl_n; i++)
		if (p->tpl[i]->iface_bind != NULL &&
		    p->tpl[i]->iface_bind(p, p->tpl_data[i], iface))
			goto err;

	return 0;

 err:
	gtp_bpf_prog_detach(p, iface);
	return -1;
}

void
gtp_bpf_prog_detach(struct gtp_bpf_prog *p, struct gtp_interface *iface)
{
	int i;

	/* Detach program from interface */
	for (i = 0; i < p->tpl_n; i++)
		if (p->tpl[i]->iface_unbind != NULL)
			p->tpl[i]->iface_unbind(p, p->tpl_data[i], iface);

	if (iface->bpf_xdp_lnk != NULL) {
		bpf_link__destroy(iface->bpf_xdp_lnk);
		iface->bpf_xdp_lnk = NULL;
	}
	if (iface->bpf_tc_lnk != NULL) {
		bpf_link__destroy(iface->bpf_tc_lnk);
		iface->bpf_tc_lnk = NULL;
	}
}

void
gtp_bpf_prog_unload(struct gtp_bpf_prog *p)
{
	int i;

	for (i = 0; i < p->tpl_n; i++) {
		if (p->tpl[i]->udata_alloc_size)
			free(p->tpl_data[i]);
	}
	p->run.tc = NULL;
	p->run.xdp = NULL;
	if (p->run.obj != NULL)
		bpf_object__close(p->run.obj);
	p->run.obj = NULL;
	if (p->load.obj != NULL)
		bpf_object__close(p->load.obj);
	p->load.obj = NULL;
	p->tpl_n = 0;
}

int
gtp_bpf_prog_destroy(struct gtp_bpf_prog *p)
{
	if (p->watch_id > 0 && inotify_th)
		inotify_rm_watch(inotify_th->u.f.fd, p->watch_id);
	gtp_bpf_prog_unload(p);
	list_head_del(&p->next);
	FREE(p->log_buf);
	FREE(p);
	return 0;
}

int
gtp_bpf_prog_tpl_data_set(struct gtp_bpf_prog *p, const char *tpl_name, void *udata)
{
	int i;

	for (i = 0; i < p->tpl_n; i++)
		if (!p->tpl[i]->udata_alloc_size &&
		    !strcmp(p->tpl[i]->name, tpl_name)) {
			p->tpl_data[i] = udata;
			return 0;
		}

	return -1;
}

/*
 * reload bpf programs from bpf file, while bpf is running.
 * there are two reload mode:
 *
 *   - soft-reload: performed if maps are the same.
 *       map are 'linked' from running to new program, then
 *       new program is substitued to running.
 *       there should be no down-time.
 *
 *   - full-reload: performed when conditions for soft-reload
 *       are not meet.
 *       program is reloaded, then all bpf links to interface are
 *       deleted then re-created.
 *
 * in any case, a running program won't be switched off if the new
 * program cannot be loaded, so it's unlikely that this function
 * will stop bpf program.
 */
static void
gtp_bpf_prog_soft_reload(struct gtp_bpf_prog *p)
{
	struct gtp_interface *iface;
	struct bpf_map *map, *omap;
	const char *name;
	int st_if_r = 0, st_if_t = 0;
	int ret;

	/* ignore previous error, it may have been fixed! */
	__clear_bit(GTP_BPF_PROG_FL_LOAD_ERR_BIT, &p->flags);

	/* bpf-prog is not running, do a full open/load/attach */
	if (!p->run.obj) {
		log_message(LOG_INFO, "%s: program is not yet running, "
			    "do a full reload", name);
		goto full_reload;
	}

	/* re-open bpf file */
	ret = gtp_bpf_prog_open(p, true);
	if (ret < 0)
		return;
	if (ret == 1)
		goto cant_soft_reload;

	/* assign bpf_map from running program if map specs are the same.
	 * if they are different, do a full reload */
	bpf_object__for_each_map(map, p->load.obj) {
		name = bpf_map__name(map);

		/* do not replace that one: it contains const */
		if (strstr(name, ".rodata"))
			continue;

		omap = bpf_object__find_map_by_name(p->run.obj, name);
		if (!omap) {
			log_message(LOG_INFO, "%s: map not found on "
				    "running program", name);
			goto cant_soft_reload;
		}
		if (bpf_map__type(map) != bpf_map__type(omap) ||
		    bpf_map__key_size(map) != bpf_map__key_size(omap) ||
		    bpf_map__value_size(map) != bpf_map__value_size(omap)) {
			log_message(LOG_INFO, "%s: map caracteristics changed",
				    name);
			goto cant_soft_reload;
		}

		bpf_map__reuse_fd(map, bpf_map__fd(omap));
	}

	/* re-load bpf program */
	if (gtp_bpf_prog_load(p, true)) {
		log_message(LOG_INFO, "%s cannot reload bpf program, "
			    "keep previous running one", p->name);
	}

	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		++st_if_t;
		/* skip down interfaces */
		if (__test_bit(GTP_INTERFACE_FL_SHUTDOWN_BIT, &iface->flags))
			continue;

		/* reattach interfaces */
		if (iface->bpf_xdp_lnk && p->load.xdp) {
			ret = bpf_link__update_program(iface->bpf_xdp_lnk, p->load.xdp);
			if (ret)
				log_message(LOG_ERR, "%s: link__update_program: %m",
					    p->name);
		}
		if (iface->bpf_tc_lnk && p->load.tc) {
			ret = bpf_link__update_program(iface->bpf_tc_lnk, p->load.tc);
			if (ret)
				log_message(LOG_ERR, "%s: link__update_program: %m",
					    p->name);
		}
		++st_if_r;
	}

	log_message(LOG_INFO, "%s: soft-reload successful, new program is loaded "
		    "on %d/%d interfaces", p->name, st_if_r, st_if_t);
	p->run = p->load;
	p->load.obj = NULL;
	p->load.tc = NULL;
	p->load.xdp = NULL;

	return;

 cant_soft_reload:
	log_message(LOG_DEBUG, "%s: soft reload is not possible, "
		    "proceed to a full reload", p->name);

	/* re-open bpf file again, this time setup templates */
	if (p->load.obj) {
		bpf_object__close(p->load.obj);
		p->load.obj = NULL;
	}
	if (gtp_bpf_prog_open(p, false))
		return;

	/* try loading bpf program into kernel */
	if (gtp_bpf_prog_load(p, false)) {
		log_message(LOG_INFO, "%s cannot reload bpf program, "
			    "keep previous running one", p->name);
		return;
	}

	/* detach running programs */
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		gtp_bpf_prog_detach(p, iface);
	}
	p->run = p->load;
	p->load.obj = NULL;
	p->load.tc = NULL;
	p->load.xdp = NULL;

 full_reload:
	list_for_each_entry(iface, &p->iface_bind_list, bpf_prog_list) {
		gtp_bpf_prog_attach(p, iface);
		++st_if_r;
	}
	log_message(LOG_INFO, "%s: full-reload successful, new program is loaded "
		    "on %d interfaces", p->name, st_if_r);
}


static void
gtp_bpf_prog_inotify_thread(struct thread *t)
{
	struct inotify_event *event;
	struct gtp_bpf_prog *p;
	ssize_t i = 0, len;
	char buf[8000];

	len = read(t->u.f.fd, buf, sizeof (buf));
	if (len <= 0) {
		log_message(LOG_ERR, "inotify/read: %m");
		thread_del(t);
		inotify_th = NULL;
		return;
	}

	while (i < len) {
		event = (struct inotify_event *)(buf + i);
		i += sizeof (*event) + event->len;

		bool found = false;
		list_for_each_entry(p, &daemon_data->bpf_progs, next) {
			if (event->wd == p->watch_id) {
				found = true;
				break;
			}
		}
		if (!found)
			continue;

		if (event->mask & IN_DELETE_SELF) {
			log_message(LOG_INFO, "%s: file '%s' is deleted",
				    p->name, p->path);
			p->watch_id = 0;

		} else {
			log_message(LOG_DEBUG, "%s: file '%s' is modified on filesystem",
				    p->name, p->path);
			gtp_bpf_prog_soft_reload(p);
		}
	}

	inotify_th = thread_add_read(master, gtp_bpf_prog_inotify_thread,
				     NULL, t->u.f.fd, TIMER_NEVER, 0);
}

/* watch bpf file with inotify (optional, not a fatal error if failing) */
static void
gtp_bpf_prog_watch(struct gtp_bpf_prog *p)
{
	if (inotify_th == NULL || p->watch_id)
		return;

	p->watch_id = inotify_add_watch(inotify_th->u.f.fd, p->path,
					IN_CLOSE_WRITE | IN_DELETE_SELF);
	if (p->watch_id < 0)
		log_message(LOG_ERR, "%s: %m", p->path);
}

/*
 *	BPF progs related
 */
void
gtp_bpf_prog_foreach_prog(int (*hdl) (struct gtp_bpf_prog *, void *), void *arg,
			  const char *filter_mode)
{
	struct gtp_bpf_prog *p;

	/* filter_mode == NULL means dump all */
	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (filter_mode == NULL ||
		    gtp_bpf_prog_has_tpl_mode(p, filter_mode)) {
			__sync_add_and_fetch(&p->refcnt, 1);
			(*(hdl)) (p, arg);
			__sync_sub_and_fetch(&p->refcnt, 1);
		}
	}
}

struct gtp_bpf_prog *
gtp_bpf_prog_get(const char *name)
{
	struct gtp_bpf_prog *p;

	list_for_each_entry(p, &daemon_data->bpf_progs, next) {
		if (!strncmp(p->name, name, strlen(name))) {
			__sync_add_and_fetch(&p->refcnt, 1);
			return p;
		}
	}

	return NULL;
}

int
gtp_bpf_prog_put(struct gtp_bpf_prog *p)
{
	__sync_sub_and_fetch(&p->refcnt, 1);
	return 0;
}

struct gtp_bpf_prog *
gtp_bpf_prog_alloc(const char *name)
{
	struct gtp_bpf_prog *new;

	PMALLOC(new);
	bsd_strlcpy(new->name, name, GTP_STR_MAX_LEN - 1);

	INIT_LIST_HEAD(&new->iface_bind_list);
	list_add_tail(&new->next, &daemon_data->bpf_progs);

	return new;
}

int
gtp_bpf_progs_init(void)
{
	int ifd;

	ifd = inotify_init();
	if (ifd < 0) {
		log_message(LOG_ERR, "inotify_init: %m");
		return -1;
	}

	inotify_th = thread_add_read(master, gtp_bpf_prog_inotify_thread,
				     NULL, ifd, TIMER_NEVER, 0);

	return 0;
}

int
gtp_bpf_progs_destroy(void)
{
	struct list_head *l = &daemon_data->bpf_progs;
	struct gtp_bpf_prog *p, *_p;

	list_for_each_entry_safe(p, _p, l, next) {
		gtp_bpf_prog_destroy(p);
	}
	return 0;
}



/*
 *	BPF progs template.
 *
 * each module handling bpf program (eg. gtp_fwd, cgn, ...) registers itself
 * with its specific callbacks.
 *
 * then, a bpf program will be attached to a bpf program template.
 * vty's mode-* command does it.
 */


/* local data */
static LIST_HEAD(bpf_prog_tpl_list);

void
gtp_bpf_prog_tpl_register(struct gtp_bpf_prog_tpl *tpl)
{
	list_add(&tpl->next, &bpf_prog_tpl_list);
}

const struct gtp_bpf_prog_tpl *
gtp_bpf_prog_tpl_get(const char *name)
{
	struct gtp_bpf_prog_tpl *tpl;

	list_for_each_entry(tpl, &bpf_prog_tpl_list, next) {
		if (!strcmp(tpl->name, name))
			return tpl;
	}
	return NULL;
}

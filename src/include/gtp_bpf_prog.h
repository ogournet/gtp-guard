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
#pragma once

#define BPF_PROG_TPL_MAX	6
#define BPF_PROG_VTY_CMD_MAX	8

typedef struct _gtp_bpf_prog gtp_bpf_prog_t;
typedef struct _gtp_interface gtp_interface_t;
struct bpf_object;

typedef struct _gtp_bpf_prog_var {
	const char *name;
	const void *value;
	uint32_t size;
} gtp_bpf_prog_var_t;


typedef struct _gtp_bpf_prog_vty_cmd {
	const char *name;
	int (*func)(gtp_bpf_prog_t *, void *, vty_t *);
	int (*iface_func)(gtp_bpf_prog_t *, void *, vty_t *, gtp_interface_t *);
} gtp_bpf_prog_vty_cmd_t;


/* BPF prog template */
typedef struct _gtp_bpf_prog_tpl {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	size_t			udata_alloc_size;

	int (*opened)(gtp_bpf_prog_t *, void *);
	int (*loaded)(gtp_bpf_prog_t *, void *);

	int (*iface_bind)(gtp_bpf_prog_t *, void *, gtp_interface_t *);
	int (*iface_bound)(gtp_bpf_prog_t *, void *, gtp_interface_t *);
	void (*iface_unbind)(gtp_bpf_prog_t *, void *, gtp_interface_t *);
	void (*iface_lladdr_updated)(gtp_bpf_prog_t *, void *, gtp_interface_t *);

	gtp_bpf_prog_vty_cmd_t vty[BPF_PROG_VTY_CMD_MAX];

	list_head_t		next;
} gtp_bpf_prog_tpl_t;


/* Flags */
enum gtp_bpf_prog_flags {
	GTP_BPF_PROG_FL_SHUTDOWN_BIT,
	GTP_BPF_PROG_FL_ERR_BIT,
};

/* BPF prog structure */
typedef struct _gtp_bpf_prog_type {
	char			progname[GTP_STR_MAX_LEN];
	struct bpf_program	*bpf_prg;
} gtp_bpf_prog_type_t;

typedef struct _gtp_bpf_prog {
	char			name[GTP_STR_MAX_LEN];
	char			description[GTP_STR_MAX_LEN];
	char			path[GTP_PATH_MAX_LEN];
	struct bpf_object	*bpf_obj;
	gtp_bpf_prog_type_t	tc;
	gtp_bpf_prog_type_t	xdp;

	const gtp_bpf_prog_tpl_t *tpl[BPF_PROG_TPL_MAX];
	void			*tpl_data[BPF_PROG_TPL_MAX];
	int			tpl_n;

	list_head_t		next;

	int			refcnt;
	unsigned long		flags;
} gtp_bpf_prog_t;


/* Prototypes */
extern int gtp_bpf_prog_obj_update_var(struct bpf_object *,
				       const gtp_bpf_prog_var_t *);
extern int gtp_bpf_prog_attach(gtp_bpf_prog_t *p, gtp_interface_t *iface);
extern void gtp_bpf_prog_detach(gtp_bpf_prog_t *p, gtp_interface_t *iface);
extern int gtp_bpf_prog_open(gtp_bpf_prog_t *);
extern int gtp_bpf_prog_load(gtp_bpf_prog_t *);
extern void gtp_bpf_prog_unload(gtp_bpf_prog_t *);
extern int gtp_bpf_prog_destroy(gtp_bpf_prog_t *);
extern int gtp_bpf_prog_tpl_data_set(gtp_bpf_prog_t *, const char *, void *);
extern void gtp_bpf_prog_vty_cmd(gtp_bpf_prog_t *, vty_t *,
				 const char *, const char *, gtp_interface_t *);
extern void gtp_bpf_prog_list_vty_cmd(vty_t *, const char *, const char *);
extern void gtp_bpf_prog_foreach_prog(int (*hdl) (gtp_bpf_prog_t *, void *),
				      void *, const char *);
extern gtp_bpf_prog_t *gtp_bpf_prog_get(const char *);
extern int gtp_bpf_prog_put(gtp_bpf_prog_t *);
extern gtp_bpf_prog_t *gtp_bpf_prog_alloc(const char *);
extern int gtp_bpf_progs_destroy(void);
extern void gtp_bpf_prog_tpl_register(gtp_bpf_prog_tpl_t *);
extern const gtp_bpf_prog_tpl_t *gtp_bpf_prog_tpl_get(const char *);


static inline bool
gtp_bpf_prog_has_tpl_mode(gtp_bpf_prog_t *p, const char *mode)
{
	int i;

	for (i = 0; i < p->tpl_n; i++)
		if (!strcmp(mode, p->tpl[i]->name))
			return true;
	return false;
}

static inline void *
gtp_bpf_prog_tpl_data_get(gtp_bpf_prog_t *p, const char *mode)
{
	int i;

	if (p == NULL)
		return NULL;
	for (i = 0; i < p->tpl_n; i++)
		if (!strcmp(mode, p->tpl[i]->name))
			return p->tpl_data[i];
	return NULL;
}

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
 * Copyright (C) 2023-2024 Alexandre Cassen, <acassen@gmail.com>
 */
#pragma once

/* Distributed lock */
#define DLOCK_HASHTAB_BITS    10
#define DLOCK_HASHTAB_SIZE    (1 << DLOCK_HASHTAB_BITS)
#define DLOCK_HASHTAB_MASK    (DLOCK_HASHTAB_SIZE - 1)

/* htab */
typedef struct _gtp_htab {
	struct hlist_head	*htab;
} gtp_htab_t;

/* Prototypes */
extern void gtp_htab_init(gtp_htab_t *, size_t);
extern gtp_htab_t *gtp_htab_alloc(size_t);
extern void gtp_htab_destroy(gtp_htab_t *);
extern void gtp_htab_free(gtp_htab_t *);

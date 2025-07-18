/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Alexandre Cassen, <acassen@gmail.com>
 *		Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2010, 2011, 2024 Olivier Gournet, <gournet.olivier@gmail.com>
 */


#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#include "tools.h"
#include "cdr_fwd-priv.h"


/*
 * read a ticket from spool file
 */
int
cdr_fwd_disk_read_ticket(struct cdr_fwd_context *ctx, int fd,
			 struct cdr_fwd_ticket_buffer *ticket,
			 const char *pathname)
{
	int ret;

	/* read ticket size and magic (mtype) */
	ret = disk_read(fd, ticket, 8);
	if (ret < 0) {
		err(ctx->log, "%s: %m", pathname);
		return -1;
	}

	/* end of file */
	if (ret == 0)
		return 0;

	/* check magic */
	if ((uint32_t)ticket->mtype != CDR_FWD_MTYPE_STOR_MAGIC) {
		err(ctx->log, "%s: bad magic: 0x%08x != 0x%08x",
		    pathname, ticket->mtype, CDR_FWD_MTYPE_STOR_MAGIC);
		return -1;
	}

	/* check file consistency */
	if (!ticket->size || ticket->size > CDR_FWD_TICKETS_MAX_BUFF) {
		err(ctx->log, "%s: bad ticket->size: %d",
			pathname, ticket->size);
		return -1;
	}

	/* read ticket payload */
	ret = disk_read(fd, ticket->mtext, ticket->size);
	if (ret != (int)ticket->size) {
		if (ret < 0)
			err(ctx->log, "%s: %m", pathname);
		else
			err(ctx->log, "%s: eof while reading", pathname);
		return -1;
	}

	return 8 + (int)ticket->size;
}


/*
 * write a ticket to window or spool file
 */
int
cdr_fwd_disk_write_ticket(struct cdr_fwd_context *ctx, int fd,
			  const struct cdr_fwd_ticket_buffer *t,
			  const char *pathname)
{
	struct {
		uint32_t size, magic;
	} v = { t->size, CDR_FWD_MTYPE_STOR_MAGIC };
	int ret = 0;

	/* Write ticket size and magic */
	ret = disk_write(fd, &v, 8);
	if (ret < 0) {
		err(ctx->log, "%s: %m", pathname);
		return -1;
	}

	/* Write ticket data */
	if (t->size > 0) {
		ret = disk_write(fd, t->mtext, t->size);
		if (ret < 0) {
			err(ctx->log, "%s: %m", pathname);
			return -1;
		}
	}

	return 8 + t->size;
}

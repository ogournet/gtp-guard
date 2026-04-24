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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "logger.h"
#include "utils.h"


/* ANSI colors per priority */
static const char *priority_colors[] = {
	[LOG_EMERG]	= "\033[1;41m",	/* bold on red bg */
	[LOG_ALERT]	= "\033[1;31m",	/* bold red */
	[LOG_CRIT]	= "\033[1;31m",	/* bold red */
	[LOG_ERR]	= "\033[31m",	/* red */
	[LOG_WARNING]	= "\033[33m",	/* yellow */
	[LOG_NOTICE]	= "\033[36m",	/* cyan */
	[LOG_INFO]	= "\033[0m",	/* default */
	[LOG_DEBUG]	= "\033[2m",	/* dim */
};

static struct log_options log_opts;

void
log_set_options(const struct log_options *opts)
{
	log_opts = *opts;
}

void
log_vprintf(const struct log_ctx *ctx, int priority, const char *fmt, va_list ap)
{
	enum log_timestamp ts_mode = LOG_TS_NONE;
	char buf[256];
	char *p = buf;
	va_list ap_cp;
	int off = 0, n;

	if (priority < 0 || priority > LOG_DEBUG)
		priority = LOG_DEBUG;
	if (priority == LOG_DEBUG && !log_opts.debug)
		return;

	if (log_opts.sd_prefix) {
		/* systemd journal prefix <priority> */
		off += scnprintf(buf + off, sizeof(buf) - off, "<%d>", priority);
	} else if (log_opts.color) {
		/* color start */
		off += scnprintf(buf + off, sizeof(buf) - off, "%s",
				 priority_colors[priority]);
	}

	/* timestamp — per-context override, fallback to global */
	if (!log_opts.sd_prefix &&
	    (ts_mode = ctx && ctx->timestamp != LOG_TS_NONE ?
	     ctx->timestamp : log_opts.timestamp) != LOG_TS_NONE) {
		struct timespec ts;
		struct tm tm;

		clock_gettime(CLOCK_REALTIME, &ts);
		localtime_r(&ts.tv_sec, &tm);

		if (ts_mode == LOG_TS_LONG)
			off += scnprintf(buf + off, sizeof(buf) - off,
					 "%04d-%02d-%02d",
					 tm.tm_year + 1900, tm.tm_mon + 1,
					 tm.tm_mday);
		off += scnprintf(buf + off, sizeof(buf) - off,
				 "%02d:%02d:%02d.%03ld",
				 tm.tm_hour, tm.tm_min, tm.tm_sec,
				 ts.tv_nsec / 1000000);
	}

	/* module prefix */
	if (ctx && *ctx->prefix)
		off += scnprintf(buf + off, sizeof(buf) - off, "%s[%s]",
				 ts_mode != LOG_TS_NONE ? " " : "", ctx->prefix);

	/* color reset */
	if (log_opts.color)
		off += scnprintf(buf + off, sizeof(buf) - off, "\033[0m");

	if (ts_mode != LOG_TS_NONE || (ctx && *ctx->prefix))
		buf[off++] = ' ';

	/* print message.  */
	va_copy(ap_cp, ap);
	n = vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
	if (off + n >= (int)sizeof(buf) - 1) {
		/* long message. truncate if going to systemd-log */
		if (!log_opts.sd_prefix &&
		    (p = malloc(off + n + 2)) != NULL) {
			memcpy(p, buf, off);
			off += vsnprintf(p + off, n + 1, fmt, ap_cp);
		} else {
			off = sizeof(buf) - 1;
		}
	} else {
		off += n;
	}
	va_end(ap_cp);

	/* add trailing '\n' if there is none */
	if (off > 0 && p[off - 1] != '\n')
		p[off++] = '\n';

	fwrite(p, 1, off, stderr);

	if (p != buf)
		free(p);

}

void
log_printf(const struct log_ctx *ctx, int priority, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_vprintf(ctx, priority, fmt, args);
	va_end(args);
}


void
log_message_va(const int priority, const char *fmt, va_list args)
{
	log_vprintf(NULL, priority, fmt, args);
}

void
log_message(const int priority, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_vprintf(NULL, priority, fmt, args);
	va_end(args);
}

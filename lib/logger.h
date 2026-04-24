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

#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>

/*
 *	Logging system — stderr only, systemd journal compatible.
 *
 *	- Prefixes lines with <priority> for systemd ingestion.
 *	- On a TTY: uses ANSI colors instead (unless NO_COLOR is set).
 *	- Optional datetime stamp (short or long format).
 */
enum log_timestamp {
	LOG_TS_NONE	= 0,
	LOG_TS_SHORT,		/* HH:MM:SS.mmm */
	LOG_TS_LONG,		/* YYYY-MM-DD HH:MM:SS.mmm */
};

struct log_options {
	enum log_timestamp	timestamp;
	bool			color;
	bool			sd_prefix;	/* systemd <priority> prefix */
	bool			debug;
};

struct log_ctx {
	char			prefix[48];
	enum log_timestamp	timestamp;
};

extern void log_set_options(const struct log_options *opts);
extern void log_vprintf(const struct log_ctx *ctx, int priority,
			const char *fmt, va_list ap);
extern void log_printf(const struct log_ctx *ctx, int priority,
		       const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* convenient macro, with and without a log context */
#define logc_emerg(ctx, ...)	log_printf(&(ctx), LOG_EMERG, __VA_ARGS__)
#define logc_alert(ctx, ...)	log_printf(&(ctx), LOG_ALERT, __VA_ARGS__)
#define logc_crit(ctx, ...)	log_printf(&(ctx), LOG_CRIT, __VA_ARGS__)
#define logc_error(ctx, ...)	log_printf(&(ctx), LOG_ERR, __VA_ARGS__)
#define logc_warn(ctx, ...)	log_printf(&(ctx), LOG_WARNING, __VA_ARGS__)
#define logc_notice(ctx, ...)	log_printf(&(ctx), LOG_NOTICE, __VA_ARGS__)
#define logc_info(ctx, ...)	log_printf(&(ctx), LOG_INFO, __VA_ARGS__)
#define logc_debug(ctx, ...)	log_printf(&(ctx), LOG_DEBUG, __VA_ARGS__)

#define log_emerg(...)		log_printf(NULL, LOG_EMERG, __VA_ARGS__)
#define log_alert(...)		log_printf(NULL, LOG_ALERT, __VA_ARGS__)
#define log_crit(...)		log_printf(NULL, LOG_CRIT, __VA_ARGS__)
#define log_error(...)		log_printf(NULL, LOG_ERR, __VA_ARGS__)
#define log_warn(...)		log_printf(NULL, LOG_WARNING, __VA_ARGS__)
#define log_notice(...)		log_printf(NULL, LOG_NOTICE, __VA_ARGS__)
#define log_info(...)		log_printf(NULL, LOG_INFO, __VA_ARGS__)
#define log_debug(...)		log_printf(NULL, LOG_DEBUG, __VA_ARGS__)

/* backward compatibility */
void log_message(const int facility, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void log_message_va(const int priority, const char *fmt, va_list args);

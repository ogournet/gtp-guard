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

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>

/* Opaque class structure */
typedef struct json_writer json_writer_t;

/* Create a new JSON stream */
json_writer_t *jsonw_new(FILE *f);

/* End output to JSON stream */
void jsonw_destroy(json_writer_t ** const self_p);

/* Cause output to have pretty whitespace */
void jsonw_pretty(json_writer_t *self, bool on);

/* Add property name */
void jsonw_name(json_writer_t *self, const char *name);

/* Add value  */
void jsonw_vprintf_enquote(json_writer_t *, const char *, va_list)
		__attribute__ ((format(printf, 2, 0)));
void jsonw_printf(json_writer_t *, const char *, ...)
		__attribute__ ((format(printf, 2, 3)));
void jsonw_string(json_writer_t *self, const char *value);
void jsonw_bool(json_writer_t *self, bool value);
void jsonw_float(json_writer_t *self, double number);
void jsonw_float_fmt(json_writer_t *self, const char *fmt, double num);
void jsonw_uint(json_writer_t *self, uint64_t number);
void jsonw_hu(json_writer_t *self, unsigned short number);
void jsonw_int(json_writer_t *self, int64_t number);
void jsonw_null(json_writer_t *self);
void jsonw_lluint(json_writer_t *self, unsigned long long int num);

/* Useful Combinations of name and value */
void jsonw_string_field(json_writer_t *self, const char *prop, const char *val);
void jsonw_string_field_fmt(json_writer_t *self, const char *prop, const char *fmt, ...);
void jsonw_bool_field(json_writer_t *self, const char *prop, bool value);
void jsonw_float_field(json_writer_t *self, const char *prop, double num);
void jsonw_uint_field(json_writer_t *self, const char *prop, uint64_t num);
void jsonw_hu_field(json_writer_t *self, const char *prop, unsigned short num);
void jsonw_int_field(json_writer_t *self, const char *prop, int64_t num);
void jsonw_null_field(json_writer_t *self, const char *prop);
void jsonw_lluint_field(json_writer_t *self, const char *prop,
			unsigned long long int num);
void jsonw_float_field_fmt(json_writer_t *self, const char *prop,
			   const char *fmt, double val);

/* Collections */
void jsonw_start_object(json_writer_t *self);
void jsonw_end_object(json_writer_t *self);

void jsonw_start_array(json_writer_t *self);
void jsonw_end_array(json_writer_t *self);

/* Override default exception handling */
typedef void (jsonw_err_handler_fn)(const char *);

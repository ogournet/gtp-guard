/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Soft:        libcdrforward provides an asynchronous client to forward cdrs to
 *              one or more cdrhubd instances (a proprietary cdr dispatcher daemon),
 *              with builtin facility to spool cdr on disk while not connected.
 *
 * Authors:     Olivier Gournet, <gournet.olivier@gmail.com>
 *
 * Copyright (C) 2025 Olivier Gournet, <gournet.olivier@gmail.com>
 */


/*
 * this file contains some wrappers to ease integration of some old
 * code from this author to this repository.
 */


#pragma once


/* have more meaning that TIMER_HZ for me */
#define USEC_PER_SEC				1000000


/* used to have a bigger lib for logging. avoid lots of replace */
#include <syslog.h>
#include "logger.h"

#define trace2(Mod, Fmt, ...)			\
	do { if (Mod & 2) log_message(LOG_DEBUG, Fmt, ## __VA_ARGS__); } while (0)
#define trace1(Mod, Fmt, ...)			\
	do { if (Mod & 1) log_message(LOG_DEBUG, Fmt, ##__VA_ARGS__); } while (0)
#define debug(Mod, Fmt, ...)	log_message(LOG_DEBUG, Fmt, ## __VA_ARGS__)
#define info(Mod, Fmt,...)	log_message(LOG_INFO, Fmt, ## __VA_ARGS__)
#define notice(Mod, Fmt, ...)	log_message(LOG_NOTICE, Fmt, ## __VA_ARGS__)
#define warn(Mod, Fmt, ...)	log_message(LOG_WARNING, Fmt, ## __VA_ARGS__)
#define err(Mod, Fmt, ...)	log_message(LOG_ERR, Fmt, ## __VA_ARGS__)


/* some const are really annoying. */
#include "scheduler.h"

typedef void (*task_func_t)(struct _thread *);

static inline struct _thread *
task_add_write(thread_master_t *m, task_func_t func,
		void *arg, int fd, unsigned long timer)
{
	return (struct _thread *)thread_add_write(m, (thread_func_t)func,
						  arg, fd, timer, 0);
}

static inline struct _thread *
task_add_read(thread_master_t *m, task_func_t func,
	       void *arg, int fd, unsigned long timer)
{
	return (struct _thread *)thread_add_read(m, (thread_func_t)func,
						 arg, fd, timer, 0);
}

static inline struct _thread *
task_add_timer(thread_master_t *m, task_func_t func, void *arg, unsigned long timer)
{
	return (struct _thread *)thread_add_timer(m, (thread_func_t)func,
						  arg, timer);
}

static inline struct _thread *
task_add_event(thread_master_t *m, task_func_t func, void *arg, int val)
{
	return (struct _thread *)thread_add_event(m, (thread_func_t)func,
						 arg, val);
}

/* some things are missing from list_head.h */
#include "list_head.h"

static inline void list_del(struct list_head *entry)
{
	list_head_del(entry);
}

/**
 * list_is_head - tests whether @list is the list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
}

/**
 * list_entry_is_head - test if the entry points to the head of the list
 * @pos:	the type * to cursor
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry_is_head(pos, head, member)				\
	list_is_head(&pos->member, (head))

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)


/* dunno why it's not in libc. */
int scnprintf(char *buf, size_t size, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));
int vscnprintf(char *buf, size_t size, const char *format, va_list args);


/* always useful */
#ifndef min
# define min(A, B) ((A) > (B) ? (B) : (A))
#endif
#ifndef max
# define max(A, B) ((A) > (B) ? (A) : (B))
#endif

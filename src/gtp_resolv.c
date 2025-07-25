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

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;
extern thread_master_t *master;


/*
 *	Service selection related
 */
static int
gtp_service_cmp(list_head_t *a, list_head_t *b)
{
	gtp_service_t *sa, *sb;

	sa = container_of(a, gtp_service_t, next);
	sb = container_of(b, gtp_service_t, next);

	return sa->prio - sb->prio;
}

gtp_service_t *
gtp_service_alloc(gtp_apn_t *apn, const char *str, int prio)
{
	gtp_service_t *new;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->prio = prio;
	if (str)
		bsd_strlcpy(new->str, str, GTP_APN_MAX_LEN);

	pthread_mutex_lock(&apn->mutex);
	list_add_tail(&new->next, &apn->service_selection);
	/* Just a few elements to be added so that is ok */
	list_sort(&apn->service_selection, gtp_service_cmp);
	pthread_mutex_unlock(&apn->mutex);

	return new;
}

int
gtp_service_destroy(gtp_apn_t *apn)
{
	gtp_service_t *s, *_s;

	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry_safe(s, _s, &apn->service_selection, next) {
		list_head_del(&s->next);
		FREE(s);
	}
	pthread_mutex_unlock(&apn->mutex);
	return 0;
}


/*
 *	Resolver helpers
 */
static int8_t
gtp_naptr_strncpy(char *str, size_t str_len, const u_char *buffer, const u_char *end)
{
	uint8_t *len = (uint8_t *) buffer;

	/* overflow prevention */
	if ((buffer + *len > end) || (*len > str_len))
		return -1;

	if (!*len)
		return 1;

	memcpy(str, buffer+1, *len);
	return *len + 1;
}

static int16_t
gtp_naptr_name_strncat(char *str, size_t str_len, const u_char *buffer, const u_char *end)
{
	int16_t offset = 0;
	const uint8_t *cp = buffer;
	uint8_t len, i;

	for (cp = buffer; cp < end && *cp; cp++) {
		len = *cp;

		/* truncate when needed */
		if (offset + len + 1 > str_len)
			goto end;

		for (i = 0; i < len && cp < end; i++)
			str[offset++] = *++cp;
		str[offset++] = '.';
	}

  end:
	return offset;
}

static void
ns_log_error(const char *dn, int error)
{
	switch(error) {
	case HOST_NOT_FOUND:
		log_message(LOG_INFO, "resolv[%s]: unknown zone", dn);
		break;
	case TRY_AGAIN:
		log_message(LOG_INFO, "resolv[%s]: No response for NS query", dn);
		break;
	case NO_RECOVERY:
		log_message(LOG_INFO, "resolv[%s]: Unrecoverable error", dn);
		break;
	case NO_DATA:
		log_message(LOG_INFO, "resolv[%s]: No NS records", dn);
		break;
	default:
		log_message(LOG_INFO, "resolv[%s]: Unexpected error", dn);
	}
}

static int
ns_bind_connect(gtp_apn_t *apn, int type)
{
	struct sockaddr_storage *addr = &apn->nameserver_bind;
	socklen_t addrlen;
	int fd, err;

	if (!apn->nameserver_bind.ss_family)
		return -1;

	/* Create UDP Client socket */
	fd = socket(addr->ss_family, type | SOCK_CLOEXEC, 0);
	err = inet_setsockopt_reuseaddr(fd, 1);
	err = (err) ? : inet_setsockopt_nolinger(fd, 1);
	err = (err) ? : inet_setsockopt_rcvtimeo(fd, 2000);
	err = (err) ? : inet_setsockopt_sndtimeo(fd, 2000);
	if (err) {
		log_message(LOG_INFO, "%s(): error creating TCP [%s]:%d socket"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		close(fd);
		return -1;
	}

	/* Bind listening channel */
	addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	err = bind(fd, (struct sockaddr *) addr, addrlen);
	if (err) {
		log_message(LOG_INFO, "%s(): Error binding to [%s]:%d (%m)"
				    , __FUNCTION__
				    , inet_sockaddrtos(addr)
				    , ntohs(inet_sockaddrport(addr)));
		close(fd);
		return -1;
	}

	err = connect(fd, (struct sockaddr *) &apn->nameserver, addrlen);
	if (err) {
		if (__test_bit(GTP_RESOLV_FL_CNX_PERSISTENT, &apn->flags) &&
		    errno == EADDRNOTAVAIL)
			goto err;

		log_message(LOG_INFO, "%s(): Error(%d) connecting to [%s]:%d (%m)"
				    , __FUNCTION__
				    , errno
				    , inet_sockaddrtos(&apn->nameserver)
				    , ntohs(inet_sockaddrport(&apn->nameserver)));
		goto err;
	}

	return fd;
  err:
	close(fd);
	return -1;
}

static int
ns_ctx_init(gtp_resolv_ctx_t *ctx)
{
	gtp_apn_t *apn = ctx->apn;
	struct sockaddr_storage *addr;
	int fd;

	fd = ns_bind_connect(apn, SOCK_STREAM);
	if (fd < 0)
		return -1;

	addr = (apn->nameserver.ss_family) ? &apn->nameserver : &daemon_data->nameserver;

	/* glibc resolver is providing extension to set remote nameserver.
	 * We are using this facility to set pre-allocated/pre-initialized
	 * socket connection to remote nameserver. Specially useful when you
	 * want to bind the connection to a local IP Address. */
	ctx->ns_rs._vcsock = fd;
	ctx->ns_rs._flags |= 0x00000003;	/* RES_F_VC|RES_F_CONN */
	ctx->ns_rs.options |= RES_USEVC;
	if (__test_bit(GTP_RESOLV_FL_CNX_PERSISTENT, &apn->flags))
		ctx->ns_rs.options |= RES_STAYOPEN;
	ctx->ns_rs._u._ext.nssocks[0] = fd;
	ctx->ns_rs._u._ext.nsaddrs[0] = MALLOC(sizeof(struct sockaddr_in6));
	*ctx->ns_rs._u._ext.nsaddrs[0] = *((struct sockaddr_in6 *) addr);
	ctx->ns_rs._u._ext.nscount = 1;
	return 0;
}


static int
ns_res_nquery_retry(gtp_resolv_ctx_t *ctx, int class, int type)
{
	int retry_count = 0;
	int ret;

retry:
	ns_ctx_init(ctx);
	ret = res_nquery(&ctx->ns_rs, ctx->nsdisp, class, type, ctx->nsbuffer, GTP_RESOLV_BUFFER_LEN);
	if (ret < 0) {
		ns_log_error(ctx->nsdisp, h_errno);
		if (h_errno == TRY_AGAIN && retry_count++ < ctx->max_retry) {
			log_message(LOG_INFO, "resolv[%s]: retry #%d", ctx->nsdisp, retry_count);
			goto retry;
		}
	}

	return ret;
}

static int
gtp_pgw_set(gtp_pgw_t *pgw, const u_char *rdata, size_t rdlen)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *) &pgw->addr;
	pgw->addr.ss_family = AF_INET;
	addr4->sin_addr.s_addr = *(uint32_t *) rdata;
	return 0;
}

static int
gtp_resolv_srv_a(gtp_resolv_ctx_t *ctx, gtp_pgw_t *pgw)
{
	int ret, i, err;

	/* Perform Query */
	snprintf(ctx->nsdisp, GTP_DISPLAY_BUFFER_LEN - 1, "%s", pgw->srv_name);
	ret = ns_res_nquery_retry(ctx, ns_c_in, ns_t_a);
	if (ret < 0) {
		res_nclose(&ctx->ns_rs);
		return -1;
	}

	ns_initparse(ctx->nsbuffer, ret, &ctx->msg);
	ret = ns_msg_count(ctx->msg, ns_s_an);
	for (i = 0; i < ret; i++) {
		err = ns_parserr(&ctx->msg, ns_s_an, i, &ctx->rr);
		if (err < 0)
			continue;

		/* Ensure only A are being used */
		if (ns_rr_type(ctx->rr) != ns_t_a)
			continue;

		gtp_pgw_set(pgw, ns_rr_rdata(ctx->rr), ns_rr_rdlen(ctx->rr));
        }

	return 0;
}

static int
gtp_resolv_pgw_srv(gtp_resolv_ctx_t *ctx, gtp_naptr_t *naptr)
{
	gtp_pgw_t *pgw;

	list_for_each_entry(pgw, &naptr->pgw, next) {
		gtp_resolv_srv_a(ctx, pgw);
	}

	return 0;
}

static int
gtp_pgw_cmp(list_head_t *a, list_head_t *b)
{
	gtp_pgw_t *pa, *pb;

	pa = container_of(a, gtp_pgw_t, next);
	pb = container_of(b, gtp_pgw_t, next);

	return pa->priority - pb->priority;
}

static int
gtp_pgw_append(gtp_naptr_t *naptr, char *name, size_t len)
{
	gtp_pgw_t *new;
	struct sockaddr_in *addr4;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->naptr = naptr;
	strncpy(new->srv_name, name, GTP_DISPLAY_SRV_LEN);

	/* Some default hard-coded value */
	addr4 = (struct sockaddr_in *) &new->addr;
	addr4->sin_port = htons(2123);
	new->priority = 10;
	new->weight = 20;

	list_add_tail(&new->next, &naptr->pgw);
	list_sort(&naptr->pgw, gtp_pgw_cmp);
	return 0;
}

static int
gtp_pgw_alloc(gtp_naptr_t *naptr, const u_char *rdata, size_t rdlen)
{
	gtp_pgw_t *new;
	const u_char *edata = rdata + rdlen;
	struct sockaddr_in *addr4;
	uint16_t port;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->next);
	new->naptr = naptr;
	addr4 = (struct sockaddr_in *) &new->addr;

	new->priority = ns_get16(rdata);
	rdata += NS_INT16SZ;
	new->weight = ns_get16(rdata);
	rdata += NS_INT16SZ;
	port = ns_get16(rdata);
	addr4->sin_port = htons(port);
	rdata += NS_INT16SZ;
	gtp_naptr_name_strncat(new->srv_name, GTP_DISPLAY_SRV_LEN, rdata, edata);

	list_add_tail(&new->next, &naptr->pgw);
	list_sort(&naptr->pgw, gtp_pgw_cmp);
	return 0;
}

static int
gtp_resolv_naptr_srv(gtp_resolv_ctx_t *ctx, gtp_naptr_t *naptr)
{
	int ret, i, err;

	/* Perform Query */
	snprintf(ctx->nsdisp, GTP_DISPLAY_BUFFER_LEN - 1, "%s", naptr->server);
	ret = ns_res_nquery_retry(ctx, ns_c_in, ns_t_srv);
        if (ret < 0) {
		res_nclose(&ctx->ns_rs);
		return -1;
	}

        ns_initparse(ctx->nsbuffer, ret, &ctx->msg);
        ret = ns_msg_count(ctx->msg, ns_s_an);
        for (i = 0; i < ret; i++) {
                err = ns_parserr(&ctx->msg, ns_s_an, i, &ctx->rr);
		if (err < 0)
			continue;

		/* Ensure only SRV are being used */
		if (ns_rr_type(ctx->rr) != ns_t_srv)
			continue;

		gtp_pgw_alloc(naptr, ns_rr_rdata(ctx->rr), ns_rr_rdlen(ctx->rr));
        }

	return 0;
}

int
gtp_resolv_pgw(gtp_resolv_ctx_t *ctx, list_head_t *l)
{
	gtp_naptr_t *naptr;
	int ret;

	list_for_each_entry(naptr, l, next) {
		if (naptr->server_type == ns_t_srv) {
			ret = gtp_resolv_naptr_srv(ctx, naptr);
			if (ret < 0)
				return -1;

			ret = gtp_resolv_pgw_srv(ctx, naptr);
			if (ret < 0)
				return -1;
			continue;
		}

		if (naptr->server_type == ns_t_a) {
			gtp_pgw_append(naptr, naptr->server, strlen(naptr->server));
			ret = gtp_resolv_pgw_srv(ctx, naptr);
			if (ret < 0)
				return -1;
		}
	}

	return 0;
}

static int
gtp_naptr_alloc(list_head_t *l, const u_char *rdata, size_t rdlen)
{
	gtp_naptr_t *new;
	const u_char *edata = rdata + rdlen;
	int16_t len = 0;

	PMALLOC(new);
	INIT_LIST_HEAD(&new->pgw);
	INIT_LIST_HEAD(&new->next);

	/* Parse ns response according to IETF-RFC2915.8 */
	new->order = ns_get16(rdata);
	rdata += NS_INT16SZ;
	new->preference = ns_get16(rdata);
	rdata += NS_INT16SZ;

	/* Flags */
	len = gtp_naptr_strncpy(new->flags, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;
	rdata += len;
	if (*new->flags == 'A' || *new->flags == 'a')
		new->server_type = ns_t_a;
	else if (*new->flags == 'S' || *new->flags == 's')
		new->server_type = ns_t_srv;

	/* Services */
	len = gtp_naptr_strncpy(new->service, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;
	rdata += len;

	/* REGEXP */
	len = gtp_naptr_strncpy(new->regexp, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;
	rdata += len;

	/* Server */
	len = gtp_naptr_name_strncat(new->server, GTP_APN_MAX_LEN, rdata, edata);
	if (len < 0)
		goto end;

  end:
	list_add_tail(&new->next, l);
	return 0;
}

int
gtp_resolv_naptr(gtp_resolv_ctx_t *ctx, list_head_t *l, const char *format, ...)
{
	va_list args;
	int ret, i, err;

	/* Perform Query */
	va_start(args, format);
	vsnprintf(ctx->nsdisp, GTP_DISPLAY_BUFFER_LEN, format, args);
	va_end(args);

	ret = ns_res_nquery_retry(ctx, ns_c_in, ns_t_naptr);
	if (ret < 0) {
		res_nclose(&ctx->ns_rs);
		return -1;
	}

	ns_initparse(ctx->nsbuffer, ret, &ctx->msg);
	ret = ns_msg_count(ctx->msg, ns_s_an);
	for (i = 0; i < ret; i++) {
		err = ns_parserr(&ctx->msg, ns_s_an, i, &ctx->rr);
		if (err < 0)
			continue;

		/* Ensure only NAPTR are being used */
		if (ns_rr_type(ctx->rr) != ns_t_naptr)
			continue;

		gtp_naptr_alloc(l, ns_rr_rdata(ctx->rr), ns_rr_rdlen(ctx->rr));
        }

	return 0;
}


gtp_resolv_ctx_t *
gtp_resolv_ctx_alloc(gtp_apn_t *apn)
{
	gtp_resolv_ctx_t *ctx;
	struct sockaddr_storage *addr;

	PMALLOC(ctx);
	if (!ctx)
		return NULL;

	ctx->apn = apn;
	ctx->max_retry = apn->resolv_max_retry;
	addr = (apn->nameserver.ss_family) ? &apn->nameserver : &daemon_data->nameserver;
	if (!addr->ss_family) {
		log_message(LOG_INFO, "%s(): No nameserver configured... Ignoring..."
				    , __FUNCTION__);
		FREE(ctx);
		return NULL;
	}

	ctx->realm = (strlen(apn->realm)) ? apn->realm : daemon_data->realm;

	res_ninit(&ctx->ns_rs);
	ctx->ns_rs.nsaddr_list[0] = *((struct sockaddr_in *) addr);
	ctx->ns_rs.nscount = 1;
	ctx->ns_rs.retrans = (apn->nameserver_timeout) ? apn->nameserver_timeout : 0;

	return ctx;
}

int
gtp_resolv_ctx_destroy(gtp_resolv_ctx_t *ctx)
{
	res_nclose(&ctx->ns_rs);
	FREE(ctx);
	return 0;
}

/*
 *	Resolver helpers
 */
static int
gtp_pgw_destroy(list_head_t *l)
{
	gtp_pgw_t *pgw, *pgw_tmp;

	list_for_each_entry_safe(pgw, pgw_tmp, l, next) {
		list_head_del(&pgw->next);
		FREE(pgw);
	}

	return 0;
}

static int
gtp_pgw_show(vty_t *vty, list_head_t *l)
{
	gtp_pgw_t *pgw;

	list_for_each_entry(pgw, l, next) {
		vty_out(vty, "  %s\t\t[%s]:%d\tPrio:%d Weight:%d%s"
			   , pgw->srv_name
			   , inet_sockaddrtos(&pgw->addr)
			   , ntohs(inet_sockaddrport(&pgw->addr))
			   , pgw->priority
			   , pgw->weight
			   , VTY_NEWLINE);
	}

	return 0;
}

static int
gtp_pgw_dump(list_head_t *l)
{
	gtp_pgw_t *pgw;

	list_for_each_entry(pgw, l, next) {
		printf(" %s\t\t[%s]:%d\tPrio:%d Weight:%d\n",
			pgw->srv_name,
			inet_sockaddrtos(&pgw->addr),
			ntohs(inet_sockaddrport(&pgw->addr)),
			pgw->priority,
			pgw->weight);
	}

	return 0;
}

int
gtp_naptr_show(vty_t *vty, gtp_apn_t *apn)
{
	list_head_t *l = &apn->naptr;
	gtp_naptr_t *naptr;

	vty_out(vty, "Access-Point-Name %s%s", apn->name, VTY_NEWLINE);
	pthread_mutex_lock(&apn->mutex);
	list_for_each_entry(naptr, l, next) {
		vty_out(vty, " %s\t(%s, %s, Order:%d, Pref:%d)%s"
			   , naptr->server, (naptr->server_type == ns_t_srv) ? "SRV" : "A"
			   , naptr->service
			   , naptr->order
			   , naptr->preference
			   , VTY_NEWLINE);
		gtp_pgw_show(vty, &naptr->pgw);
	}
	pthread_mutex_unlock(&apn->mutex);

	return 0;
}

int
gtp_naptr_dump(list_head_t *l)
{
	gtp_naptr_t *naptr;

	list_for_each_entry(naptr, l, next) {
		printf("%s\t(%s, %s, Order:%d, Pref:%d)\n",
			naptr->server, (naptr->server_type == ns_t_srv) ? "SRV" : "A",
			naptr->service,
			naptr->order,
			naptr->preference);
		gtp_pgw_dump(&naptr->pgw);
	}

	return 0;
}

int
gtp_naptr_destroy(list_head_t *l)
{
	gtp_naptr_t *naptr, *naptr_tmp;

	list_for_each_entry_safe(naptr, naptr_tmp, l, next) {
		gtp_pgw_destroy(&naptr->pgw);
		list_head_del(&naptr->next);
		FREE(naptr);
	}

	return 0;
}

gtp_naptr_t *
__gtp_naptr_get(gtp_apn_t *apn, const char *name)
{
	gtp_naptr_t *naptr;

	if (!apn || list_empty(&apn->naptr))
		return NULL;

	if (!name)
		return list_first_entry(&apn->naptr, gtp_naptr_t, next);

	list_for_each_entry(naptr, &apn->naptr, next) {
		if (strstr(naptr->service, name))
			return naptr;
	}

	return NULL;
}

gtp_naptr_t *
gtp_naptr_get(gtp_apn_t *apn, const char *name)
{
	gtp_naptr_t *naptr = NULL;

	pthread_mutex_lock(&apn->mutex);
	naptr = __gtp_naptr_get(apn, name);
	pthread_mutex_unlock(&apn->mutex);

	return naptr;
}

/*
 *	Resolver init
 */
int
gtp_resolv_init(void)
{
	return 0;
}

int
gtp_resolv_destroy(void)
{

	/* FIXME: release cache stuffs */

	return 0;
}

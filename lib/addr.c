/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024, 2025, 2026 Olivier Gournet, <gournet.olivier@gmail.com> */

#include <linux/version.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <time.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>

#define SA_USE_AF_UNIX
#define SA_USE_AF_PACKET
#include "addr.h"


socklen_t
sa_len(const union sa *a)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		return sizeof (a->sin);
	case AF_INET6:
		return sizeof (a->sin6);
	case AF_UNIX:
		return SUN_LEN(&a->sun);
	case AF_PACKET:
		return sizeof (a->sll);
	default:
		return 0;
	}
}

void
sa_copy(union sa *dst, const union sa *src)
{
	socklen_t l = sa_len(src);

	if (l > 0)
		memcpy(&dst->ss, &src->ss, l);
	else
		dst->sa.sa_family = AF_UNSPEC;
}

void
sa_from_ip4(union sa *a, uint32_t ipaddr)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = ipaddr;
	a->sin.sin_port = 0;
}

void
sa_from_ip4_port(union sa *a, uint32_t ipaddr, uint16_t port)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = ipaddr;
	a->sin.sin_port = htons(port);
}

void
sa_from_ip4h(union sa *a, uint32_t ipaddr_host)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = htonl(ipaddr_host);
	a->sin.sin_port = 0;
}

void
sa_from_ip4h_port(union sa *a, uint32_t ipaddr_host, uint16_t port)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = htonl(ipaddr_host);
	a->sin.sin_port = htons(port);
}

uint32_t
sa_ip4(const union sa *a)
{
	if (a->family == AF_INET)
		return a->sin.sin_addr.s_addr;
	return 0;
}

uint32_t
sa_ip4h(const union sa *a)
{
	if (a->family == AF_INET)
		return ntohl(a->sin.sin_addr.s_addr);
	return 0;
}

void
sa_from_ip6(union sa *a, const struct in6_addr *ipaddr)
{
	a->family = AF_INET6;
	memcpy(a->sin6.sin6_addr.s6_addr, ipaddr->s6_addr,
	       sizeof (ipaddr->s6_addr));
	a->sin6.sin6_port = 0;
}

void
sa_from_ip6_port(union sa *a, const struct in6_addr *ipaddr, uint16_t port)
{
	a->family = AF_INET6;
	memcpy(a->sin6.sin6_addr.s6_addr, ipaddr->s6_addr,
	       sizeof (ipaddr->s6_addr));
	a->sin6.sin6_port = htons(port);
}

void
sa_from_ip6_bytes(union sa *a, const uint8_t *bytes)
{
	a->family = AF_INET6;
	memcpy(a->sin6.sin6_addr.s6_addr, bytes, sizeof (a->sin6.sin6_addr));
	a->sin6.sin6_port = 0;
	a->sin6.sin6_flowinfo = 0;
	a->sin6.sin6_scope_id = 0;
}

const struct in6_addr *
sa_ip6(const union sa *a)
{
	if (a->family == AF_INET6)
		return &a->sin6.sin6_addr;
	return NULL;
}

uint16_t
sa_port(const union sa *a)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		return ntohs(a->sin.sin_port);
	case AF_INET6:
		return ntohs(a->sin6.sin6_port);
	default:
		return 0;
	}
}

uint16_t
sa_portn(const union sa *a)
{
	return htons(sa_port(a));
}

void
sa_set_port(union sa *a, uint16_t port)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		a->sin.sin_port = htons(port);
		break;
	case AF_INET6:
		a->sin6.sin6_port = htons(port);
		break;
	}
}

int
sa_cmp(const union sa *la, const union sa *ra)
{
	int r;

	if (la->sa.sa_family < ra->sa.sa_family)
		return -1;
	else if (la->sa.sa_family > ra->sa.sa_family)
		return 1;

	switch (la->sa.sa_family) {
	case AF_INET:
		r = memcmp(&la->sin.sin_addr, &ra->sin.sin_addr,
			   sizeof (la->sin.sin_addr));
		if (r != 0)
			return r;
		if (la->sin.sin_port < ra->sin.sin_port)
			return -1;
		if (la->sin.sin_port > ra->sin.sin_port)
			return 1;
		return 0;

	case AF_INET6:
		r = memcmp(&la->sin6.sin6_addr, &ra->sin6.sin6_addr,
			   sizeof (la->sin6.sin6_addr));
		if (r != 0)
			return r;
		if (la->sin6.sin6_port < ra->sin6.sin6_port)
			return -1;
		if (la->sin6.sin6_port > ra->sin6.sin6_port)
			return 1;
		return 0;

	case AF_UNIX:
		return strcmp(la->sun.sun_path, ra->sun.sun_path);

	case AF_PACKET:
		if (la->sll.sll_ifindex < ra->sll.sll_ifindex)
			return -1;
		if (la->sll.sll_ifindex > ra->sll.sll_ifindex)
			return 1;
		return 0;

	default:
		return 0;
	}
}

int
sa_cmp_ip(const union sa *la, const union sa *ra)
{
	if (la->sa.sa_family < ra->sa.sa_family)
		return -1;
	else if (la->sa.sa_family > ra->sa.sa_family)
		return 1;

	switch (la->sa.sa_family) {
	case AF_INET:
		return memcmp(&la->sin.sin_addr, &ra->sin.sin_addr,
			      sizeof (la->sin.sin_addr));
	case AF_INET6:
		return memcmp(&la->sin6.sin6_addr, &ra->sin6.sin6_addr,
			      sizeof (la->sin6.sin6_addr));
	default:
		return 0;
	}
}

int
sa_cmp_port(const union sa *la, const union sa *ra)
{
	if (la->sa.sa_family < ra->sa.sa_family)
		return -1;
	else if (la->sa.sa_family > ra->sa.sa_family)
		return 1;

	switch (la->sa.sa_family) {
	case AF_INET:
		return !(la->sin.sin_port == ra->sin.sin_port);
	case AF_INET6:
		return !(la->sin6.sin6_port == ra->sin6.sin6_port);
	default:
		return 0;
	}
}


bool
sa_is_unicast(const union sa *a)
{
	uint32_t addr;
	uint8_t last;

	if (a == NULL)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		addr = ntohl(a->sin.sin_addr.s_addr);

		/* must not be a bcast addr or network addr */
		last = addr & 0xff;
		if (last == 0 || last == 0xff)
			return false;

		/* must not be a multicast address */
		if ((addr & 0xf0000000) >= 0xe0000000)
			return false;

		return true;

	case AF_INET6:
		if (!memcmp(&a->sin6.sin6_addr, &in6addr_any,
			    sizeof (in6addr_any)))
			return false;
		return true;

	default:
		return false;
	}
}

bool
sa_is_any(const union sa *a)
{
	if (a == NULL)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		return a->sin.sin_addr.s_addr == INADDR_ANY;
	case AF_INET6:
		return !memcmp(&a->sin6.sin6_addr, &in6addr_any,
			       sizeof (in6addr_any));
	default:
		return false;
	}
}

bool
sa_is_loopback(const union sa *a)
{
	if (a == NULL)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		return (ntohl(a->sin.sin_addr.s_addr) >> 24) == 127;
	case AF_INET6:
		return !memcmp(&a->sin6.sin6_addr, &in6addr_loopback,
			       sizeof (in6addr_loopback));
	default:
		return false;
	}
}

bool
sa_is_multicast(const union sa *a)
{
	if (a == NULL)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		return (ntohl(a->sin.sin_addr.s_addr) >> 28) == 0xe;
	case AF_INET6:
		return a->sin6.sin6_addr.s6_addr[0] == 0xff;
	default:
		return false;
	}
}

bool
sa_is_linklocal(const union sa *a)
{
	uint32_t addr;

	if (a == NULL)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		addr = ntohl(a->sin.sin_addr.s_addr);
		return (addr >> 16) == 0xa9fe;  /* 169.254.0.0/16 */
	case AF_INET6:
		return (a->sin6.sin6_addr.s6_addr[0] == 0xfe &&
			(a->sin6.sin6_addr.s6_addr[1] & 0xc0) == 0x80);
	default:
		return false;
	}
}


/*
 * sockaddr -> ipv4:port or [ipv6]:port
 */
char *
sa_str(const union sa *a, char *buf, size_t buf_size)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	if (getnameinfo(&a->sa, sizeof (*a),
			hbuf, sizeof (hbuf), sbuf, sizeof (sbuf),
			NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
		if (sbuf[0] == '0' && !sbuf[1])
			snprintf(buf, buf_size, "%s", hbuf);
		else if (a->family == AF_INET6)
			snprintf(buf, buf_size, "[%s]:%s", hbuf, sbuf);
		else
			snprintf(buf, buf_size, "%s:%s", hbuf, sbuf);
	} else {
		buf[0] = 0;
	}

	return buf;
}

/*
 * sockaddr -> ipv4 or ipv6
 */
char *
sa_str_ip(const union sa *a, char *buf, size_t buf_size)
{
	if (getnameinfo(&a->sa, sizeof (*a),
			buf, buf_size, NULL, 0,
			NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
	} else {
		buf[0] = 0;
	}

	return buf;
}

/*
 * sockaddr -> port
 */
char *
sa_str_port(const union sa *a, char *buf, size_t buf_size)
{
	uint16_t port = sa_port(a);

	if (port)
		snprintf(buf, buf_size, "%d", port);
	else
		buf[0] = 0;

	return buf;
}

/*
 * thread-local buffer stringify variants
 */
char *
sa_sstr(const union sa *a)
{
	static __thread char buf[NI_MAXHOST + NI_MAXSERV + 2];

	return sa_str(a, buf, sizeof (buf));
}

char *
sa_sstr_ip(const union sa *a)
{
	static __thread char buf[NI_MAXHOST];

	return sa_str_ip(a, buf, sizeof (buf));
}

char *
sa_sstr_port(const union sa *a)
{
	static __thread char buf[NI_MAXSERV];

	return sa_str_port(a, buf, sizeof (buf));
}


/*
 * parse ipv4, ipv6, ipv4:port, [ipv6]:port or /tmp/unixsock
 */
int
sa_parse(const char *addr, union sa *out)
{
	struct addrinfo *res, hints;
	char buf[strlen(addr) + 1];
	unsigned int port;
	char *paddr, *pport, *end;
	int ret;

	if (*addr == '/') {
		out->family = AF_UNIX;
		snprintf(out->sun.sun_path, sizeof(out->sun.sun_path), "%s", addr);
		return 0;
	}

	strcpy(buf, addr);
	paddr = buf;

	memset(&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_NUMERICHOST;

	/* remove [] from ipv6 address (port is after) */
	if (paddr[0] == '[') {
		paddr++;
		pport = strchr(paddr, ']');
		if (pport)
			*pport++ = 0;

	} else {
		pport = paddr;
	}

	pport = strchr(pport, ':');
	if (pport != NULL) {
		/* multiple ':': must be an ipv6 */
		if (strchr(pport + 1, ':') == NULL)
			*pport++ = 0;
		else
			pport = NULL;
	}

	ret = getaddrinfo(paddr, NULL, &hints, &res);
	if (ret || !res)
		return -1;

	memcpy(out, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (!pport)
		return 0;

	port = strtoul(pport, &end, 10);
	if (port > 65535 || *end)
		return -1;

	switch (out->sa.sa_family) {
	case AF_INET:
	default:
		out->sin.sin_port = htons(port);
		break;
	case AF_INET6:
		out->sin6.sin6_port = htons(port);
		break;
	}

	return 0;
}

/*
 * parse ipv4 or ipv6, with optional netmask and range. ex:
 *
 * 172.18.68.0/24
 * 172.18.68.200-172.18.68.250
 *
 * for ipv6, out_count is the number of /64 prefixes
 *
 * first_ip is false   10.13.26.16/8 => 10.13.26.16
 * first_ip is true    10.13.26.16/8 => 10.0.0.0
 */
int
sa_parse_opt(const char *paddr, union sa *a,
	     uint32_t *out_netmask, uint64_t *out_count,
	     bool first_ip)
{
	struct addrinfo *res, hints;
	char buf[strlen(paddr) + 1];
	uint32_t mask_max, mask;
	char *nmask, *end, *srange;
	union sa aend;
	int ret;

	strcpy(buf, paddr);

	aend.family = AF_UNSPEC;
	if (out_count != NULL) {
		*out_count = 1;
		srange = strchr(buf, '-');
		if (srange != NULL) {
			*srange = 0;
			if (sa_parse_opt(srange + 1, &aend, NULL, NULL, 0))
				return -1;
		}
	}

	memset(&hints, 0, sizeof (hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags |= AI_NUMERICHOST;

	nmask = strchr(buf, '/');
	if (nmask)
		*nmask++ = 0;

	ret = getaddrinfo(buf, NULL, &hints, &res);
	if (ret || !res)
		return -1;

	memcpy(a, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (!nmask && !out_netmask && !out_count)
		return 0;

	mask_max = a->family == AF_INET6 ? 128 : 32;
	if (nmask) {
		mask = strtoul(nmask, &end, 10);
		if (mask > mask_max || *end)
			return -1;

		switch (a->family) {
		case AF_INET:
			if (first_ip)
				a->sin.sin_addr.s_addr &=
					htonl(~((1 << (mask_max - mask)) - 1));
			if (out_count != NULL)
				*out_count = 1 << (32 - mask);
			break;
		case AF_INET6:
			if (first_ip && (mask & 0x07))
				a->sin6.sin6_addr.s6_addr[mask / 8] &=
					~(0xff >> (mask & 0x07));
			if (first_ip && mask <= 120)
				memset(a->sin6.sin6_addr.s6_addr +
				       ((mask + 7) / 8),
				       0x00, 16 - ((mask + 7) / 8));
			if (out_count != NULL && mask < 64)
				*out_count = 1ULL << (64 - mask);
			break;
		}

	} else {
		mask = mask_max;
	}

	if (out_netmask)
		*out_netmask = mask;

	if (aend.family != AF_UNSPEC) {
		if (aend.family != a->family)
			return -1;
		switch (a->family) {
		case AF_INET:
			if (ntohl(aend.sin.sin_addr.s_addr) >
			    ntohl(a->sin.sin_addr.s_addr)) {
				*out_count = ntohl(aend.sin.sin_addr.s_addr) -
					ntohl(a->sin.sin_addr.s_addr) + 1;
			}
			break;

		case AF_INET6:
			*out_count =
				((uint64_t)(aend.sin6.sin6_addr.s6_addr32[0] -
				  a->sin6.sin6_addr.s6_addr32[0]) << 32) |
				(aend.sin6.sin6_addr.s6_addr32[1] -
				 a->sin6.sin6_addr.s6_addr32[1]);
			break;
		}
	}

	return 0;
}


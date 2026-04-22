/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024, 2025, 2026 Olivier Gournet, <gournet.olivier@gmail.com> */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <linux/if_packet.h>


/*
 * Operations on raw ipv4 (uint32_t, network byte order) and
 * ipv6 (struct in6_addr) addresses.
 */

/* parsing */
int ip4_parse(uint32_t *out, const char *str);
int ip6_parse(struct in6_addr *out, const char *str);

/* stringify. _r variants are 'reentrant' */
char *ip4_str(uint32_t addr);
char *ip4_str_r(uint32_t addr, char *buf, size_t buf_size);
char *ip6_str(const struct in6_addr *addr);
char *ip6_str_r(const struct in6_addr *addr, char *buf, size_t buf_size);

/* comparison */
static int ip6_cmp(const struct in6_addr *a, const struct in6_addr *b);
static bool ip6_equal(const struct in6_addr *a, const struct in6_addr *b);

/* classification */
static bool ip4_is_unicast(uint32_t addr);
static bool ip4_is_any(uint32_t addr);
static bool ip4_is_loopback(uint32_t addr);
static bool ip4_is_multicast(uint32_t addr);
static bool ip4_is_linklocal(uint32_t addr);
static bool ip6_is_any(const struct in6_addr *a);
static bool ip6_is_loopback(const struct in6_addr *a);
static bool ip6_is_multicast(const struct in6_addr *a);
static bool ip6_is_linklocal(const struct in6_addr *a);

/* hashing */
static uint32_t ip4_hash(uint32_t addr);
static uint32_t ip6_hash(const struct in6_addr *addr);


/*
 * Type-safe, cast-free wrapper around sockaddr_storage. Holds either
 * an ipv4 or ipv6 address with its port, ready to use for socket
 * operations (bind, connect, sendto, ...).
 */
union sockaddr_any
{
	sa_family_t		family;
	struct sockaddr		sa;
	struct sockaddr_in	sin;	/* AF_INET */
	struct sockaddr_in6	sin6;	/* AF_INET6 */
	struct sockaddr_un	sun;	/* AF_UNIX */
	struct sockaddr_ll	sll;	/* AF_PACKET */
	struct sockaddr_storage ss;
};

typedef union sockaddr_any sockaddr_t;


/* initialization & copy */
static void sa_zero(sockaddr_t *a);
socklen_t sa_len(const sockaddr_t *a);
void sa_cpy(sockaddr_t *dst, const sockaddr_t *src);

/* construction */
static void sa_from_ip4(sockaddr_t *a, uint32_t ipaddr);
static void sa_from_ip4_port(sockaddr_t *a, uint32_t ipaddr, uint16_t port);
static void sa_from_ip4h(sockaddr_t *a, uint32_t ipaddr_host);
static void sa_from_ip4h_port(sockaddr_t *a, uint32_t ipaddr_host, uint16_t port);
static void sa_from_ip6(sockaddr_t *a, const struct in6_addr *ipaddr);
static void sa_from_ip6_port(sockaddr_t *a, const struct in6_addr *ipaddr, uint16_t port);
static void sa_from_ip6_pfx(sockaddr_t *a, const uint8_t *bytes, int nbytes);
static void sa_set_port(sockaddr_t *a, uint16_t port);

/* parsing */
int sa_parse(sockaddr_t *out, const char *addr);
int sa_parse_opt(sockaddr_t *out, const char *addr, uint32_t *out_netmask,
		 uint64_t *out_count, bool first_ip);

/* extraction */
static uint32_t sa_ip4(const sockaddr_t *a);
static uint32_t sa_ip4h(const sockaddr_t *a);
static const struct in6_addr *sa_ip6(const sockaddr_t *a);
static uint16_t sa_port(const sockaddr_t *a);
static uint16_t sa_portn(const sockaddr_t *a);

/* stringify. _r variants are 'reentrant' */
char *sa_str(const sockaddr_t *a);
char *sa_str_ip(const sockaddr_t *a);
char *sa_str_port(const sockaddr_t *a);
char *sa_str_r(const sockaddr_t *a, char *buf, size_t buf_size);
char *sa_str_ip_r(const sockaddr_t *a, char *buf, size_t buf_size);
char *sa_str_port_r(const sockaddr_t *a, char *buf, size_t buf_size);

/* family predicates */
static sa_family_t sa_family(const sockaddr_t *a);
bool sa_is_unicast(const sockaddr_t *a);
bool sa_is_any(const sockaddr_t *a);
bool sa_is_loopback(const sockaddr_t *a);
bool sa_is_multicast(const sockaddr_t *a);
bool sa_is_linklocal(const sockaddr_t *a);

/* comparison. returns, like strcmp, -1 less, 0 equal or 1 greater  */
int sa_cmp(const sockaddr_t *la, const sockaddr_t *ra);
int sa_cmp_ip(const sockaddr_t *la, const sockaddr_t *ra);
int sa_cmp_port(const sockaddr_t *la, const sockaddr_t *ra);



/*
 * inline implementations
 */


static inline int
ip6_cmp(const struct in6_addr *a, const struct in6_addr *b)
{
	return memcmp(a, b, sizeof (struct in6_addr));
}

static inline bool
ip6_equal(const struct in6_addr *a, const struct in6_addr *b)
{
	return (((a->s6_addr32[0] ^ b->s6_addr32[0]) |
		 (a->s6_addr32[1] ^ b->s6_addr32[1]) |
		 (a->s6_addr32[2] ^ b->s6_addr32[2]) |
		 (a->s6_addr32[3] ^ b->s6_addr32[3])) == 0);
}

static inline bool
ip4_is_any(uint32_t addr)
{
	return addr == INADDR_ANY;
}

static inline bool
ip4_is_unicast(uint32_t addr)
{
	uint32_t h = ntohl(addr);
	uint8_t last = h & 0xff;

	if (last == 0 || last == 0xff)
		return false;
	if ((h & 0xf0000000) >= 0xe0000000)
		return false;
	return true;
}

static inline bool
ip4_is_loopback(uint32_t addr)
{
	return (ntohl(addr) >> 24) == 127;
}

static inline bool
ip4_is_multicast(uint32_t addr)
{
	return (ntohl(addr) >> 28) == 0xe;
}

static inline bool
ip4_is_linklocal(uint32_t addr)
{
	return (ntohl(addr) >> 16) == 0xa9fe;	/* 169.254.0.0/16 */
}

static inline bool
ip6_is_any(const struct in6_addr *a)
{
	return (((a->s6_addr32[0]) |
		 (a->s6_addr32[1]) |
		 (a->s6_addr32[2]) |
		 (a->s6_addr32[3])) == 0);
}

static inline bool
ip6_is_loopback(const struct in6_addr *a)
{
	return (a->s6_addr32[0] == 0 &&
		a->s6_addr32[1] == 0 &&
		a->s6_addr32[2] == 0 &&
		a->s6_addr32[3] == htonl(1));
}

static inline bool
ip6_is_multicast(const struct in6_addr *a)
{
	return a->s6_addr[0] == 0xff;
}

static inline bool
ip6_is_linklocal(const struct in6_addr *a)
{
	return (a->s6_addr[0] == 0xfe && (a->s6_addr[1] & 0xc0) == 0x80);
}

static inline uint32_t
ip4_hash(uint32_t addr)
{
	uint32_t h = addr;

	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

static inline uint32_t
ip6_hash(const struct in6_addr *addr)
{
	const uint32_t *p = (const uint32_t *) &addr->s6_addr;
	uint32_t h;

	h = p[0] ^ p[1] ^ p[2] ^ p[3];
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}


static inline void
sa_zero(sockaddr_t *a)
{
	a->family = AF_UNSPEC;
}

static inline sa_family_t
sa_family(const sockaddr_t *a)
{
	return a->family;
}

static inline void
sa_from_ip4(sockaddr_t *a, uint32_t ipaddr)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = ipaddr;
	a->sin.sin_port = 0;
}

static inline void
sa_from_ip4_port(sockaddr_t *a, uint32_t ipaddr, uint16_t port)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = ipaddr;
	a->sin.sin_port = htons(port);
}

static inline void
sa_from_ip4h(sockaddr_t *a, uint32_t ipaddr_host)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = htonl(ipaddr_host);
	a->sin.sin_port = 0;
}

static inline void
sa_from_ip4h_port(sockaddr_t *a, uint32_t ipaddr_host, uint16_t port)
{
	a->family = AF_INET;
	a->sin.sin_addr.s_addr = htonl(ipaddr_host);
	a->sin.sin_port = htons(port);
}

static inline void
sa_from_ip6(sockaddr_t *a, const struct in6_addr *ipaddr)
{
	a->family = AF_INET6;
	memcpy(a->sin6.sin6_addr.s6_addr, ipaddr->s6_addr,
	       sizeof (ipaddr->s6_addr));
	a->sin6.sin6_port = 0;
}

static inline void
sa_from_ip6_port(sockaddr_t *a, const struct in6_addr *ipaddr, uint16_t port)
{
	a->family = AF_INET6;
	memcpy(a->sin6.sin6_addr.s6_addr, ipaddr->s6_addr,
	       sizeof (ipaddr->s6_addr));
	a->sin6.sin6_port = htons(port);
}

static inline void
sa_from_ip6_pfx(sockaddr_t *a, const uint8_t *bytes, int nbytes)
{
	a->family = AF_INET6;
	nbytes = nbytes < 16 ? nbytes : 16;
	memcpy(a->sin6.sin6_addr.s6_addr, bytes, nbytes);
	if (nbytes < 16)
		memset(a->sin6.sin6_addr.s6_addr + nbytes, 0x00, 16 - nbytes);
	a->sin6.sin6_port = 0;
	a->sin6.sin6_flowinfo = 0;
	a->sin6.sin6_scope_id = 0;
}

static inline uint32_t
sa_ip4(const sockaddr_t *a)
{
	if (a->family == AF_INET)
		return a->sin.sin_addr.s_addr;
	return 0;
}

static inline uint32_t
sa_ip4h(const sockaddr_t *a)
{
	if (a->family == AF_INET)
		return ntohl(a->sin.sin_addr.s_addr);
	return 0;
}

static inline const struct in6_addr *
sa_ip6(const sockaddr_t *a)
{
	if (a->family == AF_INET6)
		return &a->sin6.sin6_addr;
	return NULL;
}

static inline uint16_t
sa_port(const sockaddr_t *a)
{
	switch (a->family) {
	case AF_INET:
		return ntohs(a->sin.sin_port);
	case AF_INET6:
		return ntohs(a->sin6.sin6_port);
	default:
		return 0;
	}
}

static inline uint16_t
sa_portn(const sockaddr_t *a)
{
	switch (a->family) {
	case AF_INET:
		return a->sin.sin_port;
	case AF_INET6:
		return a->sin6.sin6_port;
	default:
		return 0;
	}
}

static inline void
sa_set_port(sockaddr_t *a, uint16_t port)
{
	switch (a->family) {
	case AF_INET:
		a->sin.sin_port = htons(port);
		break;
	case AF_INET6:
		a->sin6.sin6_port = htons(port);
		break;
	}
}

/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright (C) 2024, 2025, 2026 Olivier Gournet, <gournet.olivier@gmail.com> */

#pragma once

#include <stdbool.h>
#include <netinet/in.h>

#ifdef SA_USE_AF_UNIX
#include <sys/un.h>
#endif
#ifdef SA_USE_AF_PACKET
#include <linux/if_packet.h>
#endif

/*
 * handle ipv4 OR ipv6 address PLUS port in a wrapped and a
 * cast-free sockaddr_storage. useful to store ip+port and for
 * socket operations.
 *
 * add supports for AF_UNIX and AF_PACKET only if explicitely required.
 */
union sa
{
	sa_family_t		family;
	struct sockaddr		sa;
	struct sockaddr_in	sin;	/* AF_INET */
	struct sockaddr_in6	sin6;	/* AF_INET6 */
#ifdef SA_USE_AF_UNIX
	struct sockaddr_un	sun;	/* AF_UNIX */
#endif
#ifdef SA_USE_AF_PACKET
	struct sockaddr_ll	sll;	/* AF_PACKET */
#endif
	struct sockaddr_storage ss;
};

/* initialization & copy */
static void sa_zero(union sa *a);
socklen_t sa_len(const union sa *a);
void sa_copy(union sa *dst, const union sa *src);

/* construction */
void sa_from_ip4(union sa *a, uint32_t ipaddr);
void sa_from_ip4_port(union sa *a, uint32_t ipaddr, uint16_t port);
void sa_from_ip4h(union sa *a, uint32_t ipaddr_host);
void sa_from_ip4h_port(union sa *a, uint32_t ipaddr_host, uint16_t port);
void sa_from_ip6(union sa *a, const struct in6_addr *ipaddr);
void sa_from_ip6_port(union sa *a, const struct in6_addr *ipaddr, uint16_t port);
void sa_from_ip6_bytes(union sa *a, const uint8_t *bytes);

/* parsing */
int sa_parse(const char *addr, union sa *out);
int sa_parse_opt(const char *addr, union sa *out, uint32_t *out_netmask,
		 uint64_t *out_count, bool first_ip);

void sa_set_port(union sa *a, uint16_t port);

/* extraction */
uint32_t sa_ip4(const union sa *a);
uint32_t sa_ip4h(const union sa *a);
const struct in6_addr *sa_ip6(const union sa *a);
uint16_t sa_port(const union sa *a);
uint16_t sa_portb(const union sa *a);

/* stringify. sstr returns from static buffer */
char *sa_str(const union sa *a, char *buf, size_t buf_size);
char *sa_str_ip(const union sa *a, char *buf, size_t buf_size);
char *sa_str_port(const union sa *a, char *buf, size_t buf_size);
char *sa_sstr(const union sa *a);
char *sa_sstr_ip(const union sa *a);
char *sa_sstr_port(const union sa *a);

/* family predicates */
static sa_family_t sa_family(const union sa *a);
bool sa_is_unicast(const union sa *a);
bool sa_is_any(const union sa *a);
bool sa_is_loopback(const union sa *a);
bool sa_is_multicast(const union sa *a);
bool sa_is_linklocal(const union sa *a);

/* comparison */
int sa_cmp(const union sa *la, const union sa *ra);
int sa_cmp_ip(const union sa *la, const union sa *ra);
int sa_cmp_port(const union sa *la, const union sa *ra);
int sa_cmp_ss(const union sa *la, const union sa *ra);
static bool sa_equal(const union sa *la, const union sa *ra);
static bool sa_equal_ip(const union sa *la, const union sa *ra);

/* hashing */
uint32_t sa_hash(const union sa *a);
uint32_t sa_hash_in6_addr(const struct in6_addr *addr);



/*
 * inline implementations
 */

static inline void
sa_zero(union sa *a)
{
	a->family = AF_UNSPEC;
}

static inline sa_family_t
sa_family(const union sa *a)
{
	return a->family;
}

static inline bool
sa_equal(const union sa *la, const union sa *ra)
{
	return sa_cmp(la, ra) == 0;
}

static inline bool
sa_equal_ip(const union sa *la, const union sa *ra)
{
	return sa_cmp_ip(la, ra) == 0;
}

static inline int __sa_ip4_equal(const struct in_addr *a1,
				 const struct in_addr *a2)
{
	return (a1->s_addr == a2->s_addr);
}

static inline int __sa_ip6_equal(const struct in6_addr *a1,
				 const struct in6_addr *a2)
{
	return (((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		 (a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		 (a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		 (a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0);
}

static inline int __attribute__((pure))
ss_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2)
{
	if (s1->ss_family < s2->ss_family)
		return -1;
	if (s1->ss_family > s2->ss_family)
		return 1;

	if (s1->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a1 = (const struct sockaddr_in6 *) s1;
		const struct sockaddr_in6 *a2 = (const struct sockaddr_in6 *) s2;

		if (__sa_ip6_equal(&a1->sin6_addr, &a2->sin6_addr) &&
		    (a1->sin6_port == a2->sin6_port))
			return 0;
	} else if (s1->ss_family == AF_INET) {
		const struct sockaddr_in *a1 = (const struct sockaddr_in *) s1;
		const struct sockaddr_in *a2 = (const struct sockaddr_in *) s2;

		if (__sa_ip4_equal(&a1->sin_addr, &a2->sin_addr) &&
		    (a1->sin_port == a2->sin_port))
			return 0;
	} else if (s1->ss_family == AF_UNSPEC)
		return 0;

	return -1;
}

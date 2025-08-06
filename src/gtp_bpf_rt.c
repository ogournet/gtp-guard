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
 * Copyright (C) 2023-2025 Alexandre Cassen, <acassen@gmail.com>
 */

/* local includes */
#include "gtp_guard.h"


/* Extern data */
extern data_t *daemon_data;

typedef struct _gtp_bpf_rt
{
	struct bpf_map *teid_ingress;
	struct bpf_map *teid_egress;
	struct bpf_map *ppp_ingress;
	struct bpf_map *iptnl_info;
	struct bpf_map *if_lladdr;
	struct bpf_map *if_stats;
} gtp_bpf_rt_t;

/*
 *	XDP RT BPF related
 */
static int
gtp_bpf_rt_load_maps(gtp_bpf_prog_t *p, void *udata)
{
	gtp_bpf_rt_t *pr = udata;

	/* MAP ref for faster access */
	pr->teid_ingress = gtp_bpf_load_map(p->bpf_obj, "teid_ingress");
	if (!pr->teid_ingress)
		return -1;

	pr->teid_egress = gtp_bpf_load_map(p->bpf_obj, "teid_egress");
	if (!pr->teid_egress)
		return -1;

	pr->ppp_ingress = gtp_bpf_load_map(p->bpf_obj, "ppp_ingress");
	if (!pr->ppp_ingress)
		return -1;

	pr->iptnl_info = gtp_bpf_load_map(p->bpf_obj, "iptnl_info");
	if (!pr->iptnl_info)
		return -1;

	pr->if_lladdr = gtp_bpf_load_map(p->bpf_obj, "if_lladdr");
	if (!pr->if_lladdr)
		return -1;

	pr->if_stats = gtp_bpf_load_map(p->bpf_obj, "if_stats");
	if (!pr->if_stats)
		return -1;

	return 0;
}


/*
 *	Statistics
 */
const char *
gtp_rt_stats_metrics_str(int type)
{
	switch (type) {
		switch_define_str(IF_METRICS_GTP);
		switch_define_str(IF_METRICS_PPPOE);
		switch_define_str(IF_METRICS_IPIP);
	}

	return "unknown";
}

static struct metrics *
gtp_bpf_rt_metrics_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct metrics *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct metrics);
	memset(new, 0, *sz);
	return new;
}

static int
gtp_bpf_rt_metrics_add(struct bpf_map *map, __u32 ifindex, __u8 type, __u8 direction)
{
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	struct metrics_key mkey;
	struct metrics *new;
	size_t sz;
	int err;

	mkey.ifindex = ifindex;
	mkey.type = type;
	mkey.direction = direction;

	new = gtp_bpf_rt_metrics_alloc(&sz);
	if (!new) {
		log_message(LOG_INFO, "%s(): Cant allocate metrics !!!"
				    , __FUNCTION__);
		return -1;
	}

	err = bpf_map__update_elem(map, &mkey, sizeof(struct metrics_key), new, sz, BPF_NOEXIST);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Unable to init XDP routing metrics (%s)"
				    , __FUNCTION__
				    , errmsg);
	}

	free(new);
	return err;
}

int
gtp_bpf_rt_metrics_init(gtp_bpf_prog_t *p, int ifindex, int type)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	int err;

	if (!pr)
		return -1;

	err = gtp_bpf_rt_metrics_add(pr->if_stats, ifindex, type, IF_DIRECTION_RX);
	return err ?: gtp_bpf_rt_metrics_add(pr->if_stats, ifindex, type, IF_DIRECTION_TX);
}

int
gtp_bpf_rt_metrics_dump(gtp_bpf_prog_t *p,
			int (*dump) (void *, __u8, __u8, struct metrics *), void *arg,
			__u32 ifindex, __u8 type, __u8 direction)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct metrics_key mkey;
	struct metrics *m;
	size_t sz;
	int err, i;

	mkey.ifindex = ifindex;
	mkey.type = type;
	mkey.direction = direction;

	m = gtp_bpf_rt_metrics_alloc(&sz);
	if (!m)
		return -1;

	err = bpf_map__lookup_elem(pr->if_stats, &mkey, sizeof(struct metrics_key), m, sz, 0);
	if (err)
		goto end;

	/* first element accumulation */
	for (i = 1; i < nr_cpus; i++) {
		m[0].packets += m[i].packets;
		m[0].bytes += m[i].bytes;
		m[0].dropped_packets += m[i].dropped_packets;
		m[0].dropped_bytes += m[i].dropped_bytes;
	}

	err = (*(dump)) (arg, type, direction, &m[0]);
  end:
	free(m);
	return err;
}

static int
gtp_bpf_rt_stats_dump(gtp_bpf_prog_t *p, int ifindex, int type,
		      int (*dump) (void *, __u8, __u8, struct metrics *),
		      vty_t *vty)
{
	int err;

	vty_out(vty, " %s:%s", gtp_rt_stats_metrics_str(type), VTY_NEWLINE);
	err = gtp_bpf_rt_metrics_dump(p, dump, vty
				       , ifindex, type, IF_DIRECTION_RX);
	err = (err) ? : gtp_bpf_rt_metrics_dump(p, dump, vty
						 , ifindex, type, IF_DIRECTION_TX);
	return err;
}

static int
gtp_bpf_rt_metrics_show(void *arg, __u8 type, __u8 direction, struct metrics *m)
{
	vty_t *vty = arg;

	vty_out(vty, "   %s: packets:%lld bytes:%lld%s"
		   , (direction) ? "TX" : "RX"
		   , m->packets, m->bytes
		   , VTY_NEWLINE);
	vty_out(vty, "       dropped_packets:%lld dropped_bytes:%lld%s"
		   , m->dropped_packets, m->dropped_bytes
		   , VTY_NEWLINE);
	return 0;
}

static void
gtp_bpf_rt_stats_vty(gtp_bpf_prog_t *p, gtp_interface_t *iface, vty_t *vty)
{
	gtp_bpf_rt_stats_dump(p, iface->ifindex, IF_METRICS_GTP
			       , gtp_bpf_rt_metrics_show
			       , vty);
	gtp_bpf_rt_stats_dump(p, iface->ifindex, IF_METRICS_PPPOE
			       , gtp_bpf_rt_metrics_show
			       , vty);
	gtp_bpf_rt_stats_dump(p, iface->ifindex, IF_METRICS_IPIP
			       , gtp_bpf_rt_metrics_show
			       , vty);
}




/*
 *	TEID Routing handling
 */
static struct gtp_rt_rule *
gtp_bpf_rt_rule_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct gtp_rt_rule *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(struct gtp_rt_rule);
	return new;
}

static void
gtp_bpf_rt_rule_set(struct gtp_rt_rule *r, gtp_teid_t *t)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	gtp_session_t *s = t->session;
	gtp_router_t *rtr = s->srv->ctx;
	gtp_server_t *srv = &rtr->gtpu;
	ip_vrf_t *vrf = s->apn->vrf;
	__be32 dst_key = (vrf) ? vrf->id : 0;
	__u8 flags = __test_bit(IP_VRF_FL_IPIP_BIT, &vrf->flags) ? GTP_RT_FL_IPIP : 0;
	__u16 vlan_id = 0;
	int i;

	if (__test_bit(IP_VRF_FL_PPPOE_BIT, &vrf->flags))
		flags |= GTP_RT_FL_PPPOE;

	vlan_id = (vrf) ? vrf->encap_vlan_id : 0;
	if (__test_bit(GTP_TEID_FL_INGRESS, &t->flags))
		vlan_id = (vrf) ? vrf->decap_vlan_id : 0;

	for (i = 0; i < nr_cpus; i++) {
		r[i].teid = t->id;
		r[i].saddr = inet_sockaddrip4(&srv->addr);
		r[i].daddr = t->ipv4;
		r[i].dst_key = dst_key;
		r[i].vlan_id = vlan_id;
		r[i].packets = 0;
		r[i].bytes = 0;
		r[i].flags = flags;
	}
}

int
gtp_bpf_rt_key_set(gtp_teid_t *t, struct ip_rt_key *rt_key)
{
	gtp_session_t *s = t->session;
	gtp_router_t *rtr = s->srv->ctx;
	gtp_server_t *srv = &rtr->gtpu;

	/* egress (upstream) : GTP TEID + pGW GTP Tunnel endpoint */
	if (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) {
		rt_key->id = t->id;
		rt_key->addr = inet_sockaddrip4(&srv->addr);
		return 0;
	}

	/* ingress (downstream) : session ipv4 address + IPIP or PPP tunnel endpoint */
	rt_key->id = 0;
	if (s->apn->vrf && __test_bit(IP_VRF_FL_IPIP_BIT, &s->apn->vrf->flags))
		rt_key->id = s->apn->vrf->iptnl.local_addr;
	rt_key->addr = s->ipv4;
	return 0;
}

static int
gtp_bpf_rt_action(struct bpf_map *map, int action, gtp_teid_t *t)
{
	struct gtp_rt_rule *new = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0;
	struct ip_rt_key rt_key;
	size_t sz;

	gtp_bpf_rt_key_set(t, &rt_key);

	/* Set rule */
	if (action == RULE_ADD) {
		/* fill per cpu rule */
		new = gtp_bpf_rt_rule_alloc(&sz);
		if (!new) {
			log_message(LOG_INFO, "%s(): Cant allocate teid_rule !!!"
					    , __FUNCTION__);
			err = -1;
			goto end;
		}
		gtp_bpf_rt_rule_set(new, t);
		err = bpf_map__update_elem(map, &rt_key, sizeof(struct ip_rt_key), new, sz, BPF_NOEXIST);
	} else if (action == RULE_DEL)
		err = bpf_map__delete_elem(map, &rt_key, sizeof(struct ip_rt_key), 0);
	else
		return -1;
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant %s XDP routing rule for TEID:0x%.8x (%s)"
				    , __FUNCTION__
				    , (action) ? "del" : "add"
				    , ntohl(t->id)
				    , errmsg);
		err = -1;
		goto end;
	}

	log_message(LOG_INFO, "%s(): %s %s XDP routing rule "
			      "{teid:0x%.8x, dst_addr:%u.%u.%u.%u}"
			    , __FUNCTION__
			    , (action) ? "deleting" : "adding"
			    , (__test_bit(GTP_TEID_FL_EGRESS, &t->flags)) ? "egress" : "ingress"
			    , ntohl(t->id), NIPQUAD(t->ipv4));
  end:
	if (new)
		free(new);
	return err;
}

static int
gtp_bpf_teid_vty(struct bpf_map *map, vty_t *vty, gtp_teid_t *t)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ip_rt_key key = { 0 }, next_key = { 0 };
	const char *direction_str;
	struct gtp_rt_rule *r;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	char addr_ip[16];
	int err = 0, i;
	size_t sz;

	/* Allocate temp rule */
	r = gtp_bpf_rt_rule_alloc(&sz);
	if (!r) {
		vty_out(vty, "%% Cant allocate temp rt_rule%s", VTY_NEWLINE);
		return -1;
	}

	if (t) {
		gtp_bpf_rt_key_set(t, &key);
		err = bpf_map__lookup_elem(map, &key, sizeof(struct ip_rt_key), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "       %% No data-plane ?! (%s)%s", errmsg, VTY_NEWLINE);
			goto end;
		}

		for (i = 1; i < nr_cpus; i++) {
			r[0].packets += r[i].packets;
			r[0].bytes += r[i].bytes;
		}

		vty_out(vty, "       %.7s pkts:%lld bytes:%lld%s"
			   , __test_bit(GTP_TEID_FL_EGRESS, &t->flags) ? "egress" : "ingress"
			   , r[0].packets, r[0].bytes, VTY_NEWLINE);

		goto end;
	}

	direction_str = "ingress";
	if (!strcmp(bpf_map__name(map), "teid_egress"))
		direction_str = "egress";

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(struct ip_rt_key)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(struct ip_rt_key), r, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:0x%.8x (%s)%s"
				   , key.id, errmsg, VTY_NEWLINE);
			continue;
		}

		for (i = 1; i < nr_cpus; i++) {
			r[0].packets += r[i].packets;
			r[0].bytes += r[i].bytes;
		}

		vty_out(vty, "| 0x%.8x | %16s | %9s | %12lld | %19lld |%s"
			   , ntohl(r[0].teid)
			   , inet_ntoa2(r[0].daddr, addr_ip)
			   , direction_str
			   , r[0].packets, r[0].bytes
			   , VTY_NEWLINE);
	}

  end:
	free(r);
	return 0;
}

static int
gtp_bpf_teid_bytes(gtp_bpf_rt_t *pr, gtp_teid_t *t, uint64_t *bytes)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ip_rt_key key = { 0 };
	struct gtp_rt_rule *r;
	struct bpf_map *map;
	int err = 0, i;
	size_t sz;

	map = __test_bit(GTP_TEID_FL_EGRESS, &t->flags) ? pr->teid_egress : pr->teid_ingress;

	/* Allocate temp rule */
	r = gtp_bpf_rt_rule_alloc(&sz);
	if (!r)
		return -1;

	gtp_bpf_rt_key_set(t, &key);
	err = bpf_map__lookup_elem(map, &key, sizeof(struct ip_rt_key), r, sz, 0);
	if (err)
		goto end;

	for (i = 0; i < nr_cpus; i++)
		*bytes += r[i].bytes;

  end:
	free(r);
	return 0;
}

int
gtp_bpf_rt_teid_action(int action, gtp_teid_t *t)
{
	gtp_router_t *router = t->session->srv->ctx;
	gtp_bpf_prog_t *p = router->bpf_prog;
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	struct bpf_map *map;
	gtp_session_t *s;
	gtp_apn_t *apn;

	/* If daemon is currently stopping, we simply skip action on ruleset.
	 * This reduce daemon exit time and entries are properly released during
	 * kernel BPF map release. */
	if (__test_bit(GTP_FL_STOP_BIT, &daemon_data->flags))
		return 0;

	if (!p || !t || !pr)
		return -1;

	s = t->session;
	apn = s->apn;
	map = __test_bit(GTP_TEID_FL_EGRESS, &t->flags) ? pr->teid_egress : pr->teid_ingress;

	/* PPPoE vrf ? */
	if (apn->vrf && (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags) ||
				__test_bit(IP_VRF_FL_PPPOE_BUNDLE_BIT, &apn->vrf->flags))) {
		return gtp_bpf_ppp_action(action, t
						, pr->teid_ingress
						, pr->teid_egress);
	}

	return gtp_bpf_rt_action(map, action, t);
}

int
gtp_bpf_rt_teid_vty(vty_t *vty, gtp_teid_t *t)
{
	gtp_router_t *router = t->session->srv->ctx;
	gtp_bpf_prog_t *p = router->bpf_prog;
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	struct bpf_map *map;
	gtp_session_t *s;
	gtp_apn_t *apn;

	if (!p || !t || !pr)
		return -1;

	s = t->session;
	apn = s->apn;
	map = __test_bit(GTP_TEID_FL_EGRESS, &t->flags) ? pr->teid_egress : pr->teid_ingress;

	/* PPPoE vrf ? */
	if (apn->vrf && (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags) ||
				__test_bit(IP_VRF_FL_PPPOE_BUNDLE_BIT, &apn->vrf->flags))) {
		gtp_bpf_ppp_teid_vty(vty, t
					, pr->teid_ingress
					, pr->teid_egress);
		return 0;
	}

	gtp_bpf_teid_vty(map, vty, t);
	return 0;
}

int
gtp_bpf_rt_vty(gtp_bpf_prog_t *p, void *arg)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	vty_t *vty = arg;

	if (!pr)
		return -1;

	vty_out(vty, "bpf-program '%s'%s", p->name, VTY_NEWLINE);

	vty_out(vty, "+------------+------------------+-----------+--------------+---------------------+%s"
		     "|    TEID    | Endpoint Address | Direction |   Packets    |        Bytes        |%s"
		     "+------------+------------------+-----------+--------------+---------------------+%s"
		   , VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	gtp_bpf_teid_vty(pr->teid_ingress, vty, NULL);
	gtp_bpf_teid_vty(pr->teid_egress, vty, NULL);
	gtp_bpf_ppp_teid_vty(vty, NULL, pr->teid_ingress, NULL);
	vty_out(vty, "+------------+------------------+-----------+--------------+---------------------+%s"
			, VTY_NEWLINE);
	return 0;
}

int
gtp_bpf_rt_teid_bytes(gtp_teid_t *t, uint64_t *bytes)
{
	gtp_router_t *router = t->session->srv->ctx;
	gtp_bpf_prog_t *p = router->bpf_prog;
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	gtp_session_t *s;
	gtp_apn_t *apn;

	if (!p || !t || !pr)
		return -1;

	s = t->session;
	apn = s->apn;

	/* PPPoE vrf ? */
	if (apn->vrf && (__test_bit(IP_VRF_FL_PPPOE_BIT, &apn->vrf->flags) ||
				__test_bit(IP_VRF_FL_PPPOE_BUNDLE_BIT, &apn->vrf->flags))) {
		gtp_bpf_ppp_teid_bytes(t, pr->ppp_ingress
				        , pr->teid_egress
					, bytes);
		return 0;
	}

	gtp_bpf_teid_bytes(pr, t, bytes);
	return 0;
}


/*
 *	IP Tunneling related
 */
static int
gtp_bpf_rt_iptnl_add(gtp_bpf_prog_t *p, void *arg)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	gtp_iptnl_t *t = arg;

	return gtp_bpf_iptnl_action(RULE_ADD, t, pr->iptnl_info);
}

static int
gtp_bpf_rt_iptnl_del(gtp_bpf_prog_t *p, void *arg)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	gtp_iptnl_t *t = arg;

	return gtp_bpf_iptnl_action(RULE_DEL, t, pr->iptnl_info);
}

int
gtp_bpf_rt_iptnl_action(int action, gtp_iptnl_t *t)
{
	switch (action) {
	case RULE_ADD:
		gtp_bpf_prog_foreach_prog(gtp_bpf_rt_iptnl_add, t, "gtp_route");
		break;
	case RULE_DEL:
		gtp_bpf_prog_foreach_prog(gtp_bpf_rt_iptnl_del, t, "gtp_route");
		break;
	default:
		return -1;
	}

	return 0;
}

int
gtp_bpf_rt_iptnl_vty(gtp_bpf_prog_t *p, void *arg)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	vty_t *vty = arg;

	if (!pr)
		return -1;

	vty_out(vty, "bpf-program '%s'%s", p->name, VTY_NEWLINE);

	return gtp_bpf_iptnl_vty(vty, pr->iptnl_info);
}


/*
 *	link-layer Address
 */
static struct ll_addr *
gtp_bpf_rt_lladdr_alloc(size_t *sz)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct ll_addr *new;

	new = calloc(nr_cpus, sizeof(*new));
	if (!new)
		return NULL;

	*sz = nr_cpus * sizeof(*new);
	return new;
}

static int
gtp_bpf_rt_lladdr_set(struct ll_addr *ll, gtp_interface_t *iface)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int i;

	for (i = 0; i < nr_cpus; i++) {
		memcpy(ll[i].local, iface->hw_addr, ETH_ALEN);
		memcpy(ll[i].remote, iface->direct_tx_hw_addr, ETH_ALEN);
	}

	return 0;
}


static int
gtp_bpf_rt_lladdr_update_prog(gtp_bpf_prog_t *p, void *arg)
{
	gtp_interface_t *iface = arg;
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	struct bpf_map *map = pr->if_lladdr;
	struct ll_addr *new = NULL;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	int err = 0;
	size_t sz;

	new = gtp_bpf_rt_lladdr_alloc(&sz);
	if (!new) {
		log_message(LOG_INFO, "%s(): Cant allocate temp ll_addr"
				    , __FUNCTION__);
		return -1;
	}

	gtp_bpf_rt_lladdr_set(new, iface);
	err = bpf_map__update_elem(map, &iface->ifindex, sizeof(__u32), new, sz, 0);
	if (err) {
		libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
		log_message(LOG_INFO, "%s(): Cant update XDP lladdr for interface:'%s' (%s)"
				    , __FUNCTION__
				    , iface->ifname
				    , errmsg);
		free(new);
		return -1;
	}

	free(new);
	return 0;
}

int
gtp_bpf_rt_lladdr_update(void *arg)
{
	gtp_bpf_prog_foreach_prog(gtp_bpf_rt_lladdr_update_prog, arg,
				  "gtp_route");
	return 0;
}

int
gtp_bpf_rt_lladdr_vty(gtp_bpf_prog_t *p, void *arg)
{
	gtp_bpf_rt_t *pr = gtp_bpf_prog_tpl_data_get(p, "gtp_route");
	struct bpf_map *map = pr->if_lladdr;
	struct ll_addr *ll;
	vty_t *vty = arg;
	char errmsg[GTP_XDP_STRERR_BUFSIZE];
	__u32 key = 0, next_key = 0;
	size_t sz;
	int err;

	vty_out(vty, "bpf-program '%s'%s", p->name, VTY_NEWLINE);

	ll = gtp_bpf_rt_lladdr_alloc(&sz);
	if (!ll) {
		vty_out(vty, "%% Cant allocate temp ll_addr%s", VTY_NEWLINE);
		return -1;
	}

	/* Walk hashtab */
	while (bpf_map__get_next_key(map, &key, &next_key, sizeof(__u32)) == 0) {
		key = next_key;
		err = bpf_map__lookup_elem(map, &key, sizeof(__u32), ll, sz, 0);
		if (err) {
			libbpf_strerror(err, errmsg, GTP_XDP_STRERR_BUFSIZE);
			vty_out(vty, "%% error fetching value for key:%d (%s)%s"
				   , key, errmsg, VTY_NEWLINE);
			continue;
		}

		vty_out(vty, "interface %s%s"
			   , if_indextoname(key, errmsg), VTY_NEWLINE);
		vty_out(vty, " local:" ETHER_FMT " remote:" ETHER_FMT "%s"
			   , ETHER_BYTES(ll[0].local)
			   , ETHER_BYTES(ll[0].remote)
			   , VTY_NEWLINE);
	}

	free(ll);
	return 0;
}


static gtp_bpf_prog_tpl_t gtp_bpf_tpl_rt = {
	.name = "gtp_route",
	.description = "gtp-route",
	.udata_alloc_size = sizeof (gtp_bpf_rt_t),
	.loaded = gtp_bpf_rt_load_maps,
	.vty_iface_show = gtp_bpf_rt_stats_vty,
};

static void __attribute__((constructor))
gtp_bpf_rt_init(void)
{
	gtp_bpf_prog_tpl_register(&gtp_bpf_tpl_rt);
}

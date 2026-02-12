/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#define BPF_CAPTURE_FL_INGRESS			0x0001
#define BPF_CAPTURE_FL_EGRESS			0x0002
#define BPF_CAPTURE_CFG_FL_BY_IFACE		0x0100

struct capture_bpf_entry
{
	__u16		flags;
	__u16		entry_id;
	__u16		cap_len;
} __attribute__((packed));


/* configuration for capture trace program */
struct capture_trace_cfg
{
	__u16		flags;
	__u16		entry_id;
	__u16		cap_len;
} __attribute__((packed));

/* metadata before each captured packet */
struct capture_metadata
{
	__u32		ifindex;
	__u32		rx_queue;
	__u16		pkt_len;
	__u16		cap_len;
	__u16		flags;
	__u16		entry_id;
	int		action;
} __attribute__((packed));

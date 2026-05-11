/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include "tools.h"
#include "capture-def.h"

//#define UPF_DEBUG

#ifdef UPF_DEBUG
# define UPF_DBG(Fmt, ...) bpf_printk(Fmt, ## __VA_ARGS__)
#else
# define UPF_DBG(...)
#endif

/********************************************************************/
/* UPF Constants */

#define BPF_UPF_USER_MAP_SIZE		1000000
#define BPF_UPF_USER_COUNTER_MAP_SIZE	1200000


/********************************************************************/
/* UPF Forward Rules (map PDR, FAR, QES) */

#define UE_IPV4		(1 << 0)
#define UE_IPV6		(1 << 1)

struct upf_ingress_key {
	__u16		flags;
	union {
		__be32	ue_ip4;
		union {
			__be32	addr4[2];
			__u8	addr[8];
		} ue_ip6pfx;
	};
}  __attribute__((packed));

struct upf_egress_key {
	__be32		gtpu_local_teid;
	__be32		gtpu_local_addr;
} __attribute__((packed));


#define UPF_FWD_FL_ACT_FWD			(1 << 0)
#define UPF_FWD_FL_ACT_BUFF			(1 << 1)
#define UPF_FWD_FL_ACT_DROP			(1 << 2)
#define UPF_FWD_FL_ACT_DUPL			(1 << 3)
#define UPF_FWD_FL_ACT_CREATE_OUTER_HEADER	(1 << 4)
#define UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER	(1 << 5)
#define UPF_FWD_FL_INGRESS			(1 << 6)
#define UPF_FWD_FL_EGRESS			(1 << 7)
#define UPF_FWD_FL_ACT_KEEP_OUTER_HEADER	\
	(UPF_FWD_FL_ACT_CREATE_OUTER_HEADER |	\
	 UPF_FWD_FL_ACT_REMOVE_OUTER_HEADER)
#define UPF_FWD_FL_GTP_EXTHDR			(1 << 8)
#define UPF_FWD_FL_GATE_UL_CLOSED		(1 << 9)
#define UPF_FWD_FL_GATE_DL_CLOSED		(1 << 10)

/* rules set by userapp. */
struct upf_fwd_rule {
	__be32		gtpu_remote_teid;
	__be32		gtpu_remote_addr;
	__be32		gtpu_local_addr;
	__be16		gtpu_remote_port;
	__be16		gtpu_local_port;

	__u8		tos_tclass;
	__u8		tos_mask;
	__u8		qfi;		/* 0: unset */
	__u8		_pad;
	__u16		flags;

	/* indexes to upf_tcc / upf_mbr. 0: unused */
	__u32		ttc_idx;
	__u32		mbr_idx;
	__u32		ambr_idx;

	__u32		li_id;		/* 0: disabled */
	__u64		seid;

	struct capture_bpf_entry capture;

	/* metrics. pkt counters can wrap, it's only metric */
	__u32		drop_v4_pkt;
	__u32		drop_v6_pkt;
	__u32		fwd_v4_pkt;
	__u32		fwd_v6_pkt;
	__u64		fwd_v4_bytes;
	__u64		fwd_v6_bytes;
}  __attribute__((packed));



/********************************************************************/
/* UPF Triggers, Timers and Counters (map URR) */

#define UPF_FL_MEAS_VOL				0x01
#define UPF_FL_MEAS_TIME			0x02
#define UPF_FL_QUOTA_REACHED			0x04
#define UPF_FL_QUOTA_EXPLICIT_BLOCK		0x08
#define UPF_FL_TIME_IMMEDIATE_METER		0x10

#define UPF_TRIG_FL_VOLTH			0x0001
#define UPF_TRIG_FL_TIMTH			0x0002
#define UPF_TRIG_FL_VOLQU			0x0004
#define UPF_TRIG_FL_TIMQU			0x0008
#define UPF_TRIG_FL_PERIO			0x0010
#define UPF_TRIG_FL_QUHTI			0x0020
#define UPF_TRIG_FL_START			0x0040
#define UPF_TRIG_FL_STOPT			0x0080

/*
 * owned by bpf, never written from userspace: modified through sysctl urr_ctl,
 * reports sent through ring_buffer.
 *
 * time counters are nanoseconds shifted by 24 bits, stored as __u32.
 * resolution is 16.7ms, max time about 2 years. more than enough for upf needs.
 *
 * keep it 64B pagecache aligned, with accessed fields on hot datapath together
 */
struct upf_ttc {
	/* cache line 1 (datapath, hot) 64B */
	__u16		flags;			/* UPF_FL_* */
	__u16		_pad1;
	__u32		report_first_pkt;	/* first pkt seen for next report */
	__u32		report_last_pkt;	/* last pkt seen for next report */
	__u32		ul_last_pkt;
	__u32		dl_last_pkt;
	__u32		inactivity_det_time;
	__u32		duration_ts_last;	/* last time duration was computed */
	__u32		inactive_time;		/* cum since last duration compute  */
	__u64		total_th_next;
	__u64		total_qu_next;
	__u64		dl_bytes;
	__u64		dl_pkt;

	/* cache line 2 (datapath, hot) 64B */
	__u64		_unused_1;
	__u64		dl_th_next;
	__u64		dl_qu_next;
	__u64		ul_bytes;
	__u64		ul_pkt;
	__u64		_unused_2;
	__u64		ul_th_next;
	__u64		ul_qu_next;

	/* cache line 3 (volume config, cold) 64B */
	__u64		total_th;
	__u64		total_qu;
	__u64		ul_th;
	__u64		ul_qu;
	__u64		dl_th;
	__u64		dl_qu;
	__u64		seid;
	__u32		ttc_idx;
	__u32		_pad2;

	/* cache line 4 (mostly timer, cold) 52B */
	struct bpf_timer timer;			/* 16B bytes */
	__u32		time_th;
	__u32		time_qu;
	__u32		time_periodic;
	__u32		time_inactivity;	/* quota holding time */
	__u32		duration;		/* cumulative */
	__u32		duration_th_last;
	__u32		duration_qu_last;
	__u32		time_periodic_next;
	__u32		time_inactivity_next;

	__u8		_pad[12];
};

enum {
	UPF_TTC_CMD_INIT,
	UPF_TTC_CMD_UPDATE,
	UPF_TTC_CMD_DELETE,
	UPF_TTC_CMD_REPORT,
};


struct upf_ttc_cmd {
	__u64		seid;
	__u32		ttc_idx;		/* idx in bpf map array */
	__u16		flags;			/* UPF_FL_* */
	__u8		cmd;			/* UPF_TTC_CMD_* */
	__u8		request_id;		/* trigger by syscall */

	__u32		time_th;
	__u32		time_qu;
	__u32		time_periodic;
	__u32		time_inactivity;
	__u32		inactivity_det_time;

	__u64		total_th;
	__u64		total_qu;
	__u64		dl_th;
	__u64		dl_qu;
	__u64		ul_th;
	__u64		ul_qu;
};

struct upf_ttc_report {
	__u64		seid;
	__u32		ttc_idx;
	__u16		report_flags;		/* UPF_TRIG_FL_* */
	__u8		request_id;		/* if trigged by syscall */
	__u8		_pad;
};

struct upf_ttc_report_data {
	struct upf_ttc_report r;

	__u64		dl_bytes;
	__u64		dl_pkt;
	__u64		ul_bytes;
	__u64		ul_pkt;
	__u32		report_first_pkt;	/* first pkt seen */
	__u32		report_last_pkt;	/* last pkt seen */
	__u32		duration;		/* total duraction (wrt inactive time) */
};



/********************************************************************/
/* UPF QoS Enforcement Rule (QER) */

/*
 * Token bucket state for MBR enforcement.
 * Tokens stored as bytes << 8 for fractional precision.
 * Time base: ns >> 24 (~16.7 ms resolution), same as upf_ttc.
 */
struct upf_mbr {
	__u32		tb_ul_last;		/* last refill ts (ns >> 24) */
	__u32		tb_dl_last;
	__u64		tb_ul_tokens;		/* current UL tokens */
	__u64		tb_dl_tokens;		/* current DL tokens */
	__u64		tb_ul_rate;		/* UL refill rate */
	__u64		tb_dl_rate;		/* DL refill rate */
	__u64		tb_ul_burst;		/* UL max bucket size */
	__u64		tb_dl_burst;		/* DL max bucket size */
	__u64		_pad;
};


/********************************************************************/
/* UPF LI */

#define UPF_LI_FL_DIR_MASK     0x0003
#define UPF_LI_FL_DIR_INGRESS  0x0001
#define UPF_LI_FL_DIR_EGRESS   0x0002

struct upf_li_entry {
	__u32		id;
	__u16		flags;
	__u16		_pad;
	__u16		payload_len;
	__u16		offset;
} __attribute__((packed));

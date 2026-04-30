/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

/* GTPv1-U (TS 29.281) */
struct gtpuhdr {
	__u8		flags;
	__u8		type;
	__be16		length;
	__be32		teid;

	/* following fields are present if flag & 0x07 is non-zero */
	__be16		seqnum;
	__u8		npdu_num;
	__u8		exthdr_type;
	__u8		exthdr[];
} __attribute__ ((__packed__));

#define GTPU_HLEN_SHORT		8
#define GTPU_HLEN_LONG		12

#define GTPU_PORT		2152
#define GTPU_EXTHDR_MAX		2

/* GTP-U Flags */
#define GTPU_FL_V_MASK		0xe0
#define GTPU_FL_V1		0x20
#define GTPU_FL_PT		0x10
#define GTPU_FL_E		0x04
#define GTPU_FL_S		0x02
#define GTPU_FL_PN		0x01

/* GTP-U Message Type */
#define GTPU_TYPE_ECHO_REQ	1
#define GTPU_TYPE_ECHO_RSP	2
#define GTPU_TYPE_ERROR_IND	26
#define GTPU_TYPE_SUPP_EXTHDR	31
#define GTPU_TYPE_END_MARKER	254
#define GTPU_TYPE_TPDU		255

/* GTP-U Extension Header Type */
#define GTPU_ETYPE_NONE				0
#define GTPU_ETYPE_UDP_PORT			0x80
#define GTPU_ETYPE_RAN_CONTAINER		0x81
#define GTPU_ETYPE_XW_RAN_CONTAINER		0x83
#define GTPU_ETYPE_NR_RAN_CONTAINER		0x84
#define GTPU_ETYPE_PDU_SESSION_CONTAINER	0x85

# QER Implementation in gtp-guard

QoS Enforcement Rule (QER) implementation status against
3GPP TS 29.244 v16.9.1 §5.4.3 and §5.4.4.

## Summary

### Implemented

- **Gate status** (UL/DL open/closed) — per-PDR enforcement
- **MBR per-flow** — token bucket, first non-aggregate QER with MBR on the PDR
- **MBR aggregate** (Session-AMBR / APN-AMBR) — auto-detected, shared across all PDRs
- **Averaging Window** — default 1000 ms per 3GPP
- **QFI** — inserted in GTP-U PDU Session Container on DL

### Not implemented

- **GBR** — Guaranteed Bit Rate enforcement
- **Packet Rate** — per-packet rate limiting (only bit rate via MBR)
- **DL Flow Level Marking** — DSCP marking for application indication
- **RQI** — Reflective QoS Indicator
- **Paging Policy Indicator**
- **QER Control Indications / QER Indications**
- **Cross-session QER Correlation** — aggregate enforcement across
  multiple PDN connections to the same APN

## Architecture

QER processing is split between the XDP data-plane and the PFCP
control-plane:

- **Data-plane**: MBR enforcement via classic token bucket, checked
  inline on every packet. Gate status is enforced via per-PDR
  forwarding rule flags, checked before any token bucket lookup.
  UL and DL are enforced independently.

- **Control-plane**: parses QER IEs, detects aggregate (Session-AMBR)
  vs per-flow QERs, allocates token bucket entries only when MBR is
  present, and sets gate flags on forwarding rules.

### Two-level enforcement

QER enforcement operates at two independent levels, each with its
own token bucket:

| Level | Scope | Detection |
|-------|-------|-----------|
| Per-flow | per-PDR | QER with QFI, or not referenced by all PDRs |
| Aggregate (Session-AMBR) | session-wide | QER with Correlation ID, or no QFI and referenced by all PDRs |

A packet must pass both token buckets when present. Per-flow is
checked first, then aggregate.

A QER is identified as aggregate (Session-AMBR / APN-AMBR) when it has
a QER Correlation ID, or it has no QFI, has MBR, and is referenced by
all PDRs in the session.


### Gate status

Gate status (open/closed per UL/DL) is enforced per-PDR via
forwarding rule flags. If any QER associated with a PDR has a gate
closed, traffic is dropped for that direction. Gate-only QERs
(without MBR) have zero data-plane overhead — no token bucket entry
is allocated.

### MBR enforcement

MBR is enforced with a classic token bucket:

- **Burst size**: derived from the Averaging Window IE. When absent,
  the 3GPP default of 1000 ms is used.
  `burst = MBR_kbps * averaging_window_ms / 8000` bytes.
- **Time resolution**: ~16.7 ms. Sub-millisecond pacing is not
  available.
- **Encoding**: 32-bit MBR only (lower 4 bytes of the 5-byte IE).
  Maximum representable rate is ~4.3 Tbps.

A data-plane token bucket entry is allocated per QER that has MBR,
not per PDR. Multiple PDRs referencing the same QER naturally share
one token bucket. For per-flow enforcement, the first non-aggregate
QER with MBR on the PDR is used.

### Token bucket preservation

On session modification, when a QER's MBR parameters change, the
token bucket preserves its current fill level (capped to the new
burst size). It does not restart from full. When a new QER is
created, its token bucket starts fully loaded.

### QFI handling

The QoS Flow Identifier from the QER IE is inserted into the GTP-U
PDU Session Container extension header on downlink encapsulation.

## Gating control (§5.4.3)

| Feature | Status | Notes |
|---------|--------|-------|
| Gate Status (UL/DL) | Implemented | Per-PDR. If any QER on a PDR has gate closed, traffic is dropped. |

## QoS control (§5.4.4)

| Feature | Status | Notes |
|---------|--------|-------|
| MBR (per-flow) | Implemented | First non-aggregate QER with MBR on the PDR. |
| MBR (aggregate) | Implemented | Auto-detected. Shared across all PDRs. |
| GBR | Not implemented | IE is parsed but ignored. |
| Averaging Window | Implemented | Default 1000 ms per 3GPP TS 23.501 §5.4.3.2. |
| Packet Rate | Not implemented | Only bit rate (MBR) is enforced. |
| QFI | Implemented | Inserted in GTP-U extension header on DL. Used for aggregate detection. |
| RQI | Not implemented | |
| DL Flow Level Marking | Not implemented | |
| Paging Policy Indicator | Not implemented | |
| QER Correlation ID | Parsed | Used for aggregate detection. Not enforced across sessions. |
| QER Control Indications | Not implemented | |
| QER Indications | Not implemented | |

## Session lifecycle

- **Establishment**: QERs parsed, aggregate detected, per-flow token
  bucket entries allocated for QERs with MBR, gate flags set on
  forwarding rules.
- **Modification**: QER create, update, remove. Token bucket entries
  are managed per QER: existing entries are updated in place with
  token preservation, new QERs get fresh entries, removed QERs are
  released. Gate flags are rebuilt on all affected forwarding rules.
- **Deletion**: token bucket entries released.

## VTY inspection

Use `show pfcp session <IMSI> details` to inspect QER state per
session:

- Per-QER: QER ID, QFI, Correlation ID, gate status, MBR (kbps),
  averaging window.
- Per-PDR: referenced QER IDs and data-plane entry index.
- Aggregate: which QER is detected as aggregate and its data-plane
  entry index.

## Deviations from specification

### QER Correlation ID usage

Per §5.4.4, the QER Correlation ID is intended for cross-session
aggregate enforcement — correlating QERs across multiple PFCP
sessions for the same APN. This cross-session enforcement is not
implemented (see "What is not implemented" below).

Instead, the Correlation ID is used as a reliable signal to identify
the aggregate QER within a single session. This is a pragmatic
reuse — the spec does not define the Correlation ID as an aggregate
marker, but in practice only aggregate QERs carry one.

### Multiple QER per PDR

The specification allows multiple QER IDs per PDR (Table 7.5.2.2-1).
All QER IDs are parsed and associated to the PDR. For MBR
enforcement, only two levels apply: one per-flow and one aggregate.
Additional QERs on the same PDR contribute gate status and QFI.

### MBR encoding

Only the lower 32 bits of the 5-byte MBR field are used. The high
byte is ignored. This limits the maximum representable rate to
~4.3 Tbps, which is sufficient for all current deployments.

### Token bucket granularity

The token bucket operates at ~16.7 ms resolution.
Sub-millisecond burst shaping is not available. The minimum MBR
from the specification is 1 kbps, which the token bucket handles
correctly.

### Token consumption on aggregate drop

Per-flow and aggregate token buckets are checked sequentially:
per-flow first, then aggregate. If the per-flow check passes but the
aggregate check fails, tokens are consumed from the per-flow bucket
even though the packet is dropped. Ideally neither bucket should be
debited when the packet is not forwarded. Refunding would require
a two-phase commit or reversing the check order, adding complexity
for a negligible effect in practice.

### Update atomicity

When MBR parameters are updated during a session modification, there
is a brief window where the data-plane may see partially updated
values. This affects at most one packet and is considered harmless.

## What is not implemented

- **GBR**: Guaranteed Bit Rate enforcement.
- **Packet Rate**: per-packet rate limiting (as opposed to bit rate).
- **DL Flow Level Marking**: DSCP marking for application indication.
- **RQI**: Reflective QoS Indicator.
- **Paging Policy Indicator**.
- **QER Control Indications / QER Indications**.
- **Cross-session QER Correlation**: aggregate enforcement across
  multiple PDN connections to the same APN.

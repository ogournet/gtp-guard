# URR Implementation in gtp-guard

Usage Reporting Rule (URR) implementation status against
3GPP TS 29.244 v16.9.1 §5.2.2.

## Architecture

URR processing is split between kernel (BPF/XDP data-plane) and
userspace (PFCP control-plane):

- **Data-plane**: volume counters, thresholds, quotas and timers run
  in kernel BPF, checked inline on every packet (volume) or via BPF
  timers (time-based). When a trigger fires, a report is sent through
  a ring buffer to userspace.

- **Control-plane**: parses PFCP URR IEs, manages per-session URR
  state, merges multiple URRs into shared data-plane entries, builds
  and sends PFCP Session Report Request messages.

### URR merging

When a session has multiple URRs, they are merged into a shared
data-plane entry. The merge takes the minimum threshold/quota across
all URRs so the data-plane triggers at the earliest deadline.
Userspace demultiplexes which URRs actually triggered based on their
individual configuration.

An optional proximity merge can be configured: two thresholds within
a configurable percent of each other are merged to the higher value,
so a single data-plane trigger covers both URRs. For example with 6%,
a 95 MB and a 100 MB threshold merge to 100 MB.

```
pfcp-router pfcp-1
 urr-merge-threshold-percent 6
```

Disabled by default (strict minimum). Set to 0 to disable explicitly.

After each volume trigger, the merged threshold is recomputed based
on per-URR next trigger points so that URRs with different periods
are tracked correctly (e.g., URR at 60 MB and URR at 100 MB will
trigger at 60, 100, 120, 180, 200, ...).

## What is implemented

### Measurement methods (§5.2.2.1)

- **Volume measurement**: uplink, downlink and total byte/packet
  counters maintained in the data-plane.
- **Duration measurement**: session duration excluding inactivity
  periods, with ~16.7 ms resolution.
- **Event measurement**: not implemented.

### Reporting triggers (§5.2.2.2.1)

| Trigger | Status | Notes |
|---------|--------|-------|
| VOLTH | Yes | Total, UL, DL independently. Per-URR tracking across trigger periods. |
| VOLQU | Yes | Stops forwarding on exhaustion. Auto-enabled when quota is provisioned without VOLTH (§5.2.2.2.1). |
| TIMTH | Yes | Timer-based. |
| TIMQU | Yes | Stops forwarding on exhaustion. Auto-enabled when time quota is provisioned without TIMTH. |
| PERIO | Yes | Timer-based periodic reporting. |
| QUHTI | Yes | Inactivity-based. Remaining quota is discarded when fired (§5.2.2.2.1 note 9). |
| LIUSA | Yes | Linked usage reporting with efficient lookup. |
| TERMR | Yes | Final report on session deletion. |
| IMMER | Yes | Immediate report on session modification query. |
| START | Not implemented | |
| STOPT | Not implemented | |
| DROTH | Not implemented | |
| ENVCL | Not implemented | |
| MACAR | Not implemented | |
| EVETH | Not implemented | |
| EVEQU | Not implemented | |
| IPMJL | Not implemented | |
| QUVTI | Not implemented | |

### Session lifecycle

- **Establishment**: URRs created and merged. Data-plane initialized.
- **Modification**: URR create, update, remove and query (specific or
  QAURR). Only changed fields are re-merged.
- **Deletion**: final usage reports with TERMR trigger.

### Linked URRs (§5.2.2.4)

- When a URR triggers, linked URRs generate reports with LIUSA
  trigger, regardless of which condition triggered the original URR.
- On modification query, linked URRs with null measurements are
  excluded (§5.2.2.3.1).
- If a URR is both explicitly queried and linked by another, trigger
  flags are merged (IMMER | LIUSA in a single report).
- Limited to 32 URRs per session for linked URR resolution.

### Quota handling (§5.2.2.2.1, §5.2.2.3.1)

- **Enforcement**: when volume or time quota is exhausted, forwarding
  stops in both directions (UL and DL).
- **Zero quota** (§5.2.2.3.1 note 3): on session establishment,
  traffic is blocked immediately without a report (service not
  allowed before quota allocation). On session modification, traffic
  is blocked and a usage report is sent with current measurements.
- **Resumption**: when the CP provisions a new non-zero quota via
  Update URR, forwarding resumes.
- **QUHTI discards quota** (§5.2.2.2.1 note 9): when Quota Holding
  Time fires and any quota is provisioned, remaining quota is
  discarded and forwarding stops. The CP must send new quota to
  resume.
- **Auto-enabled triggers**: when quota is provisioned without the
  corresponding threshold trigger, the quota trigger is automatically
  enabled so a report is generated at exhaustion (§5.2.2.2.1).
- **FAR for Quota Action**: not implemented. On exhaustion, traffic
  is always dropped (no redirect or buffering).

## Gap analysis (TS 29.244 §5.2.2)

### §5.2.2.2.1 — Provisioning

| Feature | Status | Notes |
|---------|--------|-------|
| Volume Threshold | Implemented | Per-URR tracking across trigger periods |
| Volume Quota | Implemented | Auto-enables VOLQU if no VOLTH. New quota resumes forwarding. |
| Dropped DL Traffic Threshold | Not implemented | |
| Measurement Before QoS Enforcement | Not implemented | Always measures after enforcement |
| Measurement of Number of Packets | Partial | Packets are counted but MNOP feature negotiation is not enforced |
| Time Threshold | Implemented | |
| Time Quota | Implemented | Auto-enables TIMQU if no TIMTH |
| Immediate Start Time Metering | Partial | Supported in the data-plane |
| Inactivity Detection Time | Implemented | |
| Time Quota Mechanism (CTP/DTP) | Not implemented | EPC-specific |
| Envelope Reporting | Not implemented | |
| Quota Validity Time | Not implemented | |
| Monitoring Time | Not implemented | Spec requires split reporting before/after monitoring time with Usage Information IE |
| Subsequent Threshold/Quota | Not implemented | Used with Monitoring Time |
| FAR ID for Quota Action | Not implemented | Spec requires applying a substitute FAR on quota exhaustion |
| Inactive Measurement (INAM) | Not implemented | Spec requires stopping measurement while keeping counts; still report on QUHTI/PERIO/LIUSA |
| Number of Reports (NORP) | Not implemented | Spec requires URR to become inactive after N reports |
| Zero quota | Implemented | §5.2.2.3.1 note 3 |
| Event Threshold/Quota | Not implemented | |
| Aggregated URRs / Credit Pooling | Not implemented | §5.2.2.2.2 |

### §5.2.2.3.1 — Reporting

| Feature | Status | Notes |
|---------|--------|-------|
| UR-SEQN | Implemented | |
| Reset measurements on report | Implemented | Delta reporting |
| Re-apply thresholds on VOLTH/TIMTH | Implemented | |
| Adjust threshold/quota on PERIO/LIUSA/STOPT | **Not implemented** | Spec requires subtracting reported usage from remaining threshold/quota |
| Threshold re-application after query | **Partial** | On query with Update URR, new threshold is applied. Without Update URR, spec requires subtracting reported usage — we re-merge from original values. |
| Usage Information IE | Not implemented | Required for MBQE and Monitoring Time split reports |
| Volume Measurement IE | Implemented | Total, UL, DL bytes and packets |
| Remove URR: report | Partial | URR is removed but no report sent on removal |
| Remove last PDR: reset URR | Not implemented | |
| Deactivated URR handling | Not implemented | INAM flag |
| Message splitting (AURI) | **Not implemented** | Sessions with many URRs may exceed UDP MTU |
| Additional Usage Reports Information IE | Not implemented | |
| Query URR Reference in additional reports | Not implemented | |
| PSDBU flag on last deletion report | Not implemented | |
| New threshold against ongoing measurement | **Partial** | Spec requires deducting already-forwarded traffic. We re-merge from original values. |

### §5.2.2.3.3 — Redundant Transmission (N3/N9)

Not implemented.

### §5.2.2.5 — End Marker Reception Reporting

Not implemented (REEMR trigger).

## Known limitations

### Single measurement point per session

All URRs in a session currently share a single data-plane measurement
point. Volume counters are shared: all URRs see the same byte counts.
A URR added mid-session sees cumulative counters from session start.

Future work: group URRs by SDF/application filter.

### Threshold merge approximation

When `urr-merge-threshold-percent` is configured, two close thresholds
fire at the higher value. The SMF may see a trigger slightly later
than expected. Disabled by default.

### Threshold recalculation race

After a volume trigger, the control-plane recomputes the next
threshold and updates the data-plane. Between the trigger and the
update, the data-plane continues with the old step value. Under bursty
traffic, one extra trigger may fire at the old step. This is benign
(duplicate report, not a missed report).

### Threshold/quota adjustment after non-threshold reports

§5.2.2.3.1 requires that on PERIO/LIUSA/ENVCL/STOPT reports, the
UP function adjusts the remaining threshold/quota by subtracting
the reported usage. This matters when the CP provisions a new
threshold or quota in response to such a report: the spec says the
UP should deduct already-forwarded traffic since the last report
from the new value (§5.2.2.3.1 note 1). We apply the new threshold
as-is from the current position, without deducting. This only
manifests when the CP adjusts quotas based on intermediate
(non-threshold) reports — typical in online charging flows.

### Time resolution

Duration measurement has ~16.7 ms resolution and a maximum range of
~2 years. Sub-millisecond timing is not available.

### No per-PDR URR assignment

URRs are not assigned per-PDR. All URRs in a session share the same
measurement point. PDR-to-URR references are stored for display but
do not affect data-plane behavior.

### Event measurement

Not implemented. No event counters are maintained.

### Dropped DL traffic

DROTH trigger and Dropped DL Traffic Threshold are not implemented.
Dropped packets are counted but not reported via URR.

### Maximum URRs per session

Linked URR resolution is limited to 32 URRs per session.

### Message splitting

Usage reports are not split across multiple PFCP messages. Sessions
with many URRs may produce reports exceeding the UDP MTU. The
Additional Usage Reports Information IE is not used.

### Quota exhaustion action

On quota exhaustion, traffic is always dropped. The FAR for Quota
Action IE (redirect, buffer) is not implemented.

## VTY inspection

Use `show pfcp session <IMSI> details` to inspect URR and merged
data-plane state per session.

## Source files

| File | Description |
|------|-------------|
| `src/pfcp/pfcp_session_urr.c` | URR create, update, remove, merge, report |
| `src/pfcp/include/pfcp_session.h` | URR data structures |
| `src/bpf/lib/upf-def.h` | Data-plane structures |
| `src/bpf/lib/upf_ttc.h` | Data-plane triggers, timers, counters |
| `src/pfcp/pfcp_bpf.c` | Data-plane integration |
| `src/pfcp/pfcp_session_vty.c` | VTY display |
| `test/upf.sh` | Integration tests |
| `test/smf.py` | SMF simulator |

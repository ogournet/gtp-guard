/* SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} upf_events SEC(".maps");


static __always_inline void
_ttc_compute_duration(struct upf_ttc *ut, __u32 rnow)
{
	__u32 last_pkt = max(ut->ul_last_pkt, ut->dl_last_pkt);
	if (ut->duration_ts_last && last_pkt > ut->duration_ts_last) {
		__u32 dur = last_pkt - ut->duration_ts_last;
		if (dur > ut->inactive_time)
			ut->duration += dur - ut->inactive_time;
		ut->inactive_time = 0;
		ut->duration_ts_last = rnow;
	}
}


static __always_inline void
_ttc_send_report(struct upf_ttc *ut, __u16 trigger_fl, __u16 request_id)
{
	struct upf_ttc_report_data ur;

	/* sends interesting values through ringbuf */
	ur.r.seid = ut->seid;
	ur.r.ttc_idx = ut->ttc_idx;
	ur.r.report_flags = trigger_fl;
	ur.r.request_id = request_id;
	ur.dl_bytes = ut->dl_bytes;
	ur.dl_pkt = ut->dl_pkt;
	ur.ul_bytes = ut->ul_bytes;
	ur.ul_pkt = ut->ul_pkt;
	ur.report_first_pkt = ((__u64)ut->report_first_pkt << 24) / NSEC_PER_SEC;
	ur.report_last_pkt = ((__u64)ut->report_last_pkt << 24) / NSEC_PER_SEC;
	ur.duration = ut->duration ?
		((__u64)(ut->duration + 1) << 24) / NSEC_PER_SEC : 0;

#ifdef UPF_DEBUG
	bpf_printk("%s: send report from BPF, trigger flags: 0x%x, dl:%ld ul:%ld dur:%d",
		   __func__, trigger_fl, ut->dl_bytes, ut->ul_bytes, ur.duration);
#endif

	bpf_ringbuf_output(&upf_events, &ur, sizeof(ur), 0);

	ut->report_first_pkt = 0;
	ut->report_last_pkt = 0;
}

/* return 'timeout' in ns, when next timer should trigger */
static __always_inline __u64
_ttc_compute_next_tick(struct upf_ttc *ut, __u32 rnow)
{
	__u64 ret = ~0;

	if (ut->time_th && ut->duration_ts_last) {
		__u32 elapsed = ut->duration - ut->duration_th_last;
		if (elapsed < ut->time_th)
			ret = rnow + ut->time_th - elapsed + 50;
		else
			ret = rnow;
	}

	if (ut->time_qu && ut->duration_ts_last) {
		__u32 elapsed = ut->duration - ut->duration_qu_last;
		if (elapsed < ut->time_qu)
			ret = min(ret, rnow + ut->time_qu - elapsed + 50);
		else
			ret = rnow;
	}

	if (ut->time_periodic_next) {
		ret = min(ret, ut->time_periodic_next);
	} else if (ut->time_periodic) {
		ut->time_periodic_next = rnow + ut->time_periodic + 1;
		ret = min(ret, ut->time_periodic_next);
	}

	if (ut->time_inactivity_next) {
		ret = min(ret, ut->time_inactivity_next);
	} else if (ut->time_inactivity) {
		__u32 last_pkt = max(ut->ul_last_pkt, ut->dl_last_pkt);
		last_pkt = last_pkt ?: rnow;
		ut->time_inactivity_next = last_pkt + ut->time_inactivity + 1;
		ret = min(ret, ut->time_inactivity_next);
	}

	return ret != ~0 ? (__u64)(ret - rnow) << 24 : 0;
}

static __always_inline int
_ttc_timer_tick(void *map, int *key, struct upf_ttc *ut)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	__u16 trig = 0;

	if ((ut->flags & UPF_FL_MEAS_TIME)) {
		_ttc_compute_duration(ut, rnow);

		if (ut->time_th) {
			__u32 elapsed = ut->duration - ut->duration_th_last;
			if (elapsed >= ut->time_th) {
				trig |= UPF_TRIG_FL_TIMTH;
				ut->duration_th_last = ut->duration;
			}
		}

		if (ut->time_qu) {
			__u32 elapsed = ut->duration - ut->duration_qu_last;
			if (elapsed >= ut->time_qu) {
				ut->flags |= UPF_FL_QUOTA_REACHED;
				trig |= UPF_TRIG_FL_TIMQU;
				ut->duration_qu_last = ut->duration;
			}
		}
	}

	if (ut->time_inactivity_next && rnow >= ut->time_inactivity_next) {
		__u32 last_pkt = max(ut->ul_last_pkt, ut->dl_last_pkt);
		if (!last_pkt || ut->time_inactivity <= rnow - last_pkt) {
			trig |= UPF_TRIG_FL_QUHTI;
			/* §5.2.2.2.1 note 9: discard remaining quota */
			if (ut->total_qu || ut->ul_qu || ut->dl_qu ||
			    ut->time_qu)
				ut->flags |= UPF_FL_QUOTA_REACHED;
			ut->time_inactivity_next = rnow + ut->time_inactivity + 1;
		} else {
			last_pkt = last_pkt ?: rnow;
			ut->time_inactivity_next = last_pkt + ut->time_inactivity + 1;
		}
	}

	if (ut->time_periodic_next && rnow >= ut->time_periodic_next) {
		trig |= UPF_TRIG_FL_PERIO;
		ut->time_periodic_next = 0;
	}

	/* send report if any */
	if (trig)
		_ttc_send_report(ut, trig, 0);

	if (!(ut->flags & UPF_FL_QUOTA_REACHED)) {
		/* re-arm timer */
		__u64 next = _ttc_compute_next_tick(ut, rnow);
		bpf_timer_start(&ut->timer, next, BPF_F_TIMER_CPU_PIN);
	}

	return 0;
}

static __always_inline void
_ttc_measure_time(struct upf_ttc *ut, __u32 *last_pkt, __u32 rnow)
{
	if (unlikely(!ut->report_first_pkt))
		ut->report_first_pkt = rnow;
	ut->report_last_pkt = rnow;

	if (!(ut->flags & UPF_FL_MEAS_TIME)) {
		*last_pkt = rnow;
		return;
	}

	/* count inactivity time (no packet since a looong time) */
	if (ut->inactivity_det_time && *last_pkt) {
		__u32 elapsed = rnow - *last_pkt;
		if (elapsed > ut->inactivity_det_time)
			ut->inactive_time += elapsed - ut->inactivity_det_time;
	}

	if (!ut->duration_ts_last) {
		ut->duration_ts_last = rnow;
		__u64 next = _ttc_compute_next_tick(ut, rnow);
		if (next)
			bpf_timer_start(&ut->timer, next, BPF_F_TIMER_CPU_PIN);
	}
	*last_pkt = rnow;
}

static __always_inline void
upf_ttc_check_dl(struct upf_ttc *ut)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	__u16 trigg = 0;

#ifdef UPF_DEBUG
	if (ut->dl_th || ut->total_th)
		bpf_printk("%s: th{tot:%ld p:%ld} fwd:{tot:%ld dl:%ld}", __func__,
			   ut->total_th, ut->dl_th, ut->ul_bytes + ut->dl_bytes, ut->dl_bytes);
	if (ut->dl_qu || ut->total_qu)
		bpf_printk("%s: qu{tot:%ld p:%ld} fwd:{tot:%ld dl:%ld}", __func__,
			   ut->total_qu, ut->dl_qu, ut->ul_bytes + ut->dl_bytes, ut->dl_bytes);
#endif

	if ((ut->dl_th_next && ut->dl_bytes >= ut->dl_th_next) ||
	    (ut->total_th_next && ut->ul_bytes + ut->dl_bytes >= ut->total_th_next)) {
		trigg |= UPF_TRIG_FL_VOLTH;
		if (ut->total_th)
			ut->total_th_next = ut->total_th + ut->dl_bytes + ut->ul_bytes;
		if (ut->dl_th)
			ut->dl_th_next = ut->dl_th + ut->dl_bytes;
	}

	if ((ut->dl_qu_next && ut->dl_bytes >= ut->dl_qu_next) ||
	    (ut->total_qu_next && ut->ul_bytes + ut->dl_bytes >= ut->total_qu_next)) {
		trigg = UPF_TRIG_FL_VOLQU;
		ut->flags |= UPF_FL_QUOTA_REACHED;
	}

	_ttc_measure_time(ut, &ut->dl_last_pkt, rnow);

	if (trigg) {
		if (ut->flags & UPF_FL_MEAS_TIME)
			_ttc_compute_duration(ut, rnow);
		_ttc_send_report(ut, trigg, 0);
	}
}

static __always_inline void
upf_ttc_check_ul(struct upf_ttc *ut)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	__u16 trigg = 0;

#ifdef UPF_DEBUG
	if (ut->ul_th || ut->total_th)
		bpf_printk("%s: th{tot:%ld p:%ld} fwd:{tot:%ld ul:%ld}", __func__,
			   ut->total_th, ut->ul_th, ut->ul_bytes + ut->dl_bytes, ut->ul_bytes);
	if (ut->ul_qu || ut->total_qu)
		bpf_printk("%s: qu{tot:%ld p:%ld} fwd:{tot:%ld ul:%ld}", __func__,
			   ut->total_qu, ut->ul_qu, ut->ul_bytes + ut->dl_bytes, ut->ul_bytes);
#endif

	if ((ut->ul_th_next && ut->ul_bytes >= ut->ul_th_next) ||
	    (ut->total_th_next && ut->dl_bytes + ut->ul_bytes >= ut->total_th_next)) {
		trigg |= UPF_TRIG_FL_VOLTH;
		if (ut->total_th)
			ut->total_th_next = ut->total_th + ut->dl_bytes + ut->ul_bytes;
		if (ut->ul_th)
			ut->ul_th_next = ut->ul_th + ut->ul_bytes;
	}

	if ((ut->ul_qu_next && ut->ul_bytes >= ut->ul_qu_next) ||
	    (ut->total_qu_next && ut->dl_bytes + ut->ul_bytes >= ut->total_qu_next)) {
		trigg = UPF_TRIG_FL_VOLQU;
		ut->flags |= UPF_FL_QUOTA_REACHED;
		if (ut->total_qu)
			ut->total_qu_next = ut->total_qu + ut->dl_bytes + ut->ul_bytes;
		if (ut->ul_qu)
			ut->ul_qu_next = ut->ul_qu + ut->ul_bytes;
	}

	_ttc_measure_time(ut, &ut->ul_last_pkt, rnow);

	if (trigg) {
		if (ut->flags & UPF_FL_MEAS_TIME)
			_ttc_compute_duration(ut, rnow);
		_ttc_send_report(ut, trigg, 0);
	}
}


SEC("syscall")
int ttc_ctl(struct upf_ttc_cmd *c)
{
	__u32 rnow = bpf_ktime_get_ns() >> 24;
	struct upf_ttc *ut;

	__u32 idx = c->ttc_idx;
	ut = bpf_map_lookup_elem(&upf_ttc, &idx);
	if (ut == NULL)
		return -1;

	if (c->cmd != UPF_TTC_CMD_INIT && (ut->flags & UPF_FL_MEAS_TIME))
		_ttc_compute_duration(ut, rnow);

	switch (c->cmd) {
	case UPF_TTC_CMD_INIT:
	{
		ut->seid = c->seid;
		ut->ttc_idx = c->ttc_idx;
		ut->flags = c->flags;
		if (ut->flags & UPF_FL_QUOTA_EXPLICIT_BLOCK)
			ut->flags |= UPF_FL_QUOTA_REACHED;

		ut->total_th = c->total_th;
		ut->total_qu = c->total_qu;
		ut->ul_th = c->ul_th;
		ut->ul_qu = c->ul_qu;
		ut->dl_th = c->dl_th;
		ut->dl_qu = c->dl_qu;
		ut->time_th = (((__u64)c->time_th * NSEC_PER_SEC) >> 24);
		ut->time_qu = (((__u64)c->time_qu * NSEC_PER_SEC) >> 24);
		ut->time_periodic = (((__u64)c->time_periodic * NSEC_PER_SEC) >> 24);
		ut->time_inactivity = (((__u64)c->time_inactivity * NSEC_PER_SEC) >> 24);
		ut->inactivity_det_time =
			(((__u64)c->inactivity_det_time * NSEC_PER_SEC) >> 24);
		ut->duration_ts_last =
			(ut->flags & UPF_FL_TIME_IMMEDIATE_METER) ? rnow : 0;
		ut->ul_last_pkt = 0;
		ut->dl_last_pkt = 0;

		/* Create URR: Reset all counters */
		ut->total_th_next = ut->total_th;
		ut->total_qu_next = ut->total_qu;
		ut->ul_pkt = 0;
		ut->ul_bytes = 0;
		ut->ul_th_next = ut->ul_th;
		ut->ul_qu_next = ut->ul_qu;
		ut->dl_pkt = 0;
		ut->dl_bytes = 0;
		ut->dl_th_next = ut->dl_th;
		ut->dl_qu_next = ut->dl_qu;
		ut->report_first_pkt = 0;
		ut->report_last_pkt = 0;
		ut->inactive_time = 0;
		ut->duration = 0;
		ut->duration_th_last = 0;
		ut->duration_qu_last = 0;
		ut->time_periodic_next = 0;
		ut->time_inactivity_next = 0;

		/* send ack */
		struct upf_ttc_report ur = {
			.seid = c->seid,
			.ttc_idx = c->ttc_idx,
			.request_id = c->request_id,
		};
		bpf_ringbuf_output(&upf_events, &ur, sizeof(ur), 0);

		/* arm timer(s) */
		if (bpf_timer_init(&ut->timer, &upf_ttc, CLOCK_MONOTONIC) != 0)
			return -1;
		bpf_timer_set_callback(&ut->timer, _ttc_timer_tick);
		__u64 next = _ttc_compute_next_tick(ut, rnow);
		if (next)
			bpf_timer_start(&ut->timer, next, BPF_F_TIMER_CPU_PIN);
		break;
	}

	case UPF_TTC_CMD_UPDATE:
	{
		/* quota handling: stop or restart */
		if (c->flags & UPF_FL_QUOTA_EXPLICIT_BLOCK) {
			ut->flags |= UPF_FL_QUOTA_REACHED;
			_ttc_send_report(ut, UPF_TRIG_FL_VOLQU, c->request_id);
			break;
		}
		if ((c->total_qu || c->ul_qu || c->dl_qu ||
		     c->time_qu) && (ut->flags & UPF_FL_QUOTA_REACHED))
			ut->flags &= ~UPF_FL_QUOTA_REACHED;

		/* Update URR: restart changed triggers */
		if (ut->total_th != c->total_th) {
			ut->total_th = c->total_th;
			ut->total_th_next = ut->total_th ?
				ut->total_th + ut->ul_bytes + ut->dl_bytes : 0;
		}
		if (ut->ul_th != c->ul_th) {
			ut->ul_th = c->ul_th;
			ut->ul_th_next = ut->ul_th ? ut->ul_th + ut->ul_bytes : 0;
		}
		if (ut->dl_th != c->dl_th) {
			ut->dl_th = c->dl_th;
			ut->dl_th_next = ut->dl_th ? ut->dl_th + ut->dl_bytes : 0;
		}
		if (ut->total_qu != c->total_qu) {
			ut->total_qu = c->total_qu;
			ut->total_qu_next = ut->total_qu ?
				ut->total_qu + ut->ul_bytes + ut->dl_bytes : 0;
		}
		if (ut->ul_qu != c->ul_qu) {
			ut->ul_qu = c->ul_qu;
			ut->ul_qu_next = ut->ul_qu ? ut->ul_qu + ut->ul_bytes : 0;
		}
		if (ut->dl_qu != c->dl_qu) {
			ut->dl_qu = c->dl_qu;
			ut->dl_qu_next = ut->dl_qu ? ut->dl_qu + ut->dl_bytes : 0;
		}
		ut->time_th = (((__u64)c->time_th * NSEC_PER_SEC) >> 24);
		ut->time_qu = (((__u64)c->time_qu * NSEC_PER_SEC) >> 24);
		ut->time_periodic = (((__u64)c->time_periodic * NSEC_PER_SEC) >> 24);
		ut->time_inactivity = (((__u64)c->time_inactivity * NSEC_PER_SEC) >> 24);
		ut->inactivity_det_time =
			(((__u64)c->inactivity_det_time * NSEC_PER_SEC) >> 24);
		ut->duration_ts_last =
			(ut->flags & UPF_FL_TIME_IMMEDIATE_METER) ? rnow : 0;
		ut->ul_last_pkt = 0;
		ut->dl_last_pkt = 0;

		ut->duration_th_last = ut->duration;
		ut->duration_qu_last = ut->duration;
		ut->time_periodic_next = 0;
		ut->time_inactivity_next = 0;

		/* re-arm timer(s) */
		__u64 next = _ttc_compute_next_tick(ut, rnow);
		if (next)
			bpf_timer_start(&ut->timer, next, BPF_F_TIMER_CPU_PIN);

		_ttc_send_report(ut, 0, c->request_id);
		break;
	}

	case UPF_TTC_CMD_DELETE:
		_ttc_send_report(ut, 0, c->request_id);
		bpf_timer_cancel(&ut->timer);
		break;

	case UPF_TTC_CMD_REPORT:
		_ttc_send_report(ut, 0, c->request_id);
		break;
	}

	return 0;
}

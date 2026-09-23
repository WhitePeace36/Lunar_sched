// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef HELPERS_H
#define HELPERS_H
#include "datatypes.h"
#include "defines.h"

static __always_inline struct task_ctx* get_task_ctx(struct task_struct* task)
{
  return bpf_task_storage_get(&task_ctx_store, task, NULL, 0);
}

static __always_inline u64 cpu_dsq(u32 cpu)
{
  return DSQ_CPU_BASE + cpu ;
}

static __always_inline u32 cpu_llc(u32 cpu)
{
  return cpu_to_llc[cpu];
}

// ---------------------------------------------------------------------------
// Latency criticality
// ---------------------------------------------------------------------------

static __always_inline u64 exponentially_weighted_moving_avg(u64 old, u64 sample)
{
  return old - (old >> 2) + (sample >> 2);
}

static __always_inline u32 ilog2(u64 v)
{
  return v ? log2_u64(v) - 1 : 0;
}

static __always_inline u64 elapsed(u64 now, u64 last)
{
  return now > last ? now - last : 0;
}

static __always_inline u64 clamp_interval(u64 interval)
{
  if (interval < CRIT_INTERVAL_MIN)
    return CRIT_INTERVAL_MIN;
  if (interval > CRIT_INTERVAL_REF)
    return CRIT_INTERVAL_REF;
  return interval;
}

// A gap far longer than the usual rhythm means the task went idle. A gap only
// slightly longer is jitter, and folding that into the score makes crit swing
// by several points depending on when it is sampled.
static __always_inline u64 effective_interval(u64 avg, u64 last, u64 now)
{
  u64 since = elapsed(now, last);
  return clamp_interval(since > avg * 4 ? since : avg);
}

static __always_inline u32 calc_crit(struct task_ctx* tctx, u64 now)
{
  u32 crit = ilog2(CRIT_INTERVAL_REF / effective_interval(tctx->wait_interval, tctx->last_woken_at, now)) +
             ilog2(CRIT_INTERVAL_REF / effective_interval(tctx->wake_interval, tctx->last_wake_at, now));

  return crit > CRIT_MAX ? CRIT_MAX : crit;
}

// ---------------------------------------------------------------------------
// Virtual time placement
// ---------------------------------------------------------------------------

// Where this task belongs in the queue.
//
// The base is its accumulated cpu time, so a task that has had less cpu sorts
// first. On wakeup, criticality buys a head start of up to VTIME_CREDIT_MAX;
// that is what gives a frame or audio thread its latency, and the cap is what
// stops it from shutting anyone out. The upper clamp keeps a task that has
// been running from falling so far behind that it becomes unreachable.
static __always_inline u64 calc_place_vtime(struct task_ctx* tctx, u64 enq_flags)
{
  u64 vt = tctx->vtime;
  u64 clock = vtime_now;

  if (enq_flags & SCX_ENQ_WAKEUP)
  {
    u64 credit = (u64)tctx->crit * VTIME_CREDIT_MAX / CRIT_MAX;
    u64 floor = clock > credit ? clock - credit : 0;

    if (time_before(vt, floor))
      vt = floor;
  }

  if (time_before(clock + SLICE_DEFAULT, vt))
    vt = clock + SLICE_DEFAULT;

  return vt;
}



#endif  // HELPERS_H
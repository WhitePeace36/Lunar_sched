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

static __always_inline u64 get_dsq_task_slice(u64 dsqType)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return SLICE_LC;
    case DSQ_TYPE_INTERACTIVE:
      return SLICE_INTERACTIVE;
    case DSQ_TYPE_NORMAL:
      return SLICE_NORMAL;
    case DSQ_TYPE_GREEDY:
      return SLICE_GREEDY;
  }
  return SLICE_GREEDY;
}

static __always_inline u64 get_cpu_dsq_from_type(u64 dsqType, u32 cpu)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return DSQ_CPU_QUEUE_BASE_LC + cpu;
    case DSQ_TYPE_INTERACTIVE:
      return DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu;
    case DSQ_TYPE_NORMAL:
      return DSQ_CPU_QUEUE_BASE_NORMAL + cpu;
    case DSQ_TYPE_GREEDY:
      return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
  }
  return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
}

static __always_inline void stamp_tier_head_ts(struct dispatch_ctx* dctx, u64 dsqType, u64 now)
{
  switch (dsqType)
  {
    case DSQ_TYPE_INTERACTIVE:
      dctx->tier_head_ts[DSQ_TYPE_INTERACTIVE] = now;
      return;
    case DSQ_TYPE_NORMAL:
      dctx->tier_head_ts[DSQ_TYPE_NORMAL] = now;
      return;
    case DSQ_TYPE_GREEDY:
      dctx->tier_head_ts[DSQ_TYPE_GREEDY] = now;
      return;
  }
}

static __always_inline bool is_kthread(const struct task_struct* p)
{
  return p->flags & PF_KTHREAD;
}

static __always_inline bool is_high_prio_kthread_task(struct task_struct* p)
{
  return p->prio == MAX_RT_PRIO && is_kthread(p);
}

static __always_inline struct task_ctx* get_task_ctx(struct task_struct* task)
{
  return bpf_task_storage_get(&task_ctx_store, task, NULL, 0);
}

static __always_inline u32 cpu_llc_id(u32 cpu)
{
  cpu &= (MAX_CPUS - 1);
  return cpu_to_llc[cpu];
}

static __always_inline u32 task_duty(const struct task_ctx* tctx)
{
  return (tctx->run_acc << 10) / (tctx->run_acc + tctx->sleep_acc + 1);
}

static __always_inline void duty_account(struct task_ctx* tctx, u64 run, u64 slept)
{
  if (run > DUTY_WINDOW_NS)
    run = DUTY_WINDOW_NS;
  if (slept > DUTY_WINDOW_NS)
    slept = DUTY_WINDOW_NS;

  tctx->run_acc += run;

  if (tctx->run_acc > DUTY_WINDOW_NS)
    tctx->run_acc = DUTY_WINDOW_NS;

  tctx->sleep_acc += slept;

  if (tctx->run_acc + tctx->sleep_acc > 2 * DUTY_WINDOW_NS)
  {
    tctx->run_acc >>= 1;
    tctx->sleep_acc >>= 1;
  }
}

static __always_inline u64 getTickInterval_ns(void)
{
  return 1000000000ULL / CONFIG_HZ;
}

// ---------------------------------------------------------------------------
// Latency criticality
// ---------------------------------------------------------------------------

static __always_inline u64 ewma(u64 old, u64 sample)
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

static __always_inline u64 clamp_ivl(u64 ivl)
{
  if (ivl < CRIT_IVL_MIN)
    return CRIT_IVL_MIN;
  if (ivl > CRIT_IVL_REF)
    return CRIT_IVL_REF;
  return ivl;
}

static __always_inline u64 effective_ivl(u64 avg, u64 last, u64 now)
{
  u64 since = elapsed(now, last);
  return clamp_ivl(since > avg ? since : avg);
}

static __always_inline u32 calc_crit(struct task_ctx* tctx, u64 now)
{
  u32 crit = ilog2(CRIT_IVL_REF / effective_ivl(tctx->wait_ivl, tctx->last_woken_at, now)) + ilog2(CRIT_IVL_REF / effective_ivl(tctx->wake_ivl, tctx->last_wake_at, now));

  return crit > CRIT_MAX ? CRIT_MAX : crit;
}

#endif  // HELPERS_H
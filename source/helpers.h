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
  }
  return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
}

// scx_bpf_dsq_nr_queued() returns a negative error for an invalid DSQ.
static __always_inline u64 dsq_queued(u64 dsq)
{
  s32 n = scx_bpf_dsq_nr_queued(dsq);
  return n > 0 ? (u64)n : 0;
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

static __always_inline struct task_ctx* get_task_ctx(struct task_struct* task)
{
  return bpf_task_storage_get(&task_ctx_store, task, NULL, 0);
}

static __always_inline struct dispatch_ctx* get_dispatch_ctx(u32 cpu)
{
  u32 key = 0;
  return bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
}

static __always_inline u32 cpu_llc_id(u32 cpu)
{
  cpu &= (MAX_CPUS - 1);
  return cpu_to_llc[cpu];
}

static __always_inline bool cpu_is_online(u32 cpu)
{
  cpu &= (MAX_CPUS - 1);
  return cpu_online[cpu];
}

static __always_inline bool is_percpu_kthread(const struct task_struct* p)
{
  return (p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1;
}

static __always_inline bool is_rt_task(const struct task_struct* p)
{
  // Per-cpu kernel threads with an RT policy (migration/N for every affinity
  // change and task migration, ...) only run for microseconds: they don't take
  // the cpu away in a way worth moving tasks for.
  if (is_percpu_kthread(p))
    return false;
  int policy = p->policy;
  return policy == SCHED_FIFO || policy == SCHED_RR || policy == SCHED_DEADLINE;
}

// The cpu runs a task of a higher sched class (RT, deadline) right now. sched_ext
// tasks don't run there until it is done, even when nothing of ours is running.
static __always_inline bool cpu_taken_by_rt(u32 cpu)
{
  struct task_struct* curr = __COMPAT_scx_bpf_cpu_curr(cpu);
  return curr && is_rt_task(curr);
}

// Time used by a task of the tier a starvation override runs for counts
// against the override budget.
static __always_inline void charge_override(struct dispatch_ctx* dctx, u64 tier, u64 used)
{
  if (!dctx->override_left || tier != dctx->override_tier)
    return;
  dctx->override_left = dctx->override_left > used ? dctx->override_left - used : 0;
}

static __always_inline void charge_wake_boost(struct task_ctx* tctx, u64 used)
{
  if (tctx->boost_dsq_type != DSQ_TYPE_EMPTY)
    tctx->boost_used += used;
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
  tctx->sleep_acc += slept;

  if (tctx->run_acc + tctx->sleep_acc > 2 * DUTY_WINDOW_NS)
  {
    tctx->run_acc >>= 1;
    tctx->sleep_acc >>= 1;
  }
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

static __always_inline u64 effective_interval(u64 avg, u64 last, u64 now)
{
  u64 since = elapsed(now, last);
  return clamp_interval(since > (avg * 8) ? since : avg);
}

static __always_inline u32 calc_crit(struct task_ctx* tctx, u64 now)
{
  u32 crit = ilog2(CRIT_INTERVAL_REF / effective_interval(tctx->wait_interval, tctx->last_woken_at, now)) +
             ilog2(CRIT_INTERVAL_REF / effective_interval(tctx->wake_interval, tctx->last_wake_at, now));

  return crit > CRIT_MAX ? CRIT_MAX : crit;
}

#endif  // HELPERS_H

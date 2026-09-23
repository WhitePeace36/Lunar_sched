// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <include/scx/common.bpf.h>
#include <include/bpf_experimental.h>
#include <bpf/bpf_helpers.h>
#include "defines.h"
#include "datatypes.h"
#include "helpers.h"
#include "dispatches.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

// ---------------------------------------------------------------------------
// Criticality tracking
// ---------------------------------------------------------------------------

// A wakeup came in for @p. If a task caused it, that task is a producer.
static __always_inline void record_waker(struct task_struct* p, u64 now)
{
  // In interrupt context "current" is whatever the interrupt landed on, not
  // the cause of the wakeup. Gpu and input interrupts would otherwise credit
  // random hogs as producers. Queued cross cpu wakeups are also handled from
  // an interrupt and get skipped; this is a sampled signal and does not need
  // every event.
  if (bpf_in_interrupt())
    return;

  struct task_struct* waker = bpf_get_current_task_btf();
  if (!waker || waker->pid == p->pid)
    return;

  struct task_ctx* wctx = get_task_ctx(waker);
  if (!wctx)
    return;

  wctx->wake_interval = exponentially_weighted_moving_avg(wctx->wake_interval, clamp_interval(elapsed(now, wctx->last_wake_at)));
  wctx->last_wake_at = now;
}

// ---------------------------------------------------------------------------
// Preemption
//
// The queue decides the order; preemption decides when that decision is made
// again. Without it a waking task with a large credit still sits behind the
// running task for up to a full slice, which is exactly the latency the
// credit exists to remove.
// ---------------------------------------------------------------------------
static __always_inline void maybe_preempt(u32 cpu, u64 vt, u64 now)
{
  u32 key = 0;
  struct dispatch_ctx* dctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
  if (!dctx)
    return;

  if (dctx->running_vtime == VTIME_NONE)
  {
    // Idle: ring the bell so it picks the task up now.
    scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
    return;
  }

  bool clearly_ahead = time_before(vt + PREEMPT_MARGIN, dctx->running_vtime);
  bool ran_enough = elapsed(now, dctx->run_started) >= MIN_RUN_BEFORE_PREEMPT;

  if (clearly_ahead && ran_enough)
    scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

s32 BPF_STRUCT_OPS_SLEEPABLE(lunar_init)
{
  u32 nr = scx_bpf_nr_cpu_ids();

  if (nr > MAX_CPUS)
    nr = MAX_CPUS;

  u32 key = 0;

  for (u32 cpu = 0; cpu < nr && cpu < MAX_CPUS; cpu++)
  {
    s32 err = scx_bpf_create_dsq(DSQ_CPU_BASE + cpu, -1);
    if (err)
      return err;

    // Zeroed storage would read as "running a task whose vtime is 0", which
    // every waker would lose against. Start every cpu as idle instead.
    struct dispatch_ctx* dctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);
    if (dctx)
      dctx->running_vtime = VTIME_NONE;
  }

  return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(lunar_init_task, struct task_struct* p, struct scx_init_task_args* args)
{
  struct task_ctx* tctx;
  u64 now = bpf_ktime_get_ns();

  tctx = bpf_task_storage_get(&task_ctx_store, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!tctx)
    return -ENOMEM;

  // A new task starts level with the clock: no credit, no debt.
  tctx->vtime = vtime_now;
  tctx->started_at = now;

  // No history yet, so no criticality. It is earned from the first wakeups.
  tctx->wait_interval = CRIT_INTERVAL_REF;
  tctx->wake_interval = CRIT_INTERVAL_REF;
  tctx->last_woken_at = now;
  tctx->last_wake_at = now;
  tctx->crit = 0;

  return 0;
}

s32 BPF_STRUCT_OPS(lunar_select_cpu, struct task_struct* p, s32 prev_cpu, u64 wake_flags)
{
  bool is_idle = false;
  s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

  // An idle cpu was found, so there is nothing to order against: skip the
  // queue entirely. This is the majority of wakeups on a desktop.
  if (is_idle)
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_DEFAULT, 0);

  return cpu;
}

void BPF_STRUCT_OPS(lunar_enqueue, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u32 cpu = scx_bpf_task_cpu(p);
  u64 now = bpf_ktime_get_ns();
  u64 vt;

  if (tctx)
  {
    // Credit only on a real wakeup. A re-enqueue after slice expiry must not
    // re-credit, or a busy task would pin itself at the head of the queue.
    vt = calc_place_vtime(tctx, enq_flags);
    tctx->vtime = vt;
  }
  else
  {
    vt = vtime_now;
  }

  scx_bpf_dsq_insert_vtime(p, cpu_dsq(cpu), SLICE_DEFAULT, vt, enq_flags);

  if (enq_flags & SCX_ENQ_WAKEUP)
    maybe_preempt(cpu, vt, now);
}

void BPF_STRUCT_OPS(lunar_dispatch, s32 cpu, struct task_struct* prev)
{
  if (scx_bpf_dsq_move_to_local(cpu_dsq((u32)cpu), 0))
    return;

  steal_work((u32)cpu);
}

void BPF_STRUCT_OPS(lunar_running, struct task_struct* p)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u64 now = bpf_ktime_get_ns();
  u32 key = 0;
  struct dispatch_ctx* dctx = bpf_map_lookup_elem(&dispatch_state, &key);

  if (!tctx)
    return;

  tctx->started_at = now;

  // Move the clock forward to the task now being served. Racy across cpus by
  // design: it is a reference point, and the clamps bound the error.
  if (time_before(vtime_now, tctx->vtime))
    vtime_now = tctx->vtime;

  if (dctx)
  {
    dctx->running_vtime = tctx->vtime;
    dctx->run_started = now;
  }

  // if (log_runs)
  //   bpf_printk("lunar_run cpu=%d pid=%d comm=%s vtime=%llu crit=%u duty=%lld", bpf_get_smp_processor_id(), p->pid, p->comm, tctx->vtime, tctx->crit, tctx->duty);
}

void BPF_STRUCT_OPS(lunar_stopping, struct task_struct* p, bool runnable)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u64 now = bpf_ktime_get_ns();
  u32 key = 0;
  struct dispatch_ctx* dctx = bpf_map_lookup_elem(&dispatch_state, &key);

  if (dctx)
    dctx->running_vtime = VTIME_NONE;

  if (!tctx)
    return;

  u64 used_ns = elapsed(now, tctx->started_at);

  // The charge is the whole ordering rule: cpu time used moves a task back.
  tctx->vtime += used_ns;
  tctx->crit = calc_crit(tctx, now);
}

void BPF_STRUCT_OPS(lunar_runnable, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  u64 now = bpf_ktime_get_ns();

  if (!tctx)
    return;

  if (enq_flags & SCX_ENQ_WAKEUP)
  {
    tctx->wait_interval = exponentially_weighted_moving_avg(tctx->wait_interval, clamp_interval(elapsed(now, tctx->last_woken_at)));
    tctx->last_woken_at = now;
    record_waker(p, now);
    tctx->crit = calc_crit(tctx, now);
  }
}

void BPF_STRUCT_OPS(lunar_quiescent, struct task_struct* p, u64 deq_flags)
{
}

void BPF_STRUCT_OPS(lunar_exit, struct scx_exit_info* ei)
{
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(lunar_ops,
               .init = (void*)lunar_init,
               .init_task = (void*)lunar_init_task,
               .select_cpu = (void*)lunar_select_cpu,
               .enqueue = (void*)lunar_enqueue,
               .dispatch = (void*)lunar_dispatch,
               .running = (void*)lunar_running,
               .stopping = (void*)lunar_stopping,
               .runnable = (void*)lunar_runnable,
               .quiescent = (void*)lunar_quiescent,
               .exit = (void*)lunar_exit,
               .name = "scx_lunar");
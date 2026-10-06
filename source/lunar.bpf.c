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
#include "helpers.h"
#include "datatypes.h"
#include "dispatches.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

static __always_inline u64 tier_from_crit(s64 crit)
{
  if (crit >= CRIT_EDGE_LC)
    return DSQ_TYPE_LC;
  if (crit >= CRIT_EDGE_INTERACTIVE)
    return DSQ_TYPE_INTERACTIVE;
  if (crit >= CRIT_EDGE_NORMAL)
    return DSQ_TYPE_NORMAL;
  return DSQ_TYPE_GREEDY;
}

static __always_inline u64 tier_cap_from_duty(s64 duty)
{
  if (duty < DUTY_CAP_LC)
    return DSQ_TYPE_LC;
  if (duty < DUTY_CAP_INTERACTIVE)
    return DSQ_TYPE_INTERACTIVE;
  if (duty < DUTY_CAP_NORMAL)
    return DSQ_TYPE_NORMAL;
  return DSQ_TYPE_GREEDY;
}

static __always_inline u64 target_tier(s64 crit, s64 duty)
{
  u64 wanted = tier_from_crit(crit);
  u64 allowed = tier_cap_from_duty(duty);
  return wanted > allowed ? wanted : allowed;
}

static __always_inline u64 sanitize_tier(u64 tier)
{
  if (tier < DSQ_TYPE_LC || tier > DSQ_TYPE_GREEDY)
    return DSQ_TYPE_GREEDY;
  return tier;
}

static __always_inline void update_task_dsq_type(struct task_struct* task, struct task_ctx* tctx, u64 now)
{
  u64 old = tctx->current_dsq_type;

  tctx->crit = calc_crit(tctx, now);

  if (tctx->duty_samples < DUTY_SAMPLES_NEEDED)
  {
    tctx->current_dsq_type = DSQ_TYPE_GREEDY;
  }
  else
  {
    s64 crit = tctx->crit;
    u64 pessimistic = target_tier(crit, tctx->duty + DUTY_HYST);
    u64 optimistic = target_tier(crit, tctx->duty - DUTY_HYST);

    if (pessimistic < old)
      tctx->current_dsq_type = pessimistic;
    else if (optimistic > old)
      tctx->current_dsq_type = optimistic;
  }

  if ((task->flags & PF_KTHREAD) && tctx->duty < DUTY_CAP_INTERACTIVE && tctx->current_dsq_type > DSQ_TYPE_INTERACTIVE)
    tctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
}

// Tier the task runs in now: its own tier, or a better one after a wake boost.
static __always_inline u64 effective_tier(struct task_ctx* tctx)
{
  if (!tctx)
    return DSQ_TYPE_GREEDY;
  u64 tier = sanitize_tier(tctx->current_dsq_type);
  if (tctx->boost_dsq_type < tier)
    return tctx->boost_dsq_type;
  return tier;
}

// Wake boost: called in the context of the waker. A task that wakes a task of a
// worse tier lifts it into its own tier until it sleeps again, for at most
// WAKE_BOOST_BUDGET_NS of cpu time, so work it waits for (a helper thread,
// wineserver, a kworker submitting its gpu job, ...) runs right away instead of
// behind everything in between.
static __always_inline void apply_wake_boost(struct task_struct* p, struct task_ctx* tctx)
{
  // A wakeup from an interrupt runs on top of whatever task was interrupted,
  // that task is not the waker.
  if (!bpf_in_task())
    return;

  struct task_struct* waker = bpf_get_current_task_btf();
  if (!waker || waker == p || (waker->flags & PF_IDLE))
    return;
  if (!WAKE_BOOST_FROM_KTHREADS && (waker->flags & PF_KTHREAD))
    return;

  struct task_ctx* wctx = get_task_ctx(waker);
  if (!wctx)
    return;

  u64 waker_tier = effective_tier(wctx);
  if (waker_tier < sanitize_tier(tctx->current_dsq_type) && waker_tier < tctx->boost_dsq_type)
  {
    tctx->boost_dsq_type = waker_tier;
    tctx->boost_used = 0;
  }
}

static __always_inline void record_waker(struct task_struct* p, u64 now)
{
  if (bpf_in_interrupt())
    return;

  struct task_struct* waker = bpf_get_current_task_btf();
  if (waker->pid == p->pid)
    return;

  struct task_ctx* wctx = get_task_ctx(waker);
  if (!wctx)
    return;

  wctx->wake_interval = exponentially_weighted_moving_avg(wctx->wake_interval, clamp_interval(elapsed(now, wctx->last_wake_at)));
  wctx->last_wake_at = now;
}

// callbacks

s32 BPF_STRUCT_OPS_SLEEPABLE(lunar_init)
{
  s32 ret;

  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();

  u32 cpu;
  bpf_for(cpu, 0, nr_cpu_ids)
  {
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_LC + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_NORMAL + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu, -1);
    if (ret)
      return ret;
    ret = scx_bpf_create_dsq(DSQ_CPU_QUEUE_BASE_GREEDY + cpu, -1);
    if (ret)
      return ret;
  }

  bpf_for(cpu, 0, nr_cpu_ids)
  {
    struct dispatch_ctx* dispatch_ctx = get_dispatch_ctx(cpu);
    if (!dispatch_ctx)
      return -ENOMEM;

    dispatch_ctx->current_task_dsq_type = DSQ_TYPE_EMPTY;

    u64 now = bpf_ktime_get_ns();
    dispatch_ctx->tier_head_ts[DSQ_TYPE_INTERACTIVE] = now;
    dispatch_ctx->tier_head_ts[DSQ_TYPE_NORMAL] = now;
    dispatch_ctx->tier_head_ts[DSQ_TYPE_GREEDY] = now;
    dispatch_ctx->last_override_ts = now;
    dispatch_ctx->override_tier = DSQ_TYPE_EMPTY;
    dispatch_ctx->override_left = 0;
    // rt_busy is not reset here: the sched_switch hook may already be attached
    // and counting (nr_rt_busy), the map starts zeroed.
    dispatch_ctx->preempt_pending = false;
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

  tctx->current_dsq_type = DSQ_TYPE_GREEDY;
  tctx->boost_dsq_type = DSQ_TYPE_EMPTY;
  tctx->boost_used = 0;
  tctx->started_at = now;
  tctx->run_acc = DUTY_INIT_RUN_NS;
  tctx->sleep_acc = 0;
  tctx->duty_samples = 0;
  tctx->granted_slice = 0;
  tctx->resume_slice = 0;
  tctx->last_migrated_at = 0;

  tctx->wait_interval = CRIT_INTERVAL_REF;
  tctx->wake_interval = CRIT_INTERVAL_REF;
  tctx->last_woken_at = now;
  tctx->last_wake_at = now;
  tctx->crit = 0;
  tctx->duty = DUTY_RANGE / 2;

  if (p->flags & PF_KTHREAD)
  {
    tctx->run_acc = (KTHREAD_INIT_DUTY_PCT * DUTY_WINDOW_NS) / 100;
    tctx->sleep_acc = DUTY_WINDOW_NS - tctx->run_acc;
    tctx->duty_samples = DUTY_SAMPLES_NEEDED;
    tctx->duty = task_duty(tctx);
    tctx->current_dsq_type = DSQ_TYPE_INTERACTIVE;
  }

  return 0;
}

void BPF_STRUCT_OPS(lunar_exit_task, struct task_struct* p, struct scx_exit_task_args* args) { }

s32 BPF_STRUCT_OPS(lunar_select_cpu, struct task_struct* p, s32 prev_cpu, u64 wake_flags)
{
  bool is_idle = false;
  struct task_ctx* tctx = get_task_ctx(p);

  if (tctx && (wake_flags & SCX_WAKE_TTWU))
    apply_wake_boost(p, tctx);

  s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

  // Run directly on the idle cpu, unless tasks of the same or a better tier are
  // already queued there (their kick is still on the way): the local DSQ runs
  // before them. Otherwise enqueue() queues it properly.
  if (is_idle && cpu_load_ahead(cpu, effective_tier(tctx)) == 0)
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE_NS, 0);

  return cpu;
}

void BPF_STRUCT_OPS(lunar_enqueue, struct task_struct* p, u64 enq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);

  // Pinned tasks skip select_cpu, for them the boost is taken here. A wakeup
  // that got queued to the target cpu arrives here in interrupt context and is
  // filtered out in apply_wake_boost().
  if (tctx && (enq_flags & SCX_ENQ_WAKEUP))
    apply_wake_boost(p, tctx);

  u64 tier = effective_tier(tctx);
  u32 cpu = scx_bpf_task_cpu(p);
  u64 now = bpf_ktime_get_ns();

  // A preempted task goes back to the head of its queue with the rest of its
  // slice, unless its cpu is taken by an RT task now: then it is placed like any
  // other.
  if (tctx && tctx->resume_slice && cpu_taken_by_rt(cpu))
    tctx->resume_slice = 0;

  if (tctx && tctx->resume_slice)
  {
    u64 slice = tctx->resume_slice;
    u64 own_dsq = get_cpu_dsq_from_type(tier, cpu);
    struct dispatch_ctx* own = get_dispatch_ctx(cpu);
    tctx->resume_slice = 0;
    if (own && tier != DSQ_TYPE_LC && dsq_queued(own_dsq) == 0)
      stamp_tier_head_ts(own, tier, now);
    scx_bpf_dsq_insert(p, own_dsq, slice, enq_flags | SCX_ENQ_HEAD);
    return;
  }

  u32 target = tctx ? (u32)pick_enqueue_cpu(p, tctx, tier, cpu, now) : cpu;
  if (!cpu_is_online(target))
    target = cpu;
  u64 dsq = get_cpu_dsq_from_type(tier, target);
  struct dispatch_ctx* dctx = get_dispatch_ctx(target);

  if (dctx && tier != DSQ_TYPE_LC && dsq_queued(dsq) == 0)
    stamp_tier_head_ts(dctx, tier, now);

  scx_bpf_dsq_insert(p, dsq, SLICE_NS, enq_flags);

  if (!dctx)
  {
    scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
    return;
  }

  u64 running = dctx->current_task_dsq_type;
  if (running == DSQ_TYPE_EMPTY)
  {
    scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
  }
  else if (tier == DSQ_TYPE_LC && (enq_flags & SCX_ENQ_WAKEUP) && running > tier)
  {
    dctx->preempt_pending = true;
    scx_bpf_kick_cpu(target, SCX_KICK_PREEMPT);
  }
}

void BPF_STRUCT_OPS(lunar_dispatch, s32 cpu, struct task_struct* prev)
{
  u64 prev_tier = DSQ_TYPE_EMPTY;
  struct task_ctx* pctx = NULL;
  struct dispatch_ctx* dctx = get_dispatch_ctx(cpu);

  if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
  {
    pctx = get_task_ctx(prev);
    if (pctx)
    {
      u64 now = bpf_ktime_get_ns();
      u64 used = elapsed(now, pctx->started_at);
      if (dctx)
        charge_override(dctx, effective_tier(pctx), used);
      // The slice is over: a wake boost ends once its budget is used up. A
      // preemption (dispatch is called before stopping then) keeps the boost:
      // the task gets the rest of its slice back in the boosted tier.
      charge_wake_boost(pctx, used);
      if (!(dctx && dctx->preempt_pending) && pctx->boost_used >= WAKE_BOOST_BUDGET_NS)
        pctx->boost_dsq_type = DSQ_TYPE_EMPTY;
      duty_account(pctx, used, 0);
      pctx->started_at = now;
      pctx->duty = task_duty(pctx);
      update_task_dsq_type(prev, pctx, now);
      prev_tier = effective_tier(pctx);
    }
  }

  if (dispatch_dsq_per_cpu(cpu, prev_tier) != DSQ_TYPE_EMPTY || !prev || !pctx)
    return;

  // prev keeps running for a new slice, a boost left over from a preemption
  // that didn't replace it ends here once its budget is used up.
  if (pctx->boost_dsq_type != DSQ_TYPE_EMPTY && pctx->boost_used >= WAKE_BOOST_BUDGET_NS)
  {
    pctx->boost_dsq_type = DSQ_TYPE_EMPTY;
    prev_tier = sanitize_tier(pctx->current_dsq_type);
  }

  scx_bpf_task_set_slice(prev, SLICE_NS);
  pctx->granted_slice = SLICE_NS;

  if (dctx)
  {
    dctx->current_task_dsq_type = prev_tier;
    dctx->preempt_pending = false;
  }
}

void BPF_STRUCT_OPS(lunar_running, struct task_struct* p)
{
  struct task_ctx* context = get_task_ctx(p);
  if (!context)
    return;

  u32 cpu = bpf_get_smp_processor_id();
  struct dispatch_ctx* dispatch_ctx = get_dispatch_ctx(cpu);
  if (!dispatch_ctx)
    return;

  dispatch_ctx->current_task_dsq_type = effective_tier(context);
  dispatch_ctx->preempt_pending = false;

  context->started_at = bpf_ktime_get_ns();
  context->granted_slice = p->scx.slice;

  // bpf_printk("lunar_run cpu=%d pid=%d tgid=%d comm=%s dsqType=%llu duty=%lld crit=%d ", bpf_get_smp_processor_id(), p->pid, p->tgid, p->comm, context->current_dsq_type,
  //            context->duty, context->crit);
}

void BPF_STRUCT_OPS(lunar_stopping, struct task_struct* task, bool runnable)
{
  u64 now = bpf_ktime_get_ns();

  struct task_ctx* tctx = get_task_ctx(task);
  if (!tctx)
    return;

  u64 used_ns = elapsed(now, tctx->started_at);
  struct dispatch_ctx* dctx = get_dispatch_ctx(scx_bpf_task_cpu(task));
  if (dctx)
    charge_override(dctx, effective_tier(tctx), used_ns);
  charge_wake_boost(tctx, used_ns);

  duty_account(tctx, used_ns, 0);
  tctx->duty = task_duty(tctx);

  update_task_dsq_type(task, tctx, now);

  if (!dctx)
    return;

  // Only a preemption kick (it sets the slice to 0) gives the rest of the slice
  // back, not a task that stops for another reason while a kick is pending.
  if (dctx->preempt_pending && runnable && task->scx.slice == 0 && tctx->granted_slice > used_ns + RESUME_SLICE_MIN_NS)
    tctx->resume_slice = tctx->granted_slice - used_ns;

  // A wake boost ends when the task sleeps or its budget is used up, a
  // preempted task keeps it for the rest of its slice.
  if (!tctx->resume_slice && (!runnable || tctx->boost_used >= WAKE_BOOST_BUDGET_NS))
    tctx->boost_dsq_type = DSQ_TYPE_EMPTY;

  dctx->preempt_pending = false;
  dctx->current_task_dsq_type = DSQ_TYPE_EMPTY;
}

void BPF_STRUCT_OPS(lunar_exit, struct scx_exit_info* ei)
{
  UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(lunar_quiescent, struct task_struct* p, u64 deq_flags)
{
  struct task_ctx* tctx = get_task_ctx(p);
  if (!tctx)
    return;

  tctx->resume_slice = 0;
  tctx->boost_dsq_type = DSQ_TYPE_EMPTY;
  tctx->blocked_at = (deq_flags & SCX_DEQ_SLEEP) ? bpf_ktime_get_ns() : 0;
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
  }

  if (tctx->blocked_at)
  {
    duty_account(tctx, 0, elapsed(now, tctx->blocked_at));
    tctx->duty_samples++;
    if (tctx->duty_samples > DUTY_SAMPLES_MAX)
    {
      tctx->duty_samples = DUTY_SAMPLES_MAX;
    }
    tctx->blocked_at = 0;
    tctx->duty = task_duty(tctx);
    update_task_dsq_type(p, tctx, now);
  }
}

// Every context switch: keeps track of the cpus an RT or deadline task runs on.
// When one takes a cpu (from one of our tasks or from idle), the tasks already
// picked for it (its local DSQ) go back through enqueue(), which sees the cpu as
// busy and places them on another one, and an idle cpu is woken for the first
// task waiting in its queues. Tasks in its tier queues stay: other cpus take
// them over in dispatch (try_acquire_from_rt_cpu). (This replaces
// ops.cpu_release, which newer kernels deprecate.)
SEC("tp_btf/sched_switch")
int BPF_PROG(lunar_sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next, unsigned int prev_state)
{
  u32 cpu = bpf_get_smp_processor_id();
  struct dispatch_ctx* dctx = get_dispatch_ctx(cpu);
  if (!dctx)
    return 0;

  bool rt = is_rt_task(next);
  if (rt != dctx->rt_busy)
  {
    dctx->rt_busy = rt;
    if (rt)
      __sync_fetch_and_add(&nr_rt_busy, 1);
    else
      __sync_fetch_and_sub(&nr_rt_busy, 1);
  }
  if (!rt)
    return 0;

  if (dsq_queued(SCX_DSQ_LOCAL_ON | cpu))
    scx_bpf_reenqueue_local_from_anywhere();
  kick_idle_for_waiting(cpu);
  return 0;
}

SCX_OPS_DEFINE(lunar_ops,
               .init = (void*)lunar_init,
               .init_task = (void*)lunar_init_task,
               .exit_task = (void*)lunar_exit_task,
               .select_cpu = (void*)lunar_select_cpu,
               .runnable = (void*)lunar_runnable,
               .quiescent = (void*)lunar_quiescent,
               .running = (void*)lunar_running,
               .enqueue = (void*)lunar_enqueue,
               .dispatch = (void*)lunar_dispatch,
               .stopping = (void*)lunar_stopping,
               .exit = (void*)lunar_exit,
               .name = "scx_lunar");

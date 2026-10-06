// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DISPATCHES_H
#define DISPATCHES_H

#include "defines.h"
#include "datatypes.h"
#include "helpers.h"

// ---------------------------------------------------------------------------
// Placement (enqueue side)
// ---------------------------------------------------------------------------

static __always_inline u64 cpu_load_ahead(u32 cpu, u64 tier)
{
  u64 load = 0;

  struct dispatch_ctx* dctx = get_dispatch_ctx(cpu);
  if (dctx && dctx->current_task_dsq_type <= tier)
    load++;
  // A cpu taken by an RT or deadline task is busy for every tier. Without this
  // it looks empty (stopping cleared current_task_dsq_type) and placement would
  // even prefer it when no cpu is idle.
  else if (cpu_taken_by_rt(cpu))
    load += RT_CPU_LOAD;

  // Tasks already moved to the local DSQ run next.
  load += dsq_queued(SCX_DSQ_LOCAL_ON | cpu);

  load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_LC, cpu));
  if (tier >= DSQ_TYPE_INTERACTIVE)
    load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_INTERACTIVE, cpu));
  if (tier >= DSQ_TYPE_NORMAL)
    load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_NORMAL, cpu));
  if (tier >= DSQ_TYPE_GREEDY)
    load += dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_GREEDY, cpu));

  return load;
}

static __always_inline s32 pick_enqueue_cpu(struct task_struct* p, struct task_ctx* tctx, u64 tier, u32 cpu, u64 now)
{
  u64 best_load = cpu_load_ahead(cpu, tier);
  if (best_load == 0)
  {
    // Claim the cpu if it is idle, so no select_cpu() of another wakeup picks
    // it and puts its task into the local DSQ ahead of this one.
    scx_bpf_test_and_clear_cpu_idle(cpu);
    return cpu;
  }

  if (p->nr_cpus_allowed == 1)
    return cpu;

  s32 idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
  if (idle >= 0)
  {
    if ((u32)idle != cpu)
      tctx->last_migrated_at = now;
    return idle;
  }

  // The rate limit for moving tasks doesn't apply when the own cpu is taken by
  // an RT task: the task would wait until that one is done.
  bool latency_tier = tier <= DSQ_TYPE_INTERACTIVE;
  if (!latency_tier && now - tctx->last_migrated_at < BALANCE_INTERVAL_NS && !cpu_taken_by_rt(cpu))
    return cpu;

  u32 key = 0;
  struct pick_scratch* sc = bpf_map_lookup_elem(&pick_scratch_map, &key);
  if (!sc)
    return cpu;

  sc->best_load = best_load;
  sc->best = cpu;
  sc->sampled = 0;

  u32 my_llc = cpu_llc_id(cpu);
  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 start = bpf_get_prandom_u32() % nr_cpu_ids;
  u32 budget = latency_tier ? nr_cpu_ids : BALANCE_SAMPLES;
  u32 i;

  bpf_for(i, 0, nr_cpu_ids)
  {
    u32 other = (start + i) % nr_cpu_ids;
    if (other == cpu || cpu_llc_id(other) != my_llc || !cpu_is_online(other))
      continue;
    if (!bpf_cpumask_test_cpu(other, p->cpus_ptr))
      continue;

    u64 load = cpu_load_ahead(other, tier);
    if (load < sc->best_load)
    {
      sc->best_load = load;
      sc->best = other;
      if (load == 0)
        break;
    }
    sc->sampled++;
    if (sc->sampled >= budget)
      break;
  }

  if ((u32)sc->best != cpu)
    tctx->last_migrated_at = now;
  return sc->best;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

static __always_inline u64 try_acquire_task_from_other_cpu(u64 dsqType, u32 cpu, bool sameLLC, u64 now)
{
  u32 my_llc = cpu_llc_id(cpu);
  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 start = bpf_get_prandom_u32() % nr_cpu_ids;
  u32 i;

  bpf_for(i, 0, nr_cpu_ids)
  {
    u32 other = (start + i) % nr_cpu_ids;
    if (other == cpu || !cpu_is_online(other))
      continue;
    if (sameLLC && cpu_llc_id(other) != my_llc)
      continue;
    if (!sameLLC && cpu_llc_id(other) == my_llc)
      continue;

    u64 dsq = get_cpu_dsq_from_type(dsqType, other);

    if (dsq_queued(dsq) && scx_bpf_dsq_move_to_local(dsq, 0))
    {
      struct dispatch_ctx* victim = get_dispatch_ctx(other);
      if (victim)
        stamp_tier_head_ts(victim, dsqType, now);
      return dsqType;
    }
  }
  return DSQ_TYPE_EMPTY;
}

// Take a task of @dsqType from a cpu of the LLC that is taken by an RT or
// deadline task right now: that cpu can't run it until the RT task is done.
// The scan only runs while the sched_switch hook has seen an RT task switched
// in somewhere (nr_rt_busy), so it costs nothing without RT tasks. (A task that
// turns itself RT while it runs is only noticed at its next context switch.)
static __always_inline bool try_acquire_from_rt_cpu(u64 dsqType, u32 cpu, u64 now)
{
  if (!nr_rt_busy)
    return false;

  u32 my_llc = cpu_llc_id(cpu);
  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 start = bpf_get_prandom_u32() % nr_cpu_ids;
  u32 i;

  bpf_for(i, 0, nr_cpu_ids)
  {
    u32 other = (start + i) % nr_cpu_ids;
    if (other == cpu || !cpu_is_online(other) || cpu_llc_id(other) != my_llc)
      continue;

    struct dispatch_ctx* victim = get_dispatch_ctx(other);
    if (!victim || !victim->rt_busy)
      continue;

    u64 dsq = get_cpu_dsq_from_type(dsqType, other);
    if (!dsq_queued(dsq) || !cpu_taken_by_rt(other))
      continue;

    if (scx_bpf_dsq_move_to_local(dsq, 0))
    {
      stamp_tier_head_ts(victim, dsqType, now);
      return true;
    }
  }
  return false;
}

// Wake an idle cpu for the first task waiting in the queues of @cpu that may
// run elsewhere.
static __always_inline void kick_idle_for_waiting(u32 cpu)
{
  struct task_struct* p;
  u32 tier;

  bpf_for(tier, DSQ_TYPE_LC, DSQ_TYPE_GREEDY + 1)
  {
    bpf_for_each(scx_dsq, p, get_cpu_dsq_from_type(tier, cpu), 0)
    {
      if (p->nr_cpus_allowed > 1)
      {
        s32 idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
        if (idle >= 0)
          scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
        return;
      }
      break;
    }
  }
}

static __always_inline s64 tier_overrun(struct dispatch_ctx* dctx, u64 dsqType, u32 cpu, u64 now, u64 budget)
{
  if (!dsq_queued(get_cpu_dsq_from_type(dsqType, cpu)))
    return 0;
  return (s64)(now - dctx->tier_head_ts[dsqType]) - (s64)budget;
}

static __always_inline u64 most_starved_tier(struct dispatch_ctx* dctx, u32 cpu, u64 now)
{
  if (now - dctx->last_override_ts < STARVE_OVERRIDE_COOLDOWN_NS)
    return DSQ_TYPE_EMPTY;

  u64 worst_type = DSQ_TYPE_EMPTY;
  s64 worst_overrun = 0;
  s64 overrun;

  overrun = tier_overrun(dctx, DSQ_TYPE_INTERACTIVE, cpu, now, STARVE_BUDGET_INTERACTIVE_NS);
  if (overrun > worst_overrun)
  {
    worst_overrun = overrun;
    worst_type = DSQ_TYPE_INTERACTIVE;
  }

  overrun = tier_overrun(dctx, DSQ_TYPE_NORMAL, cpu, now, STARVE_BUDGET_NORMAL_NS);
  if (overrun > worst_overrun)
  {
    worst_overrun = overrun;
    worst_type = DSQ_TYPE_NORMAL;
  }

  overrun = tier_overrun(dctx, DSQ_TYPE_GREEDY, cpu, now, STARVE_BUDGET_GREEDY_NS);
  if (overrun > worst_overrun)
  {
    worst_overrun = overrun;
    worst_type = DSQ_TYPE_GREEDY;
  }

  return worst_type;
}

static __always_inline bool take_from_local_tier(struct dispatch_ctx* dctx, u64 dsqType, u32 cpu, u64 now)
{
  u64 dsq = get_cpu_dsq_from_type(dsqType, cpu);
  if (!dsq_queued(dsq) || !scx_bpf_dsq_move_to_local(dsq, 0))
    return false;

  if (dctx)
    stamp_tier_head_ts(dctx, dsqType, now);
  return true;
}

static __always_inline bool take_from_other_tier(u64 dsqType, u32 cpu, u64 now, bool thisLLC)
{
  return try_acquire_task_from_other_cpu(dsqType, cpu, thisLLC, now) != DSQ_TYPE_EMPTY;
}

static __always_inline u64 dispatch_dsq_per_cpu(u32 cpu, u64 prev_tier)
{
  struct dispatch_ctx* dctx = get_dispatch_ctx(cpu);
  u64 now = bpf_ktime_get_ns();

  // Tasks of the tier this cpu serves next that wait on a cpu taken by an RT
  // task can't run there, so they are taken over first.
  if (try_acquire_from_rt_cpu(DSQ_TYPE_LC, cpu, now))
    return DSQ_TYPE_LC;
  if (take_from_local_tier(dctx, DSQ_TYPE_LC, cpu, now))
    return DSQ_TYPE_LC;

  // A starved tier keeps going first until it used its override budget.
  if (dctx)
  {
    if (dctx->override_left)
    {
      u64 tier = dctx->override_tier;
      if (tier >= DSQ_TYPE_INTERACTIVE && tier <= DSQ_TYPE_GREEDY && take_from_local_tier(dctx, tier, cpu, now))
        return tier;
      dctx->override_left = 0;
    }

    u64 starved = most_starved_tier(dctx, cpu, now);
    if (starved != DSQ_TYPE_EMPTY && take_from_local_tier(dctx, starved, cpu, now))
    {
      dctx->last_override_ts = now;
      dctx->override_tier = starved;
      dctx->override_left = STARVE_OVERRIDE_BUDGET_NS;
      return starved;
    }
  }

  // Tiers are strict across cpus too: a task of a better tier than anything
  // this cpu could run next (prev or its own queues) that waits on another cpu
  // of the LLC is taken over first. (Its own LC tasks were taken above.) A cpu
  // with nothing of its own skips this, it steals tier by tier below anyway.
  u64 local_best = prev_tier <= DSQ_TYPE_GREEDY ? prev_tier : DSQ_TYPE_EMPTY;
  if (local_best > DSQ_TYPE_INTERACTIVE && dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_INTERACTIVE, cpu)))
    local_best = DSQ_TYPE_INTERACTIVE;
  else if (local_best > DSQ_TYPE_NORMAL && dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_NORMAL, cpu)))
    local_best = DSQ_TYPE_NORMAL;
  else if (local_best > DSQ_TYPE_GREEDY && dsq_queued(get_cpu_dsq_from_type(DSQ_TYPE_GREEDY, cpu)))
    local_best = DSQ_TYPE_GREEDY;

  if (local_best != DSQ_TYPE_EMPTY)
  {
    if (local_best > DSQ_TYPE_LC && take_from_other_tier(DSQ_TYPE_LC, cpu, now, true))
      return DSQ_TYPE_LC;
    if (local_best > DSQ_TYPE_INTERACTIVE && take_from_other_tier(DSQ_TYPE_INTERACTIVE, cpu, now, true))
      return DSQ_TYPE_INTERACTIVE;
    if (local_best > DSQ_TYPE_NORMAL && take_from_other_tier(DSQ_TYPE_NORMAL, cpu, now, true))
      return DSQ_TYPE_NORMAL;
  }

  if (prev_tier < DSQ_TYPE_INTERACTIVE)
    return DSQ_TYPE_EMPTY;
  if (try_acquire_from_rt_cpu(DSQ_TYPE_INTERACTIVE, cpu, now))
    return DSQ_TYPE_INTERACTIVE;
  if (take_from_local_tier(dctx, DSQ_TYPE_INTERACTIVE, cpu, now))
    return DSQ_TYPE_INTERACTIVE;
  if (prev_tier < DSQ_TYPE_NORMAL)
    return DSQ_TYPE_EMPTY;
  if (try_acquire_from_rt_cpu(DSQ_TYPE_NORMAL, cpu, now))
    return DSQ_TYPE_NORMAL;
  if (take_from_local_tier(dctx, DSQ_TYPE_NORMAL, cpu, now))
    return DSQ_TYPE_NORMAL;
  if (prev_tier < DSQ_TYPE_GREEDY)
    return DSQ_TYPE_EMPTY;
  if (try_acquire_from_rt_cpu(DSQ_TYPE_GREEDY, cpu, now))
    return DSQ_TYPE_GREEDY;
  if (take_from_local_tier(dctx, DSQ_TYPE_GREEDY, cpu, now))
    return DSQ_TYPE_GREEDY;
  if (prev_tier <= DSQ_TYPE_GREEDY)
    return DSQ_TYPE_EMPTY;

  if (take_from_other_tier(DSQ_TYPE_LC, cpu, now, true))
    return DSQ_TYPE_LC;
  if (take_from_other_tier(DSQ_TYPE_INTERACTIVE, cpu, now, true))
    return DSQ_TYPE_INTERACTIVE;
  if (take_from_other_tier(DSQ_TYPE_NORMAL, cpu, now, true))
    return DSQ_TYPE_NORMAL;
  if (take_from_other_tier(DSQ_TYPE_GREEDY, cpu, now, true))
    return DSQ_TYPE_GREEDY;

  if (nr_llcs > 1)
  {
    if (take_from_other_tier(DSQ_TYPE_LC, cpu, now, false))
      return DSQ_TYPE_LC;
    if (take_from_other_tier(DSQ_TYPE_INTERACTIVE, cpu, now, false))
      return DSQ_TYPE_INTERACTIVE;
    if (take_from_other_tier(DSQ_TYPE_NORMAL, cpu, now, false))
      return DSQ_TYPE_NORMAL;
    if (take_from_other_tier(DSQ_TYPE_GREEDY, cpu, now, false))
      return DSQ_TYPE_GREEDY;
  }

  return DSQ_TYPE_EMPTY + 1;
}

#endif  // DISPATCHES_H

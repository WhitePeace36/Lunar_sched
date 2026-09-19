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

static __always_inline u64 try_acquire_task_from_other_cpu(u64 dsqType, u32 cpu, bool sameLLC)
{
  u32 my_llc = cpu_llc_id(cpu);
  u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();
  u32 start = bpf_get_prandom_u32() % nr_cpu_ids;
  u32 i;

  bpf_for(i, 0, nr_cpu_ids)
  {
    u32 other = (start + i) % nr_cpu_ids;
    if (other == cpu)
      continue;
    if (sameLLC && cpu_llc_id(other) != my_llc)
      continue;
    if (!sameLLC && cpu_llc_id(other) == my_llc)
      continue;

    u64 dsq = get_cpu_dsq_from_type(dsqType, other);

    if (scx_bpf_dsq_nr_queued(dsq) && scx_bpf_dsq_move_to_local(dsq, 0))
      return dsqType;
  }
  return DSQ_TYPE_EMPTY;
}

static __always_inline u64 most_starved_tier(
  struct dispatch_ctx* dctx,
  u32 cpu,
  u64 now)
{
  if (now - dctx->last_override_ts < STARVE_OVERRIDE_COOLDOWN_NS)
    return DSQ_TYPE_EMPTY;

  u64 worst_type = DSQ_TYPE_EMPTY;
  s64 worst_overrun = 0;  // only tiers that actually overran (> 0) qualify
  u64 dsq;
  s64 overrun;

  dsq = get_cpu_dsq_from_type(DSQ_TYPE_INTERACTIVE, cpu);
  if (scx_bpf_dsq_nr_queued(dsq))
  {
    overrun = (s64)(now - dctx->tier_head_ts[DSQ_TYPE_INTERACTIVE]) - (s64)STARVE_BUDGET_INTERACTIVE_NS;
    if (overrun > worst_overrun)
    {
      worst_overrun = overrun;
      worst_type = DSQ_TYPE_INTERACTIVE;
    }
  }

  dsq = get_cpu_dsq_from_type(DSQ_TYPE_NORMAL, cpu);
  if (scx_bpf_dsq_nr_queued(dsq))
  {
    overrun = (s64)(now - dctx->tier_head_ts[DSQ_TYPE_NORMAL]) - (s64)STARVE_BUDGET_NORMAL_NS;
    if (overrun > worst_overrun)
    {
      worst_overrun = overrun;
      worst_type = DSQ_TYPE_NORMAL;
    }
  }

  dsq = get_cpu_dsq_from_type(DSQ_TYPE_GREEDY, cpu);
  if (scx_bpf_dsq_nr_queued(dsq))
  {
    overrun = (s64)(now - dctx->tier_head_ts[DSQ_TYPE_GREEDY]) - (s64)STARVE_BUDGET_GREEDY_NS;
    if (overrun > worst_overrun)
    {
      worst_overrun = overrun;
      worst_type = DSQ_TYPE_GREEDY;
    }
  }

  return worst_type;
}

static __always_inline u64 dispatch_dsq_per_cpu(
  u32 cpu)
{
  u32 key = 0;
  struct dispatch_ctx* dctx = bpf_map_lookup_percpu_elem(&dispatch_state, &key, cpu);

  if (dctx)
  {
    u64 now = bpf_ktime_get_ns();
    u64 starved = most_starved_tier(dctx, cpu, now);
    if (starved != DSQ_TYPE_EMPTY)
    {
      u64 dsq = get_cpu_dsq_from_type(starved, cpu);
      if (scx_bpf_dsq_move_to_local(dsq, 0))
      {
        // Record that the task about to start running got here by jumping
        // the strict priority order, and start the cooldown so no other
        // tier can also override until it elapses.
        dctx->last_override_ts = now;
        dctx->pending_override = true;
        return starved;
      }
    }
  }

  if (scx_bpf_dsq_nr_queued(DSQ_CPU_QUEUE_BASE_LC + cpu) && scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_LC + cpu, 0))
  {
    return DSQ_TYPE_LC;
  }
  if (scx_bpf_dsq_nr_queued(DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu) && scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_INTERACTIVE + cpu, 0))
  {
    return DSQ_TYPE_INTERACTIVE;
  }
  if (scx_bpf_dsq_nr_queued(DSQ_CPU_QUEUE_BASE_NORMAL + cpu) && scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_NORMAL + cpu, 0))
  {
    return DSQ_TYPE_NORMAL;
  }
  if (scx_bpf_dsq_nr_queued(DSQ_CPU_QUEUE_BASE_GREEDY + cpu) && scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE_GREEDY + cpu, 0))
  {
    return DSQ_TYPE_GREEDY;
  }

  if (try_acquire_task_from_other_cpu(DSQ_TYPE_LC, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_LC;
  }
  if (try_acquire_task_from_other_cpu(DSQ_TYPE_INTERACTIVE, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_INTERACTIVE;
  }
  if (try_acquire_task_from_other_cpu(DSQ_TYPE_NORMAL, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_NORMAL;
  }
  if (try_acquire_task_from_other_cpu(DSQ_TYPE_GREEDY, cpu, true) != DSQ_TYPE_EMPTY)
  {
    return DSQ_TYPE_GREEDY;
  }

  if (nr_llcs > 1)
  {
    if (try_acquire_task_from_other_cpu(DSQ_TYPE_LC, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_LC;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_INTERACTIVE, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_INTERACTIVE;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_NORMAL, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_NORMAL;
    }

    if (try_acquire_task_from_other_cpu(DSQ_TYPE_GREEDY, cpu, false) != DSQ_TYPE_EMPTY)
    {
      return DSQ_TYPE_GREEDY;
    }
  }

  return DSQ_TYPE_EMPTY;
}

#endif  // DISPATCHES_H

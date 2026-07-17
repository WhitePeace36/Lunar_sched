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

static __always_inline bool try_acquire_task_from_other_cpu(u32 cpu, bool sameLLC)
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

    if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE + cpu, 0))
      return true;
  }
  return false;
}

static __always_inline void dispatch_dsq_per_cpu(u32 cpu)
{
  if (scx_bpf_dsq_move_to_local(DSQ_CPU_QUEUE_BASE + cpu, 0))
  {
    return;
  }
  if (try_acquire_task_from_other_cpu(cpu, true))
  {
    return;
  }

  if (nr_llcs > 1)
  {
    if (try_acquire_task_from_other_cpu(cpu, false))
    {
      return;
    }
  }
}

static __always_inline bool try_acquire_task_from_other_llc(u32 currentLLc)
{
  u32 llcs = nr_llcs;
  u32 start = bpf_get_prandom_u32() % llcs;
  u32 i;

  bpf_for(i, 0, llcs)
  {
    u32 other = (start + i) % llcs;
    if (other == currentLLc)
      continue;

    if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE + i, 0))
      return true;
  }
  return false;
}

static __always_inline void dispatch_dsq_per_llc(u32 llc)
{
  if (scx_bpf_dsq_move_to_local(DSQ_LLC_QUEUE_BASE + llc, 0))
    return;

  if (nr_llcs > 1)
  {
    if (try_acquire_task_from_other_llc(llc))
    {
      return;
    }
  }
}

#endif  // DISPATCHES_H

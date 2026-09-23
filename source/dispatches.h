// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DISPATCHES_H
#define DISPATCHES_H
#include "datatypes.h"
#include "defines.h"
#include "helpers.h"

// Each cpu queue is vtime ordered, so move_to_local() always takes the task
// with the lowest vtime. There is nothing to scan and no score to recompute
// at steal time: the queue already answers "which task".
static __always_inline bool steal_from_llc(
  u32 llc,
  u32 self_cpu,
  u32 start)
{
  if (llc >= MAX_LLCS)
  {
    llc = MAX_LLCS - 1;
  }
  if (start >= MAX_CPUS_PER_LLC)
  {
    start = MAX_CPUS_PER_LLC - 1;
  }

  u32 cpu_count = llc_nr_cpus[llc];
  if (cpu_count > MAX_CPUS_PER_LLC)
    cpu_count = MAX_CPUS_PER_LLC;

  u32 cpu_index = 0;
  bpf_for(cpu_index, 0, cpu_count)
  {
    // Rotate within the filled entries only: slots past llc_nr_cpus are
    // zero, and would send every cpu stealing from cpu0.
    u32 cpu = (start + cpu_index) % cpu_count;
    if (cpu >= MAX_CPUS_PER_LLC)
    {
      cpu = MAX_CPUS_PER_LLC - 1;
    }

    u32* cpus = &llc_cpus[llc][0];

    u32 victim = cpus[cpu];

    if (victim == self_cpu || victim >= MAX_CPUS)
      continue;

    // Do not stop on failure. move_to_local() only considers the head, and it
    // fails when that task cannot run here (affinity, migration disabled).
    // Giving up would let one pinned task block the whole steal.
    if (scx_bpf_dsq_move_to_local(cpu_dsq(victim), 0))
      return true;
  }

  return false;
}

static __always_inline bool steal_work(
  u32 self_cpu)
{
  u32 home_llc = cpu_llc(self_cpu);
  u32 start = bpf_get_prandom_u32() & (MAX_CPUS_PER_LLC - 1);

  // Same llc first: those tasks are still warm in the shared cache.
  if (steal_from_llc(home_llc, self_cpu, start))
    return true;

  if (nr_llcs > 1)
  {
    u32 nllc = nr_llcs;

    if (nllc >= MAX_LLCS)
      nllc = MAX_LLCS - 1;

    u32 llc = 0;
    bpf_for(llc, 0, nllc)
    {
      if (steal_from_llc((home_llc + llc) % nllc, self_cpu, start))
        return true;
    }
  }
  return false;
}

#endif  // DISPATCHES_H
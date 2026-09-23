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
static __always_inline bool steal_from_llc(u32 llc, u32 self, u32 start)
{
  llc &= (MAX_LLCS - 1);

  u32 n = llc_nr_cpus[llc];
  if (n > MAX_CPUS_PER_LLC)
    n = MAX_CPUS_PER_LLC;

  for (u32 i = 0; i < n && i < MAX_CPUS_PER_LLC; i++)
  {
    // Rotate within the filled entries only: slots past llc_nr_cpus are
    // zero, and would send every cpu stealing from cpu0.
    u32 victim = llc_cpus[llc][((start + i) % n) & (MAX_CPUS_PER_LLC - 1)];

    if (victim == self || victim >= MAX_CPUS)
      continue;

    // Do not stop on failure. move_to_local() only considers the head, and it
    // fails when that task cannot run here (affinity, migration disabled).
    // Giving up would let one pinned task block the whole steal.
    if (scx_bpf_dsq_move_to_local(cpu_dsq(victim), 0))
      return true;
  }

  return false;
}

static __always_inline bool steal_work(u32 self)
{
  u32 home = cpu_llc(self);
  u32 start = bpf_get_prandom_u32() & (MAX_CPUS_PER_LLC - 1);
  u32 nllc = nr_llcs;

  if (nllc > MAX_LLCS)
    nllc = MAX_LLCS;

  // Same llc first: those tasks are still warm in the shared cache.
  if (steal_from_llc(home, self, start))
    return true;

  // Only cross an llc boundary when our own has nothing left, since a remote
  // task refills from memory rather than from shared cache.
  for (u32 i = 1; i < nllc && i < MAX_LLCS; i++)
  {
    if (steal_from_llc((home + i) % nllc, self, start))
      return true;
  }

  return false;
}

#endif  // DISPATCHES_H
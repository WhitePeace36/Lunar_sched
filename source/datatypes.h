// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DATATYPES_H
#define DATATYPES_H
#include "defines.h"

const volatile u32 nr_llcs = 1;
const volatile u32 cpu_to_llc[MAX_CPUS] = {};
// Set by userspace from the topology. Offline cpus have queues too, but nobody
// serves them, so no task may ever be placed there.
const volatile u8 cpu_online[MAX_CPUS] = {};

struct task_ctx
{
  u64 current_dsq_type;
  // tier the task runs in for its next slice after a wake boost (DSQ_TYPE_EMPTY: none)
  u64 boost_dsq_type;
  // cpu time used in the boosted tier since the wakeup that boosted it
  u64 boost_used;
  u64 blocked_at;
  s64 duty;
  u64 run_acc;
  u64 sleep_acc;
  u64 started_at;
  u64 duty_samples;

  u64 granted_slice;
  u64 resume_slice;
  u64 last_migrated_at;

  u64 wait_interval;
  u64 wake_interval;
  u64 last_woken_at;
  u64 last_wake_at;
  u32 crit;
};

struct dispatch_ctx
{
  u64 current_task_dsq_type;
  u64 tier_head_ts[DSQ_TYPE_AMOUNT + 1];
  u64 last_override_ts;
  // starvation override in progress: tier and the cpu time it has left
  u64 override_tier;
  u64 override_left;
  // an RT or deadline task runs on this cpu (kept up to date by sched_switch)
  bool rt_busy;
  bool preempt_pending;
};

// Number of cpus an RT or deadline task runs on right now. Lets dispatch skip
// looking for such cpus when there are none.
u64 nr_rt_busy;

struct pick_scratch
{
  u64 best_load;
  u64 sampled;
  s32 best;
};

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct pick_scratch);

} pick_scratch_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dispatch_ctx);
} dispatch_state SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct task_ctx);
} task_ctx_store SEC(".maps");

#endif  // DATATYPES_H

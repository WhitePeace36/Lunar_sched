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
const volatile u32 nr_online_cpus = 1;
const volatile u32 cpu_to_llc[MAX_CPUS] = {};

const volatile u32 llc_cpus[MAX_LLCS][MAX_CPUS_PER_LLC] = {};
const volatile u32 llc_nr_cpus[MAX_LLCS] = {};

u64 vtime_now;

u64 slice_default;
u64 vtime_debt_max;
u64 vtime_credit_max;


struct task_ctx
{
  u64 vtime;         // accumulated cpu time, the queue key
  u64 started_at;    // when the current on cpu stretch began

  // latency criticality inputs
  u64 wait_interval;  // EWMA interval between being woken
  u64 wake_interval;  // EWMA interval between waking another task
  u64 last_woken_at;
  u64 last_wake_at;
  u32 crit;
};

struct dispatch_ctx
{
  u64 running_vtime;  // VTIME_NONE when no tracked task is on this cpu
  u64 run_started;
};

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
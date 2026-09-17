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

static __always_inline u64 get_dsq_task_slice(u64 dsqType)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return SLICE_LC;
    case DSQ_TYPE_INTERACTIVE:
      return SLICE_INTERACTIVE;
    case DSQ_TYPE_NORMAL:
      return SLICE_NORMAL;
    case DSQ_TYPE_BATCH:
      return SLICE_BATCH;
    case DSQ_TYPE_GREEDY:
      return SLICE_GREEDY;
  }
  return SLICE_GREEDY;
}

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
    case DSQ_TYPE_BATCH:
      return DSQ_CPU_QUEUE_BASE_BATCH + cpu;
    case DSQ_TYPE_GREEDY:
      return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
  }
  return DSQ_CPU_QUEUE_BASE_GREEDY + cpu;
}

static __always_inline u64 get_llc_dsq_from_type(u64 dsqType, u32 llc)
{
  switch (dsqType)
  {
    case DSQ_TYPE_LC:
      return DSQ_LLC_QUEUE_BASE_LC + llc;
    case DSQ_TYPE_INTERACTIVE:
      return DSQ_LLC_QUEUE_BASE_INTERACTIVE + llc;
    case DSQ_TYPE_NORMAL:
      return DSQ_LLC_QUEUE_BASE_NORMAL + llc;
    case DSQ_TYPE_BATCH:
      return DSQ_LLC_QUEUE_BASE_BATCH + llc;
    case DSQ_TYPE_GREEDY:
      return DSQ_LLC_QUEUE_BASE_GREEDY + llc;
  }
  return DSQ_LLC_QUEUE_BASE_GREEDY + llc;
}

static __always_inline bool is_kthread(const struct task_struct* p)
{
  return p->flags & PF_KTHREAD;
}

static __always_inline bool is_high_prio_kthread_task(struct task_struct* p)
{
  return p->prio == MAX_RT_PRIO && is_kthread(p);
}

static __always_inline struct task_ctx* get_task_ctx(struct task_struct* task)
{
  return bpf_task_storage_get(&task_ctx_store, task, NULL, 0);
}

static __always_inline u32 cpu_llc_id(u32 cpu)
{
  cpu &= (MAX_CPUS - 1);
  return cpu_to_llc[cpu];
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

  if (tctx->run_acc > DUTY_WINDOW_NS)
    tctx->run_acc = DUTY_WINDOW_NS;

  tctx->sleep_acc += slept;

  if (tctx->run_acc + tctx->sleep_acc > 2 * DUTY_WINDOW_NS)
  {
    tctx->run_acc >>= 1;
    tctx->sleep_acc >>= 1;
  }
}

static __always_inline u64 getTickInterval_ns(void)
{
  return 1000000000ULL / CONFIG_HZ;
}

static __always_inline u64* get_or_create_local_counter(struct group_key* key)
{
  u64* count = bpf_map_lookup_elem(&group_map, key);
  if (count)
    return count;

  u64 countNew = 0;
  bpf_map_update_elem(&group_map, key, &countNew, BPF_NOEXIST);
  return bpf_map_lookup_elem(&group_map, key);
}

static __always_inline void group_join(struct task_ctx *tctx, u32 tgid)
{
  if (tctx->current_dsq_type != DSQ_TYPE_BATCH && tctx->current_dsq_type != DSQ_TYPE_GREEDY)
  {
    tctx->counted_in_group = false;
    tctx->counted_cpu = 0;
    tctx->counted_dsqType = DSQ_TYPE_EMPTY;
    return;
  }

  u32 local_cpu = bpf_get_smp_processor_id();

  if (tctx->counted_in_group && tctx->counted_cpu == local_cpu && tctx->counted_dsqType == tctx->current_dsq_type)
  {
    return;
  }

  barrier_var(tgid);

  if (tctx->counted_in_group)
  {
    struct group_key key_old;
    __builtin_memset(&key_old, 0, sizeof(key_old));
    key_old.dsqType = tctx->counted_dsqType;
    key_old.tgid = tgid;

    u64 *other_count = bpf_map_lookup_percpu_elem(&group_map, &key_old, tctx->counted_cpu);
    if (other_count && *other_count > 0)
    {
      __sync_fetch_and_sub(other_count, 1);
    }
  }

  struct group_key key_new;
  __builtin_memset(&key_new, 0, sizeof(key_new));
  key_new.dsqType = tctx->current_dsq_type;
  key_new.tgid = tgid;

  u64 *local_count = get_or_create_local_counter(&key_new);
  if (local_count)
  {
    __sync_fetch_and_add(local_count, 1);
  }
  else
  {
    tctx->counted_dsqType = DSQ_TYPE_EMPTY;
    tctx->counted_in_group = false;
    tctx->counted_cpu = 0;
    return;
  }

  tctx->counted_dsqType = tctx->current_dsq_type;
  tctx->counted_in_group = true;
  tctx->counted_cpu = local_cpu;
}

static __always_inline void group_leave(struct task_ctx* tctx, u32 tgid)
{
  if (tctx->current_dsq_type != DSQ_TYPE_GREEDY && tctx->current_dsq_type != DSQ_TYPE_BATCH && !tctx->counted_in_group)
  {
    return;
  }

  barrier_var(tgid);

  struct group_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.dsqType = tctx->counted_dsqType;
  key.tgid = tgid;

  u64* count = bpf_map_lookup_elem(&group_map, &key);
  if (!count || *count == 0)
  {
    tctx->counted_in_group = false;
    tctx->counted_cpu = 0;
    tctx->counted_dsqType = DSQ_TYPE_EMPTY;
    return;
  }

  __sync_fetch_and_sub(count, 1);
}

static __always_inline u64 group_slice(u64 dsqType, u32 tgid)
{
  if (dsqType != DSQ_TYPE_GREEDY && dsqType != DSQ_TYPE_BATCH)
  {
    return get_dsq_task_slice(dsqType);
  }

  barrier_var(tgid);

  struct group_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.dsqType = dsqType;
  key.tgid = tgid;

  u64 *count = bpf_map_lookup_elem(&group_map, &key);
  const u64 defaultSlice = get_dsq_task_slice(dsqType);
  u64 slice = defaultSlice;
  if (count && *count > 1)
  {
    u64 n = *count;
    if (n > GROUP_CAP)
      n = GROUP_CAP;
    slice = defaultSlice / n;
    if (slice < MIN_SLICE)
      slice = MIN_SLICE;
  }
  return slice;
}
#endif  // HELPERS_H

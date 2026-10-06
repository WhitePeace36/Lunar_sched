
# Lunar

## Introduction

Scx_lunar is a multipurpose scheduler which was originally invented with the goal to make frametimes in games as smooth as possible

This scheduler uses only FIFO queues.

## Dependencies

```
cmake clang pkgconf libbpf bpf
```

kernel compiled with flag `CONFIG_DEBUG_INFO_BTF=y`

Linux 6.18 or newer. 6.19 or newer is recommended, 6.18 loses a part of the realtime
handling (see below).

for the kernel option you can just check if `/sys/kernel/btf/vmlinux` is present.

But this kernel option should be enabled by default, but not bad to check never the less.

## Important

To have the scheduler work at its best, DONT modify the nice levels of kernel threads.

And maybe also don't use ananicy-cpp or ananicy.

you can disable them with

`sudo systemctl disable --now ananicy-cpp.service`

or

`sudo systemctl disable --now ananicy.service`


## Building it

```
./build.sh
```

## Installing

```
sudo ./install.sh
```

## Uninstalling

```
sudo ./uninstall.sh
```

## Explanation

The scheduler works with accounting of duty and crit score.

Duty goes from 0 to 1023.

The higher the duty number the more the task hogs cpu power.
The lower the more it is sleeping or dependent on io.

Run time and sleep time are accumulated and both halved together once their sum
exceeds 200ms, so the duty roughly reflects the last 100-200ms.

It is calculated like this.

duty = run_time * 1024 / (run_time + sleep_time + 1)

The Tier are calculated as Percent of the 1024 max duty value.

crit score goes from 0 to 32.

It is based on the waker and wakee frequency of a task.

it is calculated from
log2(1s / wakee interval) + log2(1s / waker interval)

It has 3 tiers. Which are:

1. LC with duty <= 5% and crit score of >= 5
2. INTERACTIVE with duty <= 10% and crit score of >= 3
3. NORMAL with duty <= 80% and crit score of >=1
4. Greedy with everything else

There is no hysteresis on the crit score. There is a hysteresis of 1% on the duty.

All new tasks start in normal.
There is also a min. sample rate of the duty value to be eligible for promotion into higher tiers.

Every task has a slice time of 1ms.

Nice values and scheduling policies are intentionally ignored. Every task is
treated equally and only its behavior (duty and crit score) decides its tier.

## Preemption

A waking LC task preempts a running task of a lower tier. The preempted task goes
back to the head of its queue with the rest of its slice.

Kernel threads start in INTERACTIVE with a duty of 8% and complete duty samples.
Their crit score is ignored, because they wake rarely even when they are important.
As long as their duty stays under 10% they are at least INTERACTIVE, otherwise
they are classified like every other task.

## Wake boost

When a task wakes a task of a worse tier, the woken task runs in the tier of the waker
(if that is LC, it also preempts like any LC wakeup) until it goes to sleep again, for at
most 4ms of cpu time (`WAKE_BOOST_BUDGET_NS`). After that it is back in its own tier.
That way work a task waits for (a helper thread, wineserver, a kworker that submits its
gpu job, ...) runs right away instead of behind everything in between. A task that keeps
running gets no advantage beyond the budget: it is only boosted again after it has
slept and is woken again.

The budget is several slices on purpose. With a boost of only one slice, a woken task
that needs a bit more than that falls back to its own tier with its work unfinished.
Behind a busy better tier it then only runs on the starvation override, its next
requests pile up while it waits, so it never sleeps and is never woken (and boosted)
again.

Only wakeups from normal task context count. A wakeup from an interrupt runs on top of
whatever task was interrupted, and that task is not the waker. Wakeups by kernel threads
don't boost either: kworkers and ksoftirqd wake ordinary processes for every finished
disk read and network packet. This can be changed with `WAKE_BOOST_FROM_KTHREADS` in
`source/defines.h`.

## Placement and balancing

Each core has its own queue per tier.

When a task wakes up and an idle core is found, it runs there directly.
Otherwise the task goes to the queue of the core with the least work ahead of it:

- an idle core is always preferred
- LC and INTERACTIVE tasks check all cores of the same llc, so they don't wait
  behind a task of their own tier while another core runs lower tier work
- NORMAL and GREEDY tasks compare their core with 2 random cores of the same llc
  and move at most once every 10ms, which evens out long queues between busy cores

Offline cores (for example the second threads with SMT off) are never used.

### Realtime and deadline tasks

Tasks with SCHED_FIFO, SCHED_RR or SCHED_DEADLINE (kwin, irq threads, ...) run above
all tiers, outside of lunar. A core that runs such a task counts as busy for every
tier, with a load of 2 tasks (`RT_CPU_LOAD`): a task of our tiers gives the core back
after at most one slice, a realtime task only when it is done. The 10ms limit for
moving tasks doesn't apply to tasks whose own core is taken by a realtime task.

Every switch to a realtime or deadline task is seen by a `sched_switch` tracepoint.
The tasks already picked to run next on that core then go back through placement,
which moves them to a core that is free for them (kernel 6.19+), and an idle core is
woken for the first task waiting in its queues. A preempted task that would resume on
a core taken by a realtime task goes through placement too instead of going back to
the head of its old queue.

Tasks that still wait in the queues of such a core are taken over by the other cores:
before a core runs a tier of its own, it first takes a task of that tier waiting on a
core of its llc that is running a realtime task. When no core runs a realtime task,
this check costs nothing.

Per-cpu kernel threads with a realtime policy (migration/N, which runs for every
affinity change and task migration) don't count as realtime tasks taking the core:
they only run for microseconds.

## Dispatch

Each core first runs its own LC tasks, then a starved tier if there is one. Then it
looks at the best tier it could run itself (its running task or its own queues). If a
task of a better tier waits on another core of the same llc, it takes that one over, so
the tiers are strict across cores too. Otherwise it runs its own INTERACTIVE, NORMAL
and GREEDY tasks. After that it steals from another core of the same llc and then from
cores of other llcs.
From which core the core starts stealing is randomized for better load distribution.

## Starvation

If the head of a tier has not been served for longer than its budget, the tier gets
one slice (1ms, `STARVE_OVERRIDE_BUDGET_NS`) of cpu time ahead of the higher tiers, at
most once every 10ms per core: its tasks run one after another until that time is used
up or the tier is empty. One task per override isn't enough, tasks that sleep again
right away would use it up in microseconds, and a cpu bound task of the tier behind
them would never get to run. The values are in `source/defines.h`.

## CPU hotplug

When cpus go online or offline (for example when toggling SMT) the kernel stops
the scheduler, and lunar restarts itself with the new topology.

## Testing

There where 2 design goals for this scheduler.

1. That music keeps playing normally when executing the cachyos benchmarker https://github.com/CachyOS/cachyos-benchmarker
2. To keep frametimes as smooth as possible with as little frametime spikes as possible. 

As far as i have tested. Both modes do accomplish these tasks very well.

The only problem is i couldn't test the functionality with different llcs as i don't have such an cpu by hand.
The next thing is, that i mostly developed this scheduler with SMT disabled. As i found that SMT off works the best for this ryzen 5800x3d. But you can test both. Your mileage may vary.

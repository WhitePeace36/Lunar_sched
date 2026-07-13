
# Lunar

## Introduction

Lunar is a multipurpose cpu scheduler which was created with the goal to make frametimes in games and inputs as consistent as possible.
But then it grew a little and changed to a desktop usage focused scheduler.
Which exactly fulfills this requirements. 


## Dependencies

```
cmake clang pkgconf libbpf bpf
```

kernel compiled with flag `CONFIG_DEBUG_INFO_BTF=y`

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

The scheduler does only use FIFO queues and works without preemption. 

It has 6 tiers. Which are: 

1. SOFT ( KTHREADs with PRIO 100) 
2. LC which have a positive vlag and <= average runtime of 200us
3. INTERACTIVE which have a positive vlag and with <= average runtime of 500us
4. NORMAL which have a positive vlag and with <= average runtime of 2ms
5. Batch everything else but which does not exceed the avg runtime per cpu by more than a factor of 4
6. GREEDY everthing which has a 4x or more avg cpu time per run than the avg cpu time of a task on the cpu core.

Tasks and its children will also be thrown into greedy when they are spamming new tasks.

Each tier except SOFT queue has a max continous time gate. Where when there are too many tasks of for example LC and there is a task waiting in INTERACTIVE than after a defined time, one task  of a lower prio task is forced.

Each tier also has different slice times per task. 
Which are:

1. SOFT -> 200us
2. LC -> 200us
3. INTERACTIVE -> 500us
4. NORMAL -> 2000us
5. BATCH -> 2000us
6. GREEDY -> 2000us

One of the big things of this scheduler is that in LC, Interactive and NORMAL it gives it exactly the slice which the average runtime is. So this makes the execution very smooth.

## MODES

This scheduler also has 2 modes.

`--mode dsqs_per_llc` 

Where the above explained are available for each L3 cache domain. So more than one core pull from the same DSQs.

and:

`--mode dsqs_per_cpu`

DEFAULT MODE!
This mode is used automatically when starting without start parameters.

Where the above explained dsqs are available for each cpu core. So each core has its own queues.

When running a cpu which has a lot of cores incl. hyperthreading core on one L3 cache domain, then this mode is preferred.

## Dispatch

For mode `dsqs_per_cpu`
Each core first tries to run its own queued tasks, then from another core from the same llc and then from core of other llcs.
From which core the core startes stealing is randomized for better load distribution.

for mode `dsqs_per_llc`
Each core tries to first to run from the dsqs of the llc from the core. Then it tries to steal from other llcs.

## Gating mechanism

Each dsq has a continous execution gate. Each gate is only allowed to have 2ms of execution time until at least one task of the next lower
priority has to be run.

## Testing

There where 2 design goals for this scheduler.

1. That music keeps playing normally when executing the cachyos benchmarker https://github.com/CachyOS/cachyos-benchmarker
2. To keep frametimes as smooth as possible with as little frametime spikes as possible. 

As far as i have tested. Both modes do accomplish these tasks very well.

The only problem is i couldn't test the functionality with different llcs as i don't have such an cpu by hand.
The next thing is, that i mostly developed this scheduler with SMT disabled. As i found that SMT off works the best for this ryzen 5800x3d. But you can test both. Your mileage may vary.

// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DEFINES_H
#define DEFINES_H

#define SCHED_MODE_DSQ_PER_LLC 0
#define SCHED_MODE_DSQ_PER_CPU 1

#define NS_PER_US 1000ULL
#define NS_PER_MS 1000ULL * NS_PER_US

#define SLICE (500 * NS_PER_US)

#define VLAG_MIN -300000LL
#define VLAG_MAX 300000LL
#define SLEEP_CREDIT_DIVISOR 1LL
#define MAX_CREDITABLE_SLEEP 20000000000LL

#define DEFAULT_DSQ_LOCAL_ON 0xC000000000000000ULL

#define DSQ_CPU_QUEUE_BASE 4

#define DSQ_LLC_QUEUE_BASE 517

#define QUEUE_START DSQ_TYPE_BATCH

#define MAX_CPUS 512

#endif  // DEFINES_H
d
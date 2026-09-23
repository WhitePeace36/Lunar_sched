// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef DEFINES_H
#define DEFINES_H

#define NS_PER_US 1000ULL
#define NS_PER_MS (1000ULL * NS_PER_US)

#define SLICE_BASE (1000 * NS_PER_US)
#define VTIME_DEBT_MAX (50 * NS_PER_MS)
#define VTIME_CREDIT_MAX (50 * NS_PER_MS)
#define VTIME_NONE (~0ULL)

#define MIN_RUN_BEFORE_PREEMPT (150 * NS_PER_US)
#define PREEMPT_MARGIN (0 * NS_PER_US)

#define CRIT_INTERVAL_REF (1000ULL * NS_PER_MS)
#define CRIT_INTERVAL_MIN (10ULL * NS_PER_US)
#define CRIT_MAX 32

#define MAX_CPUS (MAX_CPUS_PER_LLC * MAX_LLCS)
#define MAX_LLCS 16             // power of two: used as a verifier bound
#define MAX_CPUS_PER_LLC 256   // power of two: used as a verifier bound

#define DSQ_CPU_BASE 1024

#endif  // DEFINES_H
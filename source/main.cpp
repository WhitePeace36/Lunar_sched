#include <iostream>
#include <csignal>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <atomic>
#include <thread>

enum scheduler_mode : std::uint32_t
{
  SCHED_MODE_DSQS_PER_LLC = 0,
  SCHED_MODE_DSQS_PER_CPU = 1,
};

enum ParameterStatus : std::uint32_t
{
  Ok,
  Error,
  Help,
};

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint8_t u8;
typedef int8_t s8;

#include "mode_parsing.h"
#include "lunar_topology.h"

using namespace std;

#include <include/scx/common.h>
#include <include/scx/enums.h>
#include <include/scx/user_exit_info_common.h>
#include <include/scx/enums.autogen.h>
#include <source/lunar.skel.h>

std::atomic<bool> stop{};

static void sig_handler(int)
{
  stop = true;
}

int main(int argc, const char** argv)
{
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  int err = 0;

  lunar_bpf* skel{nullptr};
  scheduler_mode mode{SCHED_MODE_DSQS_PER_CPU};

  if (parseParameters(argc, argv, mode) != Ok)
  {
    return 0;
  }

  skel = lunar_bpf__open();
  if (!skel)
  {
    std::cerr << "Failed to create BPF skeleton." << std::endl;
    return 1;
  }
  SCX_ENUM_INIT(skel);
  skel->rodata->schedulerMode = mode;

  if (!setup_lunar_topology(skel))
  {
    std::cout << "Failed to load llc information: " << err << std::endl;
    lunar_bpf__destroy(skel);
    return 1;
  }

  err = lunar_bpf__load(skel);
  if (err)
  {
    std::cerr << "Failed to load scheduler: " << err << std::endl;
    lunar_bpf__destroy(skel);
    return 1;
  }

  std::cerr << "Successfully opened and loaded the lunar scheduler." << std::endl;

  const char* mode_name = (mode == SCHED_MODE_DSQS_PER_LLC) ? "dsqs_per_LLC" : "dsqs_per_cpu";
  std::cout << "Scheduler mode: " << mode_name << std::endl;

  std::cout << "Attaching sched_ext scheduler..." << std::endl;

  err = lunar_bpf__attach(skel);
  if (err)
  {
    std::cerr << "Failed to attach BPF programs: " << err << std::endl;
    lunar_bpf__destroy(skel);
    return 1;
  }

  std::cout << "lunar scheduler is successfully running!" << std::endl;

  while (!stop)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  std::cout << "Shutting down and restoring default kernel scheduler..." << std::endl;
  lunar_bpf__destroy(skel);

  return 0;
}
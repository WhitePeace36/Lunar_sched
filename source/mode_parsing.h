#pragma once

static void print_usage(const char* prog)
{
  std::cerr << "Usage: " << prog << " [--mode <dsqs_per_llc|dsqs_per_cpu>]\n"
            << "  default: dsqs_per_cpu\n";
}

bool parse_mode(const std::string& arg, scheduler_mode& mode)
{
  if (arg == "dsqs_per_llc")
  {
    mode = SCHED_MODE_DSQS_PER_LLC;
    return true;
  }
  if (arg == "dsqs_per_cpu")
  {
    mode = SCHED_MODE_DSQS_PER_CPU;
    return true;
  }

    return false;
}

ParameterStatus parseParameters(int argc, const char** argv, scheduler_mode& mode)
{
  for (int i = 1; i < argc; ++i)
  {
    std::string a = argv[i];
    if (a == "--mode" || a == "-m")
    {
      if (i + 1 >= argc)
      {
        std::cerr << "Error: " << a << " requires an argument.\n";
        print_usage(argv[0]);
        return Error;
      }
      if (!parse_mode(argv[++i], mode))
      {
        std::cerr << "Error: unknown mode '" << argv[i] << "'.\n";
        print_usage(argv[0]);
        return Error;
      }
    }
    else if (a == "--help" || a == "-h")
    {
      print_usage(argv[0]);
      return Help;
    }
    else
    {
      std::cerr << "Error: unknown argument '" << a << "'.\n";
      print_usage(argv[0]);
      return Error;
    }
  }
  return Ok;
}
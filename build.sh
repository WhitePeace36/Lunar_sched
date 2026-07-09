#!/bin/bash

bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./include/vmlinux.h
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

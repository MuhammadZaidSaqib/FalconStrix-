#ifndef RESOURCE_MONITOR_H
#define RESOURCE_MONITOR_H

#include <string>

// CPU & Memory monitoring structures
struct CpuUsage {
    double usage_percent;
    unsigned long long user;
    unsigned long long nice;
    unsigned long long system;
    unsigned long long idle;
};

struct MemoryInfo {
    unsigned long total_kb;
    unsigned long free_kb;
    unsigned long available_kb;
    unsigned long buffers_kb;
    unsigned long cached_kb;
    double usage_percent;
};

// Resource monitoring functions
CpuUsage get_cpu_usage();
MemoryInfo get_memory_info();

// Per-process resource info from /proc/[pid]/stat
struct ProcessResourceInfo {
    int pid;
    std::string name;
    char state;
    unsigned long utime;     // User mode CPU time
    unsigned long stime;     // Kernel mode CPU time
    long num_threads;
    unsigned long vsize;     // Virtual memory size in bytes
    long rss;                // Resident Set Size (pages)
};

ProcessResourceInfo get_process_resource_info(int pid);

// Thread entry point for resource monitoring
void* start_resource_monitor(void* arg);

#endif

#include "resource_monitor.h"
#include "behavior_detector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <cstring>
#include <signal.h>

// ─── CPU Usage from /proc/stat ───────────────────────────────────────────────
// Reads aggregate CPU times, computes delta between two samples to get %.
static unsigned long long prev_idle = 0, prev_total = 0;

CpuUsage get_cpu_usage() {
    CpuUsage cpu = {0, 0, 0, 0, 0};
    std::ifstream stat_file("/proc/stat");
    if (!stat_file.is_open()) return cpu;

    std::string line;
    std::getline(stat_file, line); // First line: cpu  user nice system idle ...

    std::istringstream iss(line);
    std::string cpu_label;
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;

    iss >> cpu_label >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

    cpu.user = user;
    cpu.nice = nice;
    cpu.system = system;
    cpu.idle = idle;

    unsigned long long total_idle = idle + iowait;
    unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal;

    // Delta calculation for percentage
    unsigned long long diff_idle = total_idle - prev_idle;
    unsigned long long diff_total = total - prev_total;

    if (diff_total > 0) {
        cpu.usage_percent = (double)(diff_total - diff_idle) / (double)diff_total * 100.0;
    } else {
        cpu.usage_percent = 0.0;
    }

    prev_idle = total_idle;
    prev_total = total;

    return cpu;
}

// ─── Memory Info from /proc/meminfo ──────────────────────────────────────────
MemoryInfo get_memory_info() {
    MemoryInfo mem = {0, 0, 0, 0, 0, 0.0};
    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo.is_open()) return mem;

    std::string line;
    while (std::getline(meminfo, line)) {
        std::istringstream iss(line);
        std::string key;
        unsigned long value;
        iss >> key >> value;

        if (key == "MemTotal:")     mem.total_kb = value;
        else if (key == "MemFree:")      mem.free_kb = value;
        else if (key == "MemAvailable:") mem.available_kb = value;
        else if (key == "Buffers:")       mem.buffers_kb = value;
        else if (key == "Cached:")        mem.cached_kb = value;
    }

    if (mem.total_kb > 0) {
        unsigned long used = mem.total_kb - mem.available_kb;
        mem.usage_percent = (double)used / (double)mem.total_kb * 100.0;
    }
    return mem;
}

// ─── Per-Process Resource Info from /proc/[pid]/stat ─────────────────────────
ProcessResourceInfo get_process_resource_info(int pid) {
    ProcessResourceInfo info;
    info.pid = pid;
    info.name = "unknown";
    info.state = '?';
    info.utime = 0;
    info.stime = 0;
    info.num_threads = 0;
    info.vsize = 0;
    info.rss = 0;

    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream stat_file(path);
    if (!stat_file.is_open()) return info;

    std::string line;
    std::getline(stat_file, line);

    // /proc/[pid]/stat fields:
    // pid (comm) state ppid pgrp session tty_nr tpgid flags
    // minflt cminflt majflt cmajflt utime stime cutime cstime
    // priority nice num_threads itrealvalue starttime vsize rss ...
    
    // Find comm field (enclosed in parentheses)
    size_t open_paren = line.find('(');
    size_t close_paren = line.rfind(')');
    if (open_paren != std::string::npos && close_paren != std::string::npos) {
        info.name = line.substr(open_paren + 1, close_paren - open_paren - 1);
        
        // Parse remaining fields after the closing parenthesis
        std::string rest = line.substr(close_paren + 2); // skip ") "
        std::istringstream iss(rest);
        
        // Fields after (comm): state ppid pgrp session tty tpgid flags
        //   minflt cminflt majflt cmajflt utime stime cutime cstime
        //   priority nice num_threads ...
        std::string state_str;
        long ppid, pgrp, session, tty, tpgid;
        unsigned long flags, minflt, cminflt, majflt, cmajflt;
        unsigned long utime, stime;
        long cutime, cstime, priority, nice_val, num_threads;
        long itrealvalue;
        unsigned long long starttime;
        unsigned long vsize;
        long rss;
        
        iss >> state_str >> ppid >> pgrp >> session >> tty >> tpgid >> flags
            >> minflt >> cminflt >> majflt >> cmajflt
            >> utime >> stime >> cutime >> cstime
            >> priority >> nice_val >> num_threads
            >> itrealvalue >> starttime >> vsize >> rss;

        info.state = state_str[0];
        info.utime = utime;
        info.stime = stime;
        info.num_threads = num_threads;
        info.vsize = vsize;
        info.rss = rss;
    }

    return info;
}

// ─── Resource Monitor Thread ─────────────────────────────────────────────────
// Runs continuously, logging CPU/Memory at intervals.
// Sends alert to backend if thresholds are exceeded.
void* start_resource_monitor(void* arg) {
    volatile sig_atomic_t* running_flag = static_cast<volatile sig_atomic_t*>(arg);
    std::cout << "[+] Resource Monitor thread started." << std::endl;

    // First sample to seed delta calculation
    get_cpu_usage();
    sleep(1);

    while (running_flag == nullptr || *running_flag) {
        CpuUsage cpu = get_cpu_usage();
        MemoryInfo mem = get_memory_info();

        std::cout << "[RES] CPU: " << cpu.usage_percent << "% | "
                  << "MEM: " << mem.usage_percent << "% ("
                  << (mem.total_kb - mem.available_kb) / 1024 << "MB / "
                  << mem.total_kb / 1024 << "MB)" << std::endl;

        // Alert on high CPU usage
        if (cpu.usage_percent > 90.0) {
            send_event_to_backend("HIGH_CPU",
                "CPU usage exceeded 90% threshold",
                getpid(), "resource_monitor", 3);
        }

        // Alert on high memory usage
        if (mem.usage_percent > 90.0) {
            send_event_to_backend("HIGH_MEMORY",
                "Memory usage exceeded 90% threshold",
                getpid(), "resource_monitor", 3);
        }

        sleep(5); // Sample every 5 seconds
    }
    return NULL;
}

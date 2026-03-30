#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <string>
#include <vector>

// ─── Structures ──────────────────────────────────────────────────────────────

// 7️⃣ Parsed data from /proc/[pid]/status
struct ProcessStatus {
    int pid;
    std::string name;
    std::string state;   // e.g. "S (sleeping)", "R (running)"
    int ppid;            // Parent PID
    int threads;         // Number of threads
    unsigned long vm_size_kb;  // Virtual memory size
    unsigned long vm_rss_kb;   // Resident set size
    int uid;             // User ID
};

// ─── Function Declarations ───────────────────────────────────────────────────

// Thread entry point
void* start_process_monitor(void* arg);

// Basic process enumeration
int get_process_count();
std::vector<int> get_all_pids();
std::vector<int> get_all_pids_safe();  // 3️⃣ Mutex-protected version

// 7️⃣ /proc filesystem readers
std::string get_process_name(int pid);       // /proc/[pid]/comm
std::string get_process_cmdline(int pid);    // /proc/[pid]/cmdline
ProcessStatus get_process_status(int pid);   // /proc/[pid]/status

// 3️⃣ Shared mutex (extern so behavior_detector can use it)
#include <pthread.h>
extern pthread_mutex_t proc_mut;

#endif

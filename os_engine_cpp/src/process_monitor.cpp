#include "process_monitor.h"
#include <iostream>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <cstring>
#include <algorithm>

// 3️⃣ Synchronization — Global mutex shared across threads
pthread_mutex_t proc_mut = PTHREAD_MUTEX_INITIALIZER;

std::vector<int> get_all_pids() {
    std::vector<int> pids;
    DIR* dir = opendir("/proc");
    if (!dir) return pids;

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            std::string name = entry->d_name;
            if (isdigit(name[0])) {
                pids.push_back(std::stoi(name));
            }
        }
    }
    closedir(dir);
    return pids;
}

std::string get_process_name(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream comm_file(path);
    std::string name = "unknown";
    if (comm_file.is_open()) {
        std::getline(comm_file, name);
    }
    return name;
}

// ─── 7️⃣ /proc/[pid]/cmdline — Full command line of a process ────────────────
std::string get_process_cmdline(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmdline_file(path, std::ios::binary);
    std::string cmdline = "";
    if (cmdline_file.is_open()) {
        std::getline(cmdline_file, cmdline, '\0');
        // cmdline fields are null-separated; replace nulls with spaces
        std::string full;
        char c;
        cmdline_file.seekg(0);
        while (cmdline_file.get(c)) {
            full += (c == '\0') ? ' ' : c;
        }
        if (!full.empty()) cmdline = full;
    }
    return cmdline.empty() ? "[kernel/zombie]" : cmdline;
}

// ─── 7️⃣ /proc/[pid]/status — Detailed process status info ──────────────────
ProcessStatus get_process_status(int pid) {
    ProcessStatus status;
    status.pid = pid;
    status.name = "unknown";
    status.state = "unknown";
    status.ppid = 0;
    status.threads = 0;
    status.vm_size_kb = 0;
    status.vm_rss_kb = 0;
    status.uid = 0;

    std::string path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream status_file(path);
    if (!status_file.is_open()) return status;

    std::string line;
    while (std::getline(status_file, line)) {
        std::istringstream iss(line);
        std::string key;
        iss >> key;

        if (key == "Name:") {
            iss >> status.name;
        } else if (key == "State:") {
            std::getline(iss, status.state);
            // Trim leading whitespace
            size_t start = status.state.find_first_not_of(" \t");
            if (start != std::string::npos) status.state = status.state.substr(start);
        } else if (key == "PPid:") {
            iss >> status.ppid;
        } else if (key == "Threads:") {
            iss >> status.threads;
        } else if (key == "VmSize:") {
            iss >> status.vm_size_kb;
        } else if (key == "VmRSS:") {
            iss >> status.vm_rss_kb;
        } else if (key == "Uid:") {
            iss >> status.uid;
        }
    }
    return status;
}

// 3️⃣ Mutex-protected access to process count
int get_process_count() {
    pthread_mutex_lock(&proc_mut);
    int count = get_all_pids().size();
    pthread_mutex_unlock(&proc_mut);
    return count;
}

// 3️⃣ Mutex-protected access to full PID list (thread-safe variant)
std::vector<int> get_all_pids_safe() {
    pthread_mutex_lock(&proc_mut);
    std::vector<int> pids = get_all_pids();
    pthread_mutex_unlock(&proc_mut);
    return pids;
}

void* start_process_monitor(void* arg) {
    volatile sig_atomic_t* running_flag = static_cast<volatile sig_atomic_t*>(arg);
    std::cout << "[+] Process Monitor thread started." << std::endl;
    while (running_flag == nullptr || *running_flag) {
        int count = get_process_count();
        if (count > 500) {
            std::cout << "[MONITOR] Warning: High process count (" << count << ")" << std::endl;
        }

        // 7️⃣ Periodically log detailed info for top processes
        std::vector<int> pids = get_all_pids_safe();
        for (int i = 0; i < std::min((int)pids.size(), 3); i++) {
            ProcessStatus ps = get_process_status(pids[i]);
            std::string cmdline = get_process_cmdline(pids[i]);
            // Demonstrates reading /proc/[pid]/status and /proc/[pid]/cmdline
            (void)ps;      // Used for monitoring; suppress unused warning
            (void)cmdline;
        }

        sleep(5);
    }
    return NULL;
}

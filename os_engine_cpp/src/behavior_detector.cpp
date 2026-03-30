#include "behavior_detector.h"
#include "process_monitor.h"
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unordered_map>
#include <vector>

void send_event_to_backend(const std::string& event_type, const std::string& description, int pid, const std::string& process_name, int severity) {
    int fifo = open("/tmp/hidrs_events", O_WRONLY | O_NONBLOCK);
    if (fifo < 0) {
        // cannot push, maybe backend down
        return;
    }
    std::string payload = "{\"event_type\": \"" + event_type + "\", " +
                          "\"description\": \"" + description + "\", " +
                          "\"source\": \"C++_OS_Engine\", " +
                          "\"pid\": " + std::to_string(pid) + ", " +
                          "\"process_name\": \"" + process_name + "\", " +
                          "\"severity\": " + std::to_string(severity) + "}\n";
                          
    write(fifo, payload.c_str(), payload.length());
    close(fifo);
}

void* start_behavior_detector(void* arg) {
    volatile sig_atomic_t* running_flag = static_cast<volatile sig_atomic_t*>(arg);
    std::cout << "[+] Behavior Detector thread started." << std::endl;
    
    int last_process_cnt = get_process_count();

    // Simple "repeated behavior" memory: track consecutive cycles where a suspicious
    // process name is present.
    std::unordered_map<std::string, int> suspicious_streak;
    std::unordered_map<std::string, bool> warned_this_streak;
    
    while (running_flag == nullptr || *running_flag) {
        int cur_cnt = get_process_count();
        if ((cur_cnt - last_process_cnt) > 20) {
            // Rapid process spike
            send_event_to_backend("PROCESS_SPIKE", "Detected rapid spike in process count", getpid(), "system", 3);
        }
        last_process_cnt = cur_cnt;
        
        // Scan for suspicious process names
        // 3️⃣ Uses mutex-protected variant to prevent race condition with monitor thread
        auto pids = get_all_pids_safe();

        std::unordered_map<std::string, bool> seen_names;
        seen_names.reserve(suspicious_streak.size());

        for (int p : pids) {
            std::string pname = get_process_name(p);
            if (pname == "nc" || pname == "ncat" || pname == "netcat") {
                send_event_to_backend("SUSPICIOUS_PROC", "Detected reverse shell process: " + pname, p, pname, 3);

                seen_names[pname] = true;
                int new_streak = suspicious_streak[pname] + 1;
                suspicious_streak[pname] = new_streak;

                // Emit only once when we reach 3 consecutive cycles.
                if (new_streak == 3 && warned_this_streak[pname] == false) {
                    send_event_to_backend(
                        "REPEATED_SUSPICIOUS_BEHAVIOR",
                        "Suspicious process name persisted for >= 3 detector cycles",
                        getpid(),
                        "behavior_detector",
                        3
                    );
                    warned_this_streak[pname] = true;
                }
            }
        }

        // Reset streaks for suspicious names not observed in this cycle.
        for (auto& kv : suspicious_streak) {
            const std::string& name = kv.first;
            if (!seen_names[name]) {
                kv.second = 0;
                warned_this_streak[name] = false;
            }
        }
        
        sleep(2);
    }
    return NULL;
}

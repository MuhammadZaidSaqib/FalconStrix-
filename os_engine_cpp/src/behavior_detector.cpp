#include "behavior_detector.h"
#include "process_monitor.h"
#include <iostream>
#include <unistd.h>
#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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
    std::cout << "[+] Behavior Detector thread started." << std::endl;
    
    int last_process_cnt = get_process_count();
    
    while(true) {
        int cur_cnt = get_process_count();
        if ((cur_cnt - last_process_cnt) > 20) {
            // Rapid process spike
            send_event_to_backend("PROCESS_SPIKE", "Detected rapid spike in process count", getpid(), "system", 3);
        }
        last_process_cnt = cur_cnt;
        
        // Scan for suspicious process names
        // 3️⃣ Uses mutex-protected variant to prevent race condition with monitor thread
        auto pids = get_all_pids_safe();
        for (int p : pids) {
            std::string pname = get_process_name(p);
            if (pname == "nc" || pname == "ncat" || pname == "netcat") {
                send_event_to_backend("SUSPICIOUS_PROC", "Detected reverse shell process: " + pname, p, pname, 3);
            }
        }
        
        sleep(2);
    }
    return NULL;
}

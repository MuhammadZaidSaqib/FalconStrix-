#include "response_engine.h"
#include <signal.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <thread>
#include "behavior_detector.h" // send_event_to_backend

static const char* kCmdFifoPath = "/tmp/hidrs_cmd";

static std::string get_comm_for_pid(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream f(path);
    std::string line;
    if (f && std::getline(f, line)) return line;
    return "unknown";
}

void trigger_response(int pid) {
    std::cout << "Response Engine: Killing PID " << pid << std::endl;
    kill(pid, SIGKILL);
}

static void handle_locked_command(const std::string& line) {
    // Command format (backend writes tokens): RESPOND_LOCKED <pid> <pid> ...
    // We accept that the line may include extra JSON; we still extract numeric tokens after RESPOND_LOCKED.
    if (line.find("RESPOND_LOCKED") == std::string::npos) {
        return;
    }

    pid_t self = getpid();
    std::vector<int> targets;

    // Extract integers from the string.
    for (size_t i = 0; i < line.size(); ) {
        while (i < line.size() && (line[i] < '0' || line[i] > '9')) {
            i++;
        }
        if (i >= line.size()) break;
        size_t j = i;
        while (j < line.size() && (line[j] >= '0' && line[j] <= '9')) j++;
        if (j > i) {
            long v = 0;
            try {
                v = std::stol(line.substr(i, j - i));
            } catch (...) {
                v = 0;
            }
            if (v > 1 && static_cast<pid_t>(v) != self) {
                targets.push_back(static_cast<int>(v));
            }
        }
        i = j;
    }

    if (targets.empty()) {
        send_event_to_backend(
            "RESPONSE_ACTION",
            "LOCKED command with no targets (defensive mode still active)",
            0,
            "response_engine",
            1
        );
        return;
    }

    for (int pid_int : targets) {
        pid_t pid = static_cast<pid_t>(pid_int);
        std::string pname = get_comm_for_pid(pid);
        if (kill(pid, SIGKILL) != 0) {
            std::ostringstream o;
            o << "SIGKILL failed errno=" << errno << " pid=" << pid << " name=" << pname;
            send_event_to_backend("RESPONSE_ACTION", o.str(), pid_int, "response_engine", 2);
            continue;
        }
        std::ostringstream o;
        o << "SIGKILL delivered (LOCKED response) pid=" << pid << " name=" << pname;
        send_event_to_backend("RESPONSE_ACTION", o.str(), pid_int, "response_engine", 3);
    }
}

void* start_response_engine(void* arg) {
    volatile sig_atomic_t* running_flag = static_cast<volatile sig_atomic_t*>(arg);
    int fd = -1;
    std::string acc;
    char buf[512];

    while (running_flag && *running_flag) {
        if (fd < 0) {
            // Ensure FIFO exists before opening.
            struct stat st {};
            if (stat(kCmdFifoPath, &st) != 0) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            if (!S_ISFIFO(st.st_mode)) {
                std::cerr << "[response_engine] command path exists but is not FIFO: " << kCmdFifoPath << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            fd = open(kCmdFifoPath, O_RDONLY | O_NONBLOCK);
            if (fd < 0) {
                fd = -1;
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
        }

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            acc.append(buf, static_cast<size_t>(n));
            for (;;) {
                auto pos = acc.find('\n');
                if (pos == std::string::npos) break;
                std::string line = acc.substr(0, pos);
                acc.erase(0, pos + 1);
                if (!line.empty()) {
                    handle_locked_command(line);
                }
            }
        } else if (n == 0) {
            // Writer closed: reopen to catch future commands
            close(fd);
            fd = -1;
            acc.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } else {
            if (errno == EAGAIN || errno == EINTR) {
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
                continue;
            }
            // Other error: reopen
            close(fd);
            fd = -1;
            acc.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    if (fd >= 0) close(fd);
    return nullptr;
}

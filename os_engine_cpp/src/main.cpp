/**
 * HIDRS Blue Team OS engine (Kali/Linux):
 * - Parent: reads backend command FIFO, forwards JSON lines to child via pipe.
 * - Child: pthread monitors (/proc, behavioral heuristics) + response thread.
 * - Child: single thread-safe writer to HIDRS events FIFO (JSONL).
 */
#include "behavior_detector.h"
#include "event_writer.h"
#include "process_monitor.h"
#include "response_engine.h"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

namespace {

const char* kDefaultEventsFifo = "/tmp/hidrs_events.fifo";
const char* kDefaultCmdFifo = "/tmp/hidrs_cmd.fifo";

std::atomic<bool> g_child_stop{false};

void on_signal(int) {
    g_child_stop = true;
}

const char* envOr(const char* k, const char* d) {
    const char* v = std::getenv(k);
    return v && v[0] ? v : d;
}

int openEventsFifoWriteBlocking(const char* path) {
    for (;;) {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) {
            return fd;
        }
        if (errno != ENXIO) {
            std::cerr << "[os_engine child] open events fifo failed: " << std::strerror(errno) << "\n";
            return -1;
        }
        std::cerr << "[os_engine child] waiting for events FIFO reader (start backend)...\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

struct ProcArg {
    ProcessMonitor* pm;
    std::atomic<bool>* stop;
};

struct BehArg {
    BehaviorDetector* bd;
    std::atomic<bool>* stop;
};

struct RespArg {
    int read_fd;
    EventWriter* ew;
};

void* proc_entry(void* p) {
    auto* a = static_cast<ProcArg*>(p);
    a->pm->runLoop(a->stop);
    return nullptr;
}

void* beh_entry(void* p) {
    auto* a = static_cast<BehArg*>(p);
    a->bd->runLoop(a->stop);
    return nullptr;
}

void* resp_entry(void* p) {
    auto* a = static_cast<RespArg*>(p);
    ResponseEngine re(a->ew);
    std::string acc;
    char buf[1024];
    while (!g_child_stop.load()) {
        ssize_t n = read(a->read_fd, buf, sizeof(buf));
        if (n > 0) {
            acc.append(buf, static_cast<size_t>(n));
            for (;;) {
                auto pos = acc.find('\n');
                if (pos == std::string::npos) {
                    break;
                }
                std::string line = acc.substr(0, pos);
                acc.erase(0, pos + 1);
                re.handleLockedCommand(line);
            }
        } else if (n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        } else {
            if (errno == EAGAIN || errno == EINTR) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            break;
        }
    }
    return nullptr;
}

int parentMain(const char* cmd_fifo, int pipe_write_end, pid_t child_pid) {
    std::signal(SIGPIPE, SIG_IGN);
    std::cout << "[os_engine parent] reading commands from " << cmd_fifo << std::endl;
    std::string acc;
    char buf[1024];
    while (true) {
        int fd = open(cmd_fifo, O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            std::cerr << "[os_engine parent] failed to open cmd fifo, retry\n";
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        for (;;) {
            int st = 0;
            pid_t wp = waitpid(child_pid, &st, WNOHANG);
            if (wp == child_pid) {
                std::cerr << "[os_engine parent] child exited, restart requested\n";
                close(fd);
                return 2;
            }

            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n > 0) {
                acc.append(buf, static_cast<size_t>(n));
                for (;;) {
                    auto pos = acc.find('\n');
                    if (pos == std::string::npos) {
                        break;
                    }
                    std::string line = acc.substr(0, pos + 1);
                    acc.erase(0, pos + 1);
                    if (line == "\n") {
                        continue;
                    }
                    ssize_t w = ::write(pipe_write_end, line.c_str(), line.size());
                    if (w < 0) {
                        std::cerr << "[os_engine parent] pipe write error\n";
                    }
                }
            } else if (n == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
            } else {
                if (errno == EAGAIN || errno == EINTR) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(80));
                    continue;
                }
                break;
            }
        }
        close(fd);
    }
    return 0;
}

int childMain(const char* events_fifo, int pipe_read_end) {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    int flags = fcntl(pipe_read_end, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(pipe_read_end, F_SETFL, flags | O_NONBLOCK);
    }

    int efd = openEventsFifoWriteBlocking(events_fifo);
    if (efd < 0) {
        close(pipe_read_end);
        return 1;
    }

    EventWriter writer(efd);
    ProcessMonitor pm(&writer);
    BehaviorDetector bd(&writer);

    ProcArg pa{&pm, &g_child_stop};
    BehArg ba{&bd, &g_child_stop};
    RespArg ra{pipe_read_end, &writer};

    pthread_t t1, t2, t3;
    pthread_create(&t1, nullptr, proc_entry, &pa);
    pthread_create(&t2, nullptr, beh_entry, &ba);
    pthread_create(&t3, nullptr, resp_entry, &ra);

    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);
    pthread_join(t3, nullptr);
    close(pipe_read_end);
    close(efd);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    const char* events_fifo = envOr("HIDRS_EVENTS_FIFO", kDefaultEventsFifo);
    const char* cmd_fifo = envOr("HIDRS_CMD_FIFO", kDefaultCmdFifo);

    int restart_budget = 10;
    while (restart_budget-- > 0) {
        int fds[2];
        if (pipe(fds) != 0) {
            std::cerr << "pipe() failed\n";
            return 1;
        }

        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "fork() failed\n";
            close(fds[0]);
            close(fds[1]);
            return 1;
        }
        if (pid == 0) {
            close(fds[1]);
            int rc = childMain(events_fifo, fds[0]);
            close(fds[0]);
            _exit(rc);
        }

        close(fds[0]);
        int rc = parentMain(cmd_fifo, fds[1], pid);
        close(fds[1]);

        if (rc == 2) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        kill(pid, SIGTERM);
        int st = 0;
        waitpid(pid, &st, 0);
        return rc;
    }
    std::cerr << "[os_engine parent] restart budget exhausted\n";
    return 2;
}

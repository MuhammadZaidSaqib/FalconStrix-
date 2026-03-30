#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <cstdlib>
#include "process_monitor.h"
#include "behavior_detector.h"
#include "resource_monitor.h"
#include "response_engine.h"

// ─── 5️⃣ Signal Handling ──────────────────────────────────────────────────────
// Global flag for graceful shutdown. volatile sig_atomic_t is async-signal-safe.
volatile sig_atomic_t running = 1;
static pid_t child_pid = -1;

// Signal handler for SIGINT (Ctrl+C) and SIGTERM (kill command)
void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n[SIGNAL] Caught SIGINT (Ctrl+C), initiating graceful shutdown..." << std::endl;
    } else if (signum == SIGTERM) {
        std::cout << "\n[SIGNAL] Caught SIGTERM, initiating graceful shutdown..." << std::endl;
    }
    running = 0;

    // Forward signal to child process for coordinated shutdown
    if (child_pid > 0) {
        kill(child_pid, signum);
    }
}

// Child signal handler — stops worker threads gracefully
void child_signal_handler(int signum) {
    std::cout << "[SIGNAL] Child process received signal " << signum << ", stopping threads..." << std::endl;
    running = 0;
}

// ─── Child Process Work Function ─────────────────────────────────────────────
void run_child_engine() {
    // Register child-specific signal handler
    signal(SIGINT, child_signal_handler);
    signal(SIGTERM, child_signal_handler);

    // 2️⃣ Multithreading — Four concurrent threads
    pthread_t monitor_thread, detector_thread, resource_thread, response_thread;

    // Pass shutdown flag pointer to all worker threads.
    // Worker threads should periodically check this to exit cleanly.
    void* flag_ptr = (void*)&running;

    // Thread 1: Process monitoring (enumerates /proc)
    pthread_create(&monitor_thread, NULL, start_process_monitor, flag_ptr);

    // Thread 2: Behavioral detection (anomaly scanning)
    pthread_create(&detector_thread, NULL, start_behavior_detector, flag_ptr);

    // Thread 3: 8️⃣ Resource monitoring (CPU & Memory from /proc/stat, /proc/meminfo)
    pthread_create(&resource_thread, NULL, start_resource_monitor, flag_ptr);

    // Thread 4: Response commands listener (FIFO → kill targets)
    pthread_create(&response_thread, NULL, start_response_engine, flag_ptr);

    // Wait for threads to complete (they loop until `running` becomes 0)
    pthread_join(monitor_thread, NULL);
    pthread_join(detector_thread, NULL);
    pthread_join(resource_thread, NULL);
    pthread_join(response_thread, NULL);

    std::cout << "[*] Child engine: All worker threads stopped." << std::endl;
}

// ─── Main Entry Point ────────────────────────────────────────────────────────
int main() {
    std::cout << "[*] Starting Blue Team OS Engine..." << std::endl;

    // 5️⃣ Register signal handlers for graceful shutdown (SIGINT, SIGTERM)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 🔟 Fault Tolerance — Supervision loop: restart child if it crashes
    while (running) {
        // 1️⃣ Process Creation — fork() creates parent-child architecture
        pid_t pid = fork();

        if (pid < 0) {
            std::cerr << "[ERROR] Fork failed." << std::endl;
            return 1;
        }

        if (pid == 0) {
            // ── Child Process ── runs the monitoring engine
            run_child_engine();
            _exit(0);  // Use _exit to avoid flushing parent's stdio buffers
        } else {
            // ── Parent Process ── supervises the child
            child_pid = pid;
            std::cout << "[*] Parent Engine supervising child workers (PID: " << pid << ")" << std::endl;

            int status;
            waitpid(pid, &status, 0);  // Block until child exits

            if (!running) {
                // We received a shutdown signal, don't restart
                std::cout << "[*] Shutdown signal received — not restarting child." << std::endl;
                break;
            }

            // 🔟 Fault Recovery — Child crashed, restart it
            if (WIFEXITED(status)) {
                int exit_code = WEXITSTATUS(status);
                if (exit_code != 0) {
                    std::cerr << "[!] Child exited with error code " << exit_code
                              << ", restarting in 2 seconds..." << std::endl;
                    sleep(2);
                    continue;  // Restart the child
                } else {
                    std::cout << "[*] Child exited normally (code 0)." << std::endl;
                    break;
                }
            } else if (WIFSIGNALED(status)) {
                int term_sig = WTERMSIG(status);
                std::cerr << "[!] Child killed by signal " << term_sig
                          << ", restarting in 2 seconds..." << std::endl;
                sleep(2);
                continue;  // Restart the child
            }
        }
    }

    std::cout << "[*] Blue Team OS Engine shut down cleanly." << std::endl;
    return 0;
}

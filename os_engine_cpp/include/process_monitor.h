#pragma once

#include <atomic>
#include <string>

class EventWriter;

/**
 * /proc-based monitoring: suspicious process names and coarse process inventory samples.
 */
class ProcessMonitor {
public:
    explicit ProcessMonitor(EventWriter* writer);

    void runLoop(std::atomic<bool>* stop_flag);

private:
    void scanOnce();
    bool isSuspiciousName(const std::string& name) const;

    EventWriter* writer_;
};

#pragma once

#include <atomic>
#include <string>

class EventWriter;

/**
 * Behavioral heuristics: process spikes, simulated auth log churn, canary file tamper.
 */
class BehaviorDetector {
public:
    explicit BehaviorDetector(EventWriter* writer);

    void runLoop(std::atomic<bool>* stop_flag);

private:
    void checkSpike();
    void checkAuthLog();
    void checkWatchFile();
    void checkResourcePressure();

    EventWriter* writer_;
    int last_proc_count_;
    long last_auth_size_;
    long last_watch_mtime_;
    float last_load1_;
};

#pragma once

#include <pthread.h>
#include <string>
#include <unistd.h>

/**
 * Thread-safe line writer to the HIDRS events FIFO (one write() per JSON line).
 */
class EventWriter {
public:
    explicit EventWriter(int fd);
    ~EventWriter();

    void writeLine(const std::string& line);

    EventWriter(const EventWriter&) = delete;
    EventWriter& operator=(const EventWriter&) = delete;

private:
    int fd_;
    pthread_mutex_t mu_;
};

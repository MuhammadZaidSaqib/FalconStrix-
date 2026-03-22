#include "event_writer.h"

#include <cstring>

EventWriter::EventWriter(int fd) : fd_(fd) {
    pthread_mutex_init(&mu_, nullptr);
}

EventWriter::~EventWriter() {
    pthread_mutex_destroy(&mu_);
}

void EventWriter::writeLine(const std::string& line) {
    pthread_mutex_lock(&mu_);
    const char* p = line.c_str();
    size_t n = line.size();
    if (n == 0 || line.back() != '\n') {
        // enforce newline for JSONL framing
        std::string tmp = line + "\n";
        (void)::write(fd_, tmp.c_str(), tmp.size());
    } else {
        (void)::write(fd_, p, n);
    }
    pthread_mutex_unlock(&mu_);
}

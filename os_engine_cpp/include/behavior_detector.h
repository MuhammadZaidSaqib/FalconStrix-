#ifndef BEHAVIOR_DETECTOR_H
#define BEHAVIOR_DETECTOR_H

#include <string>

void* start_behavior_detector(void* arg);
void send_event_to_backend(const std::string& event_type, const std::string& description, int pid, const std::string& process_name, int severity);

#endif

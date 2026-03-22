#pragma once

#include <string>

class EventWriter;

/**
 * Executes defensive actions (SIGTERM) and emits RESPONSE_ACTION events on the FIFO.
 */
class ResponseEngine {
public:
    explicit ResponseEngine(EventWriter* writer);

    void handleLockedCommand(const std::string& json_line);

private:
    EventWriter* writer_;
};

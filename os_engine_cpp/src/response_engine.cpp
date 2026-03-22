#include "response_engine.h"

#include "event_writer.h"

#include <cerrno>
#include <csignal>
#include <signal.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::vector<int> parseTargetPids(const std::string& json) {
    std::vector<int> out;
    auto pos = json.find("\"targets\"");
    if (pos == std::string::npos) {
        return out;
    }
    auto lb = json.find('[', pos);
    auto rb = json.find(']', lb);
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb) {
        return out;
    }
    std::string inner = json.substr(lb + 1, rb - lb - 1);
    const char* p = inner.c_str();
    while (*p) {
        while (*p && (*p < '0' || *p > '9') && *p != '-') {
            ++p;
        }
        if (!*p) {
            break;
        }
        char* end = nullptr;
        long v = std::strtol(p, &end, 10);
        if (end == p) {
            break;
        }
        p = end;
        if (v > 1 && v != static_cast<long>(getpid())) {
            out.push_back(static_cast<int>(v));
        }
    }
    return out;
}

} // namespace

ResponseEngine::ResponseEngine(EventWriter* writer) : writer_(writer) {}

void ResponseEngine::handleLockedCommand(const std::string& json_line) {
    if (json_line.find("RESPOND_LOCKED") == std::string::npos) {
        return;
    }
    auto pids = parseTargetPids(json_line);
    pid_t self = getpid();
    for (int pid : pids) {
        if (pid == static_cast<int>(self)) {
            continue;
        }
        if (kill(static_cast<pid_t>(pid), SIGTERM) != 0) {
            std::ostringstream o;
            o << "{\"type\":\"RESPONSE_ACTION\",\"source\":\"response_engine\",\"severity\":\"MEDIUM\","
              << "\"detail\":\"SIGTERM failed errno=" << errno << "\",\"pid\":" << pid << "}";
            writer_->writeLine(o.str());
            continue;
        }
        std::ostringstream o;
        o << "{\"type\":\"RESPONSE_ACTION\",\"source\":\"response_engine\",\"severity\":\"HIGH\","
          << "\"detail\":\"SIGTERM delivered (LOCKED response)\",\"pid\":" << pid << "}";
        writer_->writeLine(o.str());
    }
    if (pids.empty()) {
        std::ostringstream o;
        o << "{\"type\":\"RESPONSE_ACTION\",\"source\":\"response_engine\",\"severity\":\"LOW\","
          << "\"detail\":\"LOCKED command with no target PIDs — FSM defensive mode active\"}";
        writer_->writeLine(o.str());
    }
}

#include "process_monitor.h"

#include "event_writer.h"

#include <dirent.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool isDigits(const std::string& s) {
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

std::string readComm(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream f(path);
    std::string line;
    if (std::getline(f, line)) {
        return line;
    }
    return {};
}

std::string readCmdline(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return {};
    }
    std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (raw.empty()) {
        return {};
    }
    for (char& c : raw) {
        if (c == '\0') {
            c = ' ';
        }
    }
    return raw;
}

std::string readProcessState(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream f(path);
    if (!f) {
        return {};
    }
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("State:", 0) == 0) {
            return line;
        }
    }
    return {};
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out.push_back(c);
    }
    return out;
}

} // namespace

ProcessMonitor::ProcessMonitor(EventWriter* writer) : writer_(writer) {}

bool ProcessMonitor::isSuspiciousName(const std::string& name) const {
    if (name == "nc") {
        return true;
    }
    const std::vector<std::string> bad = {
        "ncat", "netcat", "nmap", "masscan", "hydra", "sqlmap", "nikto", "msf", "metasploit",
    };
    for (const auto& b : bad) {
        if (name.find(b) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void ProcessMonitor::scanOnce() {
    DIR* d = opendir("/proc");
    if (!d) {
        return;
    }
    std::vector<std::pair<pid_t, std::string>> suspicious;
    int count = 0;
    while (dirent* ent = readdir(d)) {
        std::string n(ent->d_name);
        if (!isDigits(n)) {
            continue;
        }
        char* end = nullptr;
        long pv = std::strtol(n.c_str(), &end, 10);
        if (end == n.c_str() || pv <= 0) {
            continue;
        }
        pid_t pid = static_cast<pid_t>(pv);
        std::string comm = readComm(pid);
        if (!comm.empty()) {
            count++;
            if (isSuspiciousName(comm)) {
                suspicious.emplace_back(pid, comm);
            }
        }
    }
    closedir(d);

    if (!suspicious.empty()) {
        std::ostringstream payload;
        payload << "{\"type\":\"SUSPICIOUS_PROCESS\",\"source\":\"os_engine\",\"severity\":\"HIGH\","
                << "\"detail\":\"Suspicious comm names detected\",\"processes\":[";
        for (size_t i = 0; i < suspicious.size(); ++i) {
            if (i) {
                payload << ',';
            }
            std::string cmdline = readCmdline(suspicious[i].first);
            std::string state = readProcessState(suspicious[i].first);
            payload << "{\"pid\":" << suspicious[i].first << ",\"name\":\""
                    << jsonEscape(suspicious[i].second) << "\",\"cmdline\":\""
                    << jsonEscape(cmdline) << "\",\"status\":\"" << jsonEscape(state) << "\"}";
        }
        payload << "]}";
        writer_->writeLine(payload.str());
    }
    (void)count;
}

void ProcessMonitor::runLoop(std::atomic<bool>* stop_flag) {
    using namespace std::chrono_literals;
    while (!stop_flag->load()) {
        scanOnce();
        std::this_thread::sleep_for(1200ms);
    }
}
